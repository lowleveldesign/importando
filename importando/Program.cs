using importando;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.System.Memory;
using Windows.Win32.Foundation;
using Windows.Win32.System.Diagnostics.Debug;
using Windows.Win32.System.Threading;
using Microsoft.Win32.SafeHandles;
using Windows.Win32.System.WindowsProgramming;

[assembly: InternalsVisibleTo("importando.tests")]

using CancellationTokenSource cts = new();

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

var parsedArgs = ProgramArgs.ParseArgs(["v", "h", "help"], args);
if (parsedArgs.ContainsKey("h") || parsedArgs.ContainsKey("help"))
{
    Console.WriteLine("""
importando - a tool for modifying PE imports on a process start

Copyright (C) 2023 Sebastian Solnica (https://wtrace.net)

importando [options] <executable> [args]

Options:
    -i <import_definition>
    -i <import_definition1>:<import_definition2>
        Add a new import to the executable or forward an existing import. This option can be specified multiple times.
    -v
        Print verbose output.
    -h, --help
        Print this help message.

Possible import_definition:
  dll_name.dll!function_name - import by name
  dll_name.dll#ordinal - import by ordinal

Examples:
  importando -i test.dll#1 -i kernelbase.dll!CreateFileW:trace.dll!CreateFileW cmd.exe
""");
    return;
}

if (!parsedArgs.TryGetValue("", out var freeArgs))
{
    Console.WriteLine("ERROR: no executable specified");
    return;
}

TextWriter logger = (parsedArgs.ContainsKey("v") || parsedArgs.ContainsKey("verbose")) ?
    Console.Out : TextWriter.Null;

try
{
    var (forwards, importUpdates) = parsedArgs.TryGetValue("i", out var updateArgs) ? ProgramArgs.ParseImportUpdates(updateArgs) : ([], []);

    uint pid;
    unsafe
    {
        var commandLine = "\"" + string.Join("\" \"", freeArgs) + "\"\0";
        fixed (char* commandLinePtr = commandLine)
        {
            var startupInfo = new STARTUPINFOW() { cb = (uint)Marshal.SizeOf<STARTUPINFOW>() };
            var processInformation = new PROCESS_INFORMATION();

            bool res = PInvoke.CreateProcess(new PCWSTR(null), new PWSTR(commandLinePtr),
                null, null, false, PROCESS_CREATION_FLAGS.DEBUG_ONLY_THIS_PROCESS, null, new PCWSTR(null),
                &startupInfo, &processInformation);
            if (!res)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"{nameof(PInvoke.CreateProcess)} error");
            }

            if (!PInvoke.DebugSetProcessKillOnExit(false))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"{nameof(PInvoke.DebugSetProcessKillOnExit)} error");
            }

            pid = processInformation.dwProcessId;

            PInvoke.CloseHandle(processInformation.hProcess);
            PInvoke.CloseHandle(processInformation.hThread);
        }
    }

    HANDLE processHandle = HANDLE.Null;
    nuint imageBase = 0;
    bool is64bit = false;
    ModuleImport[] originalImports = [];
    ModuleImport[] newImports = [];

    while (!cts.Token.IsCancellationRequested)
    {
        if (WaitForDebugEvent(1000) is { } debugEvent)
        {
            switch (debugEvent.dwDebugEventCode)
            {
                case DEBUG_EVENT_CODE.CREATE_PROCESS_DEBUG_EVENT:
                    {
                        logger.WriteLine($"CreateProcess: {debugEvent.dwProcessId}");

                        Debug.Assert(pid == debugEvent.dwProcessId);
                        var createProcessInfo = debugEvent.u.CreateProcessInfo;

                        // we are closing hFile handle after we finish reading the image data
                        using var pereader = new PEReader(new FileStream(
                            new SafeFileHandle(createProcessInfo.hFile, true), FileAccess.Read));

                        processHandle = createProcessInfo.hProcess;
                        is64bit = pereader.Is64Bit();
                        unsafe { imageBase = (nuint)createProcessInfo.lpBaseOfImage; }

                        (originalImports, newImports) = UpdateProcessImports(processHandle,
                            pereader, imageBase, importUpdates, forwards);
                    }
                    break;

                case DEBUG_EVENT_CODE.EXCEPTION_DEBUG_EVENT:
                    if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode == NTSTATUS.STATUS_BREAKPOINT)
                    {
                        // first breakpoint exception is the process breakpoint - it happens when loader finished its initial
                        // work and thunks are resolved
                        Debug.Assert(imageBase != 0 && !processHandle.IsNull);
                        UpdateForwardedImports(processHandle, is64bit, imageBase, originalImports, newImports, forwards);
                        cts.Cancel();
                    }
                    else
                    {
                        logger.WriteLine($"Unexpected exception: {debugEvent.u.Exception.ExceptionRecord.ExceptionCode.Value:x}");
                    }
                    break;

                case DEBUG_EVENT_CODE.OUTPUT_DEBUG_STRING_EVENT:
                    var debugString = debugEvent.u.DebugString;
                    unsafe
                    {
                        // the string could be longer than the ushort length, but we don't really care here
                        var value = ReadRemoteString(processHandle, debugString.lpDebugStringData.Value,
                            debugString.nDebugStringLength, debugString.fUnicode != 0);
                        logger.Write("Debug output: {0}", value);
                    }
                    break;

                case DEBUG_EVENT_CODE.EXIT_PROCESS_DEBUG_EVENT:
                    cts.Cancel();
                    break;
                default:
                    break;
            }

            if (!PInvoke.ContinueDebugEvent(debugEvent.dwProcessId,
                debugEvent.dwThreadId, NTSTATUS.DBG_EXCEPTION_NOT_HANDLED))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"{nameof(PInvoke.ContinueDebugEvent)} error");
            }
        }
    }

    if (!PInvoke.DebugActiveProcessStop(pid))
    {
        logger.Write($"Error occured when detaching from the process: {Marshal.GetLastWin32Error()}");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"ERROR: {ex}");
}

static (ModuleImport[] OriginalImports, ModuleImport[] NewImports) UpdateProcessImports(HANDLE processHandle,
    PEReader imageReader, nuint imageBase, ImportUpdate[] importUpdates, (string ForwardFrom, string ForwardTo)[] forwards)
{
    void UpdatePEDirectory(nuint dataDirectoriesRva, IMAGE_DIRECTORY_ENTRY entry, uint rva, uint size)
    {
        int IMAGE_DATA_DIRECTORY_SIZE = Marshal.SizeOf<IMAGE_DATA_DIRECTORY>();

        var dataDirectory = new IMAGE_DATA_DIRECTORY { VirtualAddress = rva, Size = size };
        var addr = imageBase + dataDirectoriesRva + (nuint)((int)entry * IMAGE_DATA_DIRECTORY_SIZE);

        unsafe
        {
            PAGE_PROTECTION_FLAGS oldProtection;
            if (!PInvoke.VirtualProtectEx(processHandle, (void*)addr, (nuint)IMAGE_DATA_DIRECTORY_SIZE,
                PAGE_PROTECTION_FLAGS.PAGE_READWRITE, &oldProtection))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"{nameof(PInvoke.VirtualProtectEx)} error");
            }
            if (!PInvoke.WriteProcessMemory(processHandle, (void*)addr, &dataDirectory, (nuint)IMAGE_DATA_DIRECTORY_SIZE, null))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"{nameof(PInvoke.WriteProcessMemory)} error");
            }
            PInvoke.VirtualProtectEx(processHandle, (void*)addr, (nuint)IMAGE_DATA_DIRECTORY_SIZE,
                               oldProtection, &oldProtection);
        }
    }

    var existingImports = PEImports.ReadModuleImports(imageReader);

    var newImports = PEImports.PrepareNewModuleImports(existingImports, importUpdates, forwards);

    var is64bit = imageReader.Is64Bit();
    var (importDirRva, importDirSize) = PEImports.UpdateImportsDirectory(processHandle, is64bit, imageBase, newImports);

    nuint dataDirectoriesRva = (nuint)(imageReader.PEHeaders.PEHeaderStartOffset +
        (is64bit ? Marshal.OffsetOf<IMAGE_OPTIONAL_HEADER64>("DataDirectory") : Marshal.OffsetOf<IMAGE_OPTIONAL_HEADER32>("DataDirectory")));

    UpdatePEDirectory(dataDirectoriesRva, IMAGE_DIRECTORY_ENTRY.IMAGE_DIRECTORY_ENTRY_IMPORT, importDirRva, importDirSize);
    UpdatePEDirectory(dataDirectoriesRva, IMAGE_DIRECTORY_ENTRY.IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, 0, 0);

    return (existingImports, newImports);
}

static void UpdateForwardedImports(HANDLE processHandle, bool is64bit, nuint imageBase,
    ModuleImport[] originalImports, ModuleImport[] newImports, (string ForwardFrom, string ForwardTo)[] forwards)
{
    int thunkSize = is64bit ? Marshal.SizeOf<IMAGE_THUNK_DATA64>() : Marshal.SizeOf<IMAGE_THUNK_DATA32>();

    uint GetThunkRva(ModuleImport[] moduleImports, string importName)
    {
        var (dllName, functionOrOrdinal) = importName.IndexOfAny(['!', '#']) switch
        {
            -1 => throw new InvalidOperationException("Critical error - invalid import name"),
            var i => (importName[..i], importName[(i + 1)..])
        };

        var mi = moduleImports.First(mi => mi.DllName == dllName);

        var thunkIndex = Array.FindIndex(mi.FirstThunks, thunk => thunk.Import switch
        {
            FunctionImportByName { FunctionName: var name } => name == functionOrOrdinal,
            FunctionImportByOrdinal { Ordinal: var ordinal } => ordinal.ToString() == functionOrOrdinal,
            _ => false
        });

        return mi.FirstThunkRva + (uint)(thunkIndex * thunkSize);
    }

    void CopyThunkValues(uint fromRva, uint toRva)
    {
        unsafe
        {
            var buffer = stackalloc byte[thunkSize];
            if (!PInvoke.ReadProcessMemory(processHandle, (void*)(imageBase + fromRva), buffer, (nuint)thunkSize, null))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"{nameof(PInvoke.ReadProcessMemory)} error when reading thunk");
            }

            void *toAddr = (void*)(imageBase + toRva);
            PAGE_PROTECTION_FLAGS oldProtection;
            if (!PInvoke.VirtualProtectEx(processHandle, toAddr, (nuint)thunkSize, PAGE_PROTECTION_FLAGS.PAGE_READWRITE, &oldProtection))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"{nameof(PInvoke.VirtualProtectEx)} error when changing thunk protection");
            }
            if (!PInvoke.WriteProcessMemory(processHandle, toAddr, buffer, (nuint)thunkSize, null))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"{nameof(PInvoke.WriteProcessMemory)} error when writing thunk");
            }
            PInvoke.VirtualProtectEx(processHandle, toAddr, (nuint)thunkSize, oldProtection, &oldProtection);
        }
    }

    foreach ((string forwardFrom, string forwardTo) in forwards)
    {
        var originalThunkRva = GetThunkRva(originalImports, forwardFrom);
        var newThunkRva = GetThunkRva(newImports, forwardTo);

        // new thunk should be resolved by now, so we may copy its value to the original place
        // that could be referenced by application code
        CopyThunkValues(newThunkRva, originalThunkRva);
    }
}

unsafe string ReadRemoteString(HANDLE processHandle, byte* addr, int bytesLength, bool isUnicode)
{
    unsafe
    {
        var buffer = stackalloc byte[bytesLength];
        if (PInvoke.ReadProcessMemory(processHandle, addr, buffer, (nuint)bytesLength, null))
        {
            return isUnicode ? Marshal.PtrToStringUni((nint)buffer, bytesLength / sizeof(ushort)) :
                Marshal.PtrToStringAnsi((nint)buffer, bytesLength);
        }
        else
        {
            return "ERROR READING VALUE";
        }
    }
}

static DEBUG_EVENT? WaitForDebugEvent(uint timeout)
{
    if (!PInvoke.WaitForDebugEvent(out var debugEvent, timeout))
    {
        int err = Marshal.GetLastPInvokeError();
        if (err == (int)WIN32_ERROR.ERROR_SEM_TIMEOUT)
        {
            return null;
        }

        throw new Win32Exception(err, $"{nameof(PInvoke.WaitForDebugEvent)} error");
    }
    else
    {
        return debugEvent;
    }
}

