using importando;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Diagnostics.Debug;
using Windows.Win32.System.Threading;

[assembly: InternalsVisibleTo("importando.tests")]

using CancellationTokenSource cts = new CancellationTokenSource();

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

var parsedArgs = ProgramArgs.ParseArgs(["v", "h", "help"], args);
if (parsedArgs.ContainsKey("h") || parsedArgs.ContainsKey("help"))
{
    Console.WriteLine("""
importando - a tool for modifying imports on a process start

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
TextWriter logger = (parsedArgs.ContainsKey("v") || parsedArgs.ContainsKey("verbose")) ?
    Console.Out : TextWriter.Null;

HANDLE processHandle = HANDLE.Null;

try
{
    var importUpdates = ProgramArgs.ParseImportUpdates(parsedArgs["i"].ToArray());


    uint pid;
    unsafe
    {
        var commandLine = "\"" + string.Join("\" \"", args) + "\"\0";
        fixed (char* commandLinePtr = commandLine)
        {
            var startupInfo = new STARTUPINFOW() { cb = (uint)Marshal.SizeOf<STARTUPINFOW>() };
            var processInformation = new PROCESS_INFORMATION();

            bool res = PInvoke.CreateProcess(new PCWSTR(null), new PWSTR(commandLinePtr),
                null, null, false, PROCESS_CREATION_FLAGS.DEBUG_ONLY_THIS_PROCESS, null, new PCWSTR(null),
                &startupInfo, &processInformation);
            if (!res)
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }

            if (!PInvoke.DebugSetProcessKillOnExit(false))
            {
                throw new Win32Exception();
            }

            pid = processInformation.dwProcessId;

            PInvoke.CloseHandle(processInformation.hProcess);
            PInvoke.CloseHandle(processInformation.hThread);
        }
    }

    while (!cts.Token.IsCancellationRequested)
    {
        if (WaitForDebugEvent(1000) is { } debugEvent)
        {
            switch (debugEvent.dwDebugEventCode)
            {
                case DEBUG_EVENT_CODE.CREATE_PROCESS_DEBUG_EVENT:
                    pid = debugEvent.dwProcessId;
                    processHandle = debugEvent.u.CreateProcessInfo.hProcess;
                    logger.WriteLine($"CreateProcess: {debugEvent.dwProcessId}");
                    // FIXME: perform the modifications
                    break;
                case DEBUG_EVENT_CODE.EXCEPTION_DEBUG_EVENT:
                    // first breakpoint exception is the process breakpoint - it happens when loader finished its initial
                    // work and IAT is already resolved
                    logger.WriteLine($"Exception: {debugEvent.u.Exception.ExceptionRecord.ExceptionCode.Value:x}");
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
                throw new Win32Exception();
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
finally
{
    if (!processHandle.IsNull)
    {
        PInvoke.CloseHandle(processHandle);
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

        throw new Win32Exception(err);
    }
    else
    {
        return debugEvent;
    }
}

