using System.ComponentModel;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Memory;
using Windows.Win32.System.SystemServices;
using Windows.Win32.System.WindowsProgramming;


namespace importando;

interface IFunctionImport { }

record FunctionImportByName(uint Rva, ushort Hint, string FunctionName) : IFunctionImport;

record FunctionImportByOrdinal(uint Ordinal) : IFunctionImport;

record NullImport : IFunctionImport;

record FunctionThunk(IFunctionImport Import);

record ModuleImport(string DllName, uint DllNameRva, uint OriginalFirstThunkRva,
    uint FirstThunkRva, FunctionThunk[] FirstThunks)
{
    public bool TryFindFirstThunk(string functionName, out FunctionThunk? thunk)
    {
        thunk = Array.FindIndex(FirstThunks, t => t.Import is FunctionImportByName imp && imp.FunctionName == functionName)
            is var ind && ind != -1 ? FirstThunks[ind] : null;
        return thunk != null;
    }

    public bool TryFindFirstThunk(uint ordinal, out FunctionThunk? thunk)
    {
        thunk = Array.FindIndex(FirstThunks, t => t.Import is FunctionImportByOrdinal imp && imp.Ordinal == ordinal)
            is var ind && ind != -1 ? FirstThunks[ind] : null;
        return thunk != null;
    }
}

record ImportUpdate(string ImportName, string DllName, IFunctionImport Import);

record NewImportDataSize(int ThunksArraySize, int StringsArraySize, int ImportDescTableSize)
{
    public int TotalSize => 2 * ThunksArraySize /* orig first and first */ +
        StringsArraySize + ImportDescTableSize;
}

internal static class PEImports
{
    static readonly int NameOffset = Marshal.OffsetOf<IMAGE_IMPORT_BY_NAME>("Name").ToInt32();

    public static unsafe ModuleImport[] ReadModuleImports(string modulePath)
    {
        using var pereader = new PEReader(File.OpenRead(modulePath));

        unsafe IFunctionImport GetFunctionImport(bool isOrdinal, uint rva)
        {
            if (rva == 0)
            {
                return new NullImport();
            }
            if (isOrdinal)
            {
                return new FunctionImportByOrdinal(rva & 0xFFFF);
            }
            var importByName = (IMAGE_IMPORT_BY_NAME*)pereader!.GetSectionData((int)rva).Pointer;
            var functionName = Marshal.PtrToStringAnsi((nint)importByName + NameOffset)!;
            return new FunctionImportByName(rva, importByName->Hint, functionName);
        }

        unsafe FunctionThunk[] ReadThunks32(uint firstThunkRva)
        {
            List<FunctionThunk> thunks = [];
            var currThunk = (IMAGE_THUNK_DATA32*)pereader!.GetSectionData((int)firstThunkRva).Pointer;
            while (currThunk->u1.AddressOfData != 0)
            {
                var isOrdinal = (currThunk->u1.Ordinal & PInvoke.IMAGE_ORDINAL_FLAG32) != 0;
                var rva = isOrdinal ? currThunk->u1.Ordinal : currThunk->u1.AddressOfData;

                thunks.Add(new(GetFunctionImport(isOrdinal, rva)));

                currThunk++;
            }

            return [.. thunks];
        }

        unsafe FunctionThunk[] ReadThunks64(uint firstThunkRva)
        {
            List<FunctionThunk> thunks = [];
            var currThunk = (IMAGE_THUNK_DATA64*)pereader!.GetSectionData((int)firstThunkRva).Pointer;
            while (currThunk->u1.AddressOfData != 0)
            {
                var isOrdinal = (currThunk->u1.Ordinal & PInvoke.IMAGE_ORDINAL_FLAG64) != 0;
                var rva = isOrdinal ? currThunk->u1.Ordinal : currThunk->u1.AddressOfData;

                thunks.Add(new(GetFunctionImport(isOrdinal, (uint)rva)));

                currThunk++;
                firstThunkRva += (uint)sizeof(IMAGE_THUNK_DATA64);
            }

            return [.. thunks];
        }

        var is64Bit = pereader.PEHeaders.PEHeader!.Magic == PEMagic.PE32Plus;
        var importTableDirectory = pereader.PEHeaders.PEHeader!.ImportTableDirectory;

        var importDirEntryData = pereader.GetSectionData(importTableDirectory.RelativeVirtualAddress);
        var importDescriptors = (IMAGE_IMPORT_DESCRIPTOR*)importDirEntryData.Pointer;

        var imports = new List<ModuleImport>(importTableDirectory.Size == 0 ?
                        10 : importTableDirectory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR));

        for (int i = 0; importDescriptors[i].Name != 0; i++)
        {
            var importDescriptor = importDescriptors[i];
            var dllName = Marshal.PtrToStringAnsi((nint)pereader.GetSectionData((int)importDescriptor.Name).Pointer)!;

            var originalFirstThunkRva = importDescriptor.Anonymous.OriginalFirstThunk;
            var firstThunks = is64Bit ? ReadThunks64(importDescriptor.FirstThunk) : ReadThunks32(importDescriptor.FirstThunk);
            imports.Add(new(dllName.ToUpper(), importDescriptor.Name, originalFirstThunkRva,
                importDescriptor.FirstThunk, firstThunks));
        }

        return imports.ToArray();
    }

    // This is a port to C# of a FindAndAllocateNearBase function from the Detours library
    public static nuint FindAndAllocateNearBase(HANDLE processHandle, nuint imageBase, uint bytesCount)
    {
        void CheckAddressWithinBounds(nuint address)
        {
            if (Environment.Is64BitProcess && (address + bytesCount - 1 - imageBase > uint.MaxValue))
            {
                throw new Exception($"FindAndAllocateNearBase(2) failing due to distance >4GB {address:X}");
            }
        }

        const nuint MM_ALLOCATION_GRANULARITY = 0x10000;

        var lastBase = imageBase;
        while (true)
        {
            unsafe
            {
                MEMORY_BASIC_INFORMATION mbi;
                if (PInvoke.VirtualQueryEx(processHandle, (void*)lastBase, &mbi, (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) == 0)
                {
                    throw new Win32Exception();
                }

                // Usermode address space has such an unaligned region size always at the
                // end and only at the end.
                if ((mbi.RegionSize & 0xfff) == 0xfff)
                {
                    break;
                }

                // Skip anything other than a pure free region.
                if (mbi.State == VIRTUAL_ALLOCATION_TYPE.MEM_FREE)
                {
                    // Use the max of mbi.BaseAddress and pbBase, in case mbi.BaseAddress < imageBase.
                    var address = Math.Max(imageBase, (nuint)mbi.BaseAddress);

                    // Round pbAddress up to the nearest MM allocation boundary.
                    var mmGranularityMinusOne = MM_ALLOCATION_GRANULARITY - 1;
                    address = (address + mmGranularityMinusOne) & ~mmGranularityMinusOne;

                    CheckAddressWithinBounds(address);

                    Debug.WriteLine($"Free region at {(nuint)mbi.BaseAddress:X} .. {(nuint)mbi.BaseAddress + mbi.RegionSize:X}");

                    for (; address < (nuint)mbi.BaseAddress + mbi.RegionSize; address += MM_ALLOCATION_GRANULARITY)
                    {
                        var allocAddress = PInvoke.VirtualAllocEx(processHandle, (void*)address, bytesCount,
                            VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE | VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT, PAGE_PROTECTION_FLAGS.PAGE_READWRITE);
                        if (allocAddress == null)
                        {
                            var lastError = Marshal.GetLastWin32Error();
                            Debug.WriteLine($"VirtualAllocEx({address:X}) failed: {lastError}");
                            continue;
                        }

                        CheckAddressWithinBounds((nuint)allocAddress);

                        Debug.WriteLine($"[{(nuint)allocAddress:X}..{(nuint)allocAddress + bytesCount:X}] Allocated for import table.");
                        return (nuint)allocAddress;
                    }
                }

                lastBase += mbi.RegionSize;
            }
        }
        return nuint.Zero;
    }

    public static ((string ForwardFrom, string ForwardTo)[], ImportUpdate[]) ParseImportUpdates(string[] importUpdates)
    {
        static ImportUpdate ParseFunctionImport(string s)
        {
            var byOrdinalParts = s.Split('#');
            if (byOrdinalParts.Length == 2 && uint.TryParse(byOrdinalParts[1], out var ordinal))
            {
                var dllName = byOrdinalParts[0].ToUpperInvariant();
                return new($"{dllName}#{ordinal}", dllName, new FunctionImportByOrdinal(ordinal));
            }
            else
            {
                var byNameParts = s.Split('!');
                if (byNameParts.Length == 2)
                {
                    var dllName = byNameParts[0].ToUpperInvariant();
                    var functionName = byNameParts[1];
                    return new($"{dllName}!{functionName}", dllName, new FunctionImportByName(0, 0, functionName));
                }
                else
                {
                    throw new ArgumentException($"Invalid import update: {s}");
                }
            }
        }

        var updates = new Dictionary<string, ImportUpdate>();
        var forwardings = new HashSet<(string, string)>();

        for (int i = 0; i < importUpdates.Length; i++)
        {
            var importUpdate = importUpdates[i];
            var forwarding = importUpdate.Split(':');
            if (forwarding.Length == 1)
            {
                var update = ParseFunctionImport(forwarding[0]);
                updates.TryAdd(update.ImportName, update);
            }
            else if (forwarding.Length == 2)
            {
                var original = ParseFunctionImport(forwarding[0]);
                var forwarded = ParseFunctionImport(forwarding[1]);

                updates.TryAdd(original.ImportName, original);
                updates.TryAdd(forwarded.ImportName, forwarded);

                forwardings.Add((original.ImportName, forwarded.ImportName));
            }
            else
            {
                throw new ArgumentException($"Invalid import update: {importUpdate}");
            }
        }
        return ([.. forwardings], [.. updates.Values]);
    }

    public static ModuleImport[] PrepareNewModuleImports(ModuleImport[] existingImports, ImportUpdate[] updates,
        (string ForwardFrom, string ForwardTo)[] forwardings)
    {
        unsafe string GetFunctionImportName(string dllName, IFunctionImport import)
        {
            return import switch
            {
                FunctionImportByName imp => $"{dllName}!{imp.FunctionName}",
                FunctionImportByOrdinal imp => $"{dllName}#{imp.Ordinal}",
                NullImport _ => "",
                _ => throw new Exception("Invalid import type")
            };
        }

        bool IsForwardedFrom(string importName) => Array.Exists(forwardings, f => f.ForwardFrom == importName);
        bool IsForwardedTo(string importName) => Array.Exists(forwardings, f => f.ForwardTo == importName);

        var imports = new List<ModuleImport>();
        var dllNames = updates.Select(u => u.DllName).ToHashSet();

        foreach (var existingImport in existingImports)
        {
            if (!dllNames.Contains(existingImport.DllName))
            {
                // an existing import without updates
                imports.Add(existingImport);
            }
            else
            {
                var updateImportNames = updates.Where(u => u.DllName == existingImport.DllName)
                    .Select(u => u.ImportName).ToHashSet();

                var newThunks = new List<FunctionThunk>();

                // existing thunks
                foreach (var existingThunk in existingImport.FirstThunks)
                {
                    var importName = GetFunctionImportName(existingImport.DllName, existingThunk.Import);

                    if (IsForwardedFrom(importName))
                    {
                        if (IsForwardedTo(importName))
                        {
                            throw new ArgumentException(
                                $"Forwarded import '{importName}' can't be used as a forwarding target");
                        }
                    }
                    else
                    {
                        // the thunk is still in use
                        newThunks.Add(new(existingThunk.Import));
                    }

                    updateImportNames.Remove(importName);
                }

                // new thunks
                foreach (var updateImportName in updateImportNames)
                {
                    // we only add imports that are not forwarded are added - why would
                    // you want to forward an import that is not used?
                    if (IsForwardedFrom(updateImportName))
                    {
                        throw new ArgumentException($"A non-existing import '{updateImportName}' can't be forwarded");
                    }
                    var update = Array.Find(updates, u => u.ImportName == updateImportName)!;
                    newThunks.Add(new(update.Import));
                }

                if (newThunks.Count > 0)
                {
                    imports.Add(existingImport with
                    {
                        OriginalFirstThunkRva = 0,
                        FirstThunkRva = 0,
                        FirstThunks = newThunks.ToArray()
                    });
                }

                dllNames.Remove(existingImport.DllName);
            }
        }

        foreach (var newDllName in dllNames)
        {
            // completely new import
            var thunks = updates.Where(u => u.DllName == newDllName).Select(u => new FunctionThunk(u.Import)).ToArray();
            imports.Add(new ModuleImport(newDllName, 0, 0, 0, thunks));
        }

        return imports.ToArray();
    }

    public static NewImportDataSize CalculateImportDirectorySize(ModuleImport[] moduleImports, bool is64bit)
    {
        var (thunksArraySize, stringsArraySize, importDescTableSize) =
            moduleImports.Aggregate((0, 0, 0), (acc, moduleImport) =>
        {
            var (thunksArraySize, stringsArraySize, importDescTableSize) = acc;

            if (moduleImport.DllNameRva == 0)
            {
                stringsArraySize += Encoding.ASCII.GetByteCount(moduleImport.DllName) + 1 /* null byte */;
            }

            importDescTableSize += Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();

            // thunks (only the ones that we need to allocate)
            if (moduleImport.FirstThunkRva == 0)
            {
                thunksArraySize = (moduleImport.FirstThunks.Length + 1 /* ending zero import */) *
                    (is64bit ? Marshal.SizeOf<IMAGE_THUNK_DATA64>() : Marshal.SizeOf<IMAGE_THUNK_DATA32>());

                stringsArraySize += moduleImport.FirstThunks.Aggregate(0, (acc, thunk) =>
                {
                    return thunk.Import switch
                    {
                        FunctionImportByName imp when imp.Rva == 0 => acc + Marshal.SizeOf(imp.Hint) +
                                Encoding.ASCII.GetByteCount(imp.FunctionName) + 1 /* null byte */,
                        _ => acc
                    };
                });
            }

            return (thunksArraySize, stringsArraySize, importDescTableSize);
        });

        return new NewImportDataSize(thunksArraySize, stringsArraySize,
            importDescTableSize + Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>() /* zero import */);
    }

    public static void UpdateImportsDirectory(HANDLE processHandle, uint imageBase, ModuleImport[] moduleImports)
    {
        bool Is64bit()
        {
            unsafe
            {
                BOOL isWow64 = false;
                return Environment.Is64BitOperatingSystem switch
                {
                    true => PInvoke.IsWow64Process(processHandle, &isWow64) ? !isWow64 : true,
                    false => false
                };
            }
        }

        bool is64bit = Is64bit();

        var newImportsSize = CalculateImportDirectorySize(moduleImports, is64bit);
        var newImportsAddr = FindAndAllocateNearBase(processHandle, imageBase, (uint)newImportsSize.TotalSize);
        if (newImportsAddr == nuint.Zero)
        {
            throw new Exception("Failed to allocate memory for new import data");
        }

        uint firstThunksRva = (uint)(newImportsAddr - imageBase);
        uint origFirstThunksRva = firstThunksRva + (uint)newImportsSize.ThunksArraySize;
        uint importDescTableRva = origFirstThunksRva + (uint)newImportsSize.ThunksArraySize;
        uint stringsRva = importDescTableRva + (uint)newImportsSize.ImportDescTableSize;

        uint WriteStringToRemoteProcessMemory(uint rva, string s)
        {
            unsafe
            {
                var bytes = Encoding.ASCII.GetBytes(s);
                fixed (void* pBytes = bytes)
                {
                    // wirtual memory allocated by VirtualAllocEx is set to zero, thus we don't need
                    // to add the zero byte here
                    if (!PInvoke.WriteProcessMemory(processHandle, (void*)(newImportsAddr + rva), pBytes, (uint)bytes.Length, null))
                    {
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Failed to write string data: '{s}'");
                    }
                }
                return rva + (uint)bytes.Length + 1 /* null byte */;
            }
        };

        uint WriteThunksToMemory(uint rva, bool is64bit, FunctionThunk[] thunks)
        {
            if (is64bit)
            {
                var nativeThunks = thunks.Select(thunk => thunk.Import switch
                {
                    FunctionImportByName imp => new IMAGE_THUNK_DATA64 { u1 = new IMAGE_THUNK_DATA64._u1_e__Union { AddressOfData = imp.Rva } },
                    FunctionImportByOrdinal imp => new IMAGE_THUNK_DATA64
                    {
                        u1 = new IMAGE_THUNK_DATA64._u1_e__Union
                        {
                            Ordinal = (ulong)imp.Ordinal | PInvoke.IMAGE_ORDINAL_FLAG64
                        }
                    },
                    _ => throw new ArgumentException("Unsupported thunk type")
                }).ToArray();

                unsafe
                {
                    fixed (void* pNativeThunks = nativeThunks)
                    {
                        if (!PInvoke.WriteProcessMemory(processHandle, (void*)(newImportsAddr + rva), pNativeThunks,
                            (uint)Marshal.SizeOf<IMAGE_THUNK_DATA64>() * ((uint)nativeThunks.Length + 1 /* ending zero thunk */), null))
                        {
                            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Failed to write thunk data");
                        }
                    }
                }

                rva += (uint)Marshal.SizeOf<IMAGE_THUNK_DATA64>() * ((uint)nativeThunks.Length + 1 /* ending zero thunk */);
            }
            else
            {
                var nativeThunks = thunks.Select(thunk => thunk.Import switch
                {
                    FunctionImportByName imp => new IMAGE_THUNK_DATA32 { u1 = new IMAGE_THUNK_DATA32._u1_e__Union { AddressOfData = imp.Rva } },
                    FunctionImportByOrdinal imp => new IMAGE_THUNK_DATA32
                    {
                        u1 = new IMAGE_THUNK_DATA32._u1_e__Union
                        {
                            Ordinal = imp.Ordinal | PInvoke.IMAGE_ORDINAL_FLAG32
                        }
                    },
                    _ => throw new ArgumentException("Unsupported thunk type")
                }).ToArray();

                unsafe
                {
                    fixed (void* pNativeThunks = nativeThunks)
                    {
                        if (!PInvoke.WriteProcessMemory(processHandle, (void*)(newImportsAddr + rva), pNativeThunks,
                            (uint)Marshal.SizeOf<IMAGE_THUNK_DATA32>() * ((uint)nativeThunks.Length + 1 /* ending zero thunk */), null))
                        {
                            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Failed to write thunk data");
                        }
                    }
                }

                rva += (uint)Marshal.SizeOf<IMAGE_THUNK_DATA32>() * ((uint)nativeThunks.Length + 1 /* ending zero thunk */);
            }
            return rva;
        }

        for (var i = 0; i < moduleImports.Length; i++)
        {
            var moduleImport = moduleImports[i];

            if (moduleImport.FirstThunkRva == 0)
            {
                // we need to replace import thunks
                var dllNameRva = moduleImport.DllNameRva;
                if (dllNameRva == 0)
                {
                    dllNameRva = stringsRva;
                    stringsRva = WriteStringToRemoteProcessMemory(stringsRva, moduleImport.DllName);
                }

                var firstThunks = moduleImport.FirstThunks;
                for (int j = 0; j < firstThunks.Length; j++)
                {
                    var thunk = firstThunks[j];
                    if (thunk.Import is FunctionImportByName imp && imp.Rva == 0)
                    {
                        var rva = stringsRva;
                        var hint = imp.Hint;
                        unsafe
                        {
                            if (!PInvoke.WriteProcessMemory(processHandle, (void*)(imageBase + rva), &hint, (uint)Marshal.SizeOf(imp.Hint), null))
                            {
                                throw new Win32Exception(Marshal.GetLastPInvokeError(),
                                    $"Failed to write import by name data for '{imp.FunctionName}'");
                            }
                        }
                        stringsRva = WriteStringToRemoteProcessMemory(
                            stringsRva + (uint)Marshal.SizeOf(imp.Hint), imp.FunctionName);
                        firstThunks[j] = new(imp with { Rva = rva });
                    }
                }
                var newFirstThunksRva = WriteThunksToMemory(firstThunksRva, is64bit, firstThunks);
                var newOrigFirstThunksRva = WriteThunksToMemory(origFirstThunksRva, is64bit, firstThunks);

                moduleImports[i] = moduleImport with
                {
                    DllNameRva = dllNameRva,
                    FirstThunkRva = firstThunksRva,
                    OriginalFirstThunkRva = origFirstThunksRva
                };

                firstThunksRva = newFirstThunksRva;
                origFirstThunksRva = newOrigFirstThunksRva;
            }
        }

        // write import descriptors
        // FIXME
    }
}

}
