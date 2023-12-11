using System.Diagnostics;
using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using Windows.Win32.System.WindowsProgramming;
using Windows.Win32.System.SystemServices;

namespace importando.tests;

public class PEImportsTests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void TestFindAndAllocateNearBase()
    {
        var process = Process.Start("winver.exe");
        var imageBase = (nuint)process.MainModule!.BaseAddress;

        var allocAddress = PEImports.FindAndAllocateNearBase(new HANDLE(process.Handle), imageBase, 256);
        Assert.That(allocAddress, Is.Not.EqualTo(nuint.Zero));

        process.CloseMainWindow();
        process.WaitForExit(1000);
        if (!process.HasExited)
        {
            process.Kill();
        }
    }

    [Test]
    public void TestParsingUpdates()
    {
        string[] arguments = ["Test1.dll:Test2.dll"];
        Assert.That(() => PEImports.ParseImportUpdates(arguments), Throws.TypeOf<ArgumentException>());
        arguments = ["Test1.dll!Function:Test2.dll"];
        Assert.That(() => PEImports.ParseImportUpdates(arguments), Throws.TypeOf<ArgumentException>());
        arguments = ["Test1.dll!Function:Test2.dll:Test3"];
        Assert.That(() => PEImports.ParseImportUpdates(arguments), Throws.TypeOf<ArgumentException>());

        arguments = [
            "Test1.dll!Function13",
            "test1.dll!Function11:tEST2.dll!Function21",
            "test2.dll!Function21",
            "Test2.dll!Function21:Test1.dll!Function11",
            "test1.dll#11",
            "test1.dll#13:test2.dll#21",
            "test1.DLL#13:test3.dll#31"
        ];
        var (forwardings, importUpdates) = PEImports.ParseImportUpdates(arguments);

        Assert.That(importUpdates.Length, Is.EqualTo(arguments.Length));
        int ind = 0;
        Assert.That(importUpdates[ind++], Is.EqualTo(new ImportUpdate(
            "TEST1.DLL!Function13", "TEST1.DLL", new FunctionImportByName(0, 0, "Function13"))));
        Assert.That(importUpdates[ind++], Is.EqualTo(new ImportUpdate(
            "TEST1.DLL!Function11", "TEST1.DLL", new FunctionImportByName(0, 0, "Function11"))));
        Assert.That(importUpdates[ind++], Is.EqualTo(new ImportUpdate(
            "TEST2.DLL!Function21", "TEST2.DLL", new FunctionImportByName(0, 0, "Function21"))));
        Assert.That(importUpdates[ind++], Is.EqualTo(new ImportUpdate(
            "TEST1.DLL#11", "TEST1.DLL", new FunctionImportByOrdinal(11))));
        Assert.That(importUpdates[ind++], Is.EqualTo(new ImportUpdate(
            "TEST1.DLL#13", "TEST1.DLL", new FunctionImportByOrdinal(13))));
        Assert.That(importUpdates[ind++], Is.EqualTo(new ImportUpdate(
            "TEST2.DLL#21", "TEST2.DLL", new FunctionImportByOrdinal(21))));
        Assert.That(importUpdates[ind++], Is.EqualTo(new ImportUpdate(
            "TEST3.DLL#31", "TEST3.DLL", new FunctionImportByOrdinal(31))));
        Assert.That(ind, Is.EqualTo(arguments.Length));

        ind = 0;
        Assert.That(forwardings[ind++], Is.EqualTo(("TEST1.DLL!Function11", "TEST2.DLL!Function21")));
        Assert.That(forwardings[ind++], Is.EqualTo(("TEST2.DLL!Function21", "TEST1.DLL!Function11")));
        Assert.That(forwardings[ind++], Is.EqualTo(("TEST1.DLL#13", "TEST2.DLL#21")));
        Assert.That(forwardings[ind++], Is.EqualTo(("TEST1.DLL#13", "TEST3.DLL#31")));
        Assert.That(ind, Is.EqualTo(forwardings.Length));
    }

    [Test]
    public void TestPreparingNewImports()
    {
        var existingImports = new ModuleImport[]
        {
                new("TEST0.DLL", 10, 1, 2, [
                    new(new FunctionImportByName(10, 11, "Function01")),
                    new(new FunctionImportByName(18, 12, "Function02")),
                ]),
                new("TEST1.DLL", 100, 11, 12, [
                    new(new FunctionImportByName(1100, 11, "Function11")),
                    new(new FunctionImportByName(1108, 12, "Function12")),
                    new(new FunctionImportByName(1116, 13, "Function13")),
                    new(new FunctionImportByOrdinal(13)),
                ]),
                new("TEST2.DLL", 200, 21, 22, [
                    new(new FunctionImportByName(2100, 21, "Function21")),
                    new(new FunctionImportByName(2108, 22, "Function22")),
                ]),
        };

        string[] arguments = [
            "Test1.dll!Function13",
            "test1.dll!Function11:tEST2.dll!Function21",
            "test1.DLL!Function18:test3.dll!Function31", // not existing
            "test1.dll#14:test4.dll#41" // not existing
        ];
        var (forwardings, importUpdates) = PEImports.ParseImportUpdates(arguments);
        Assert.That(() => PEImports.PrepareNewModuleImports(existingImports, importUpdates, forwardings),
            Throws.TypeOf<ArgumentException>());

        arguments = [
            "Test1.dll!Function13",
            "test2.dll!Function21",
            "Test2.dll!Function21:Test1.dll!Function11", // this forward will override the previous line
            "test1.dll#11",
            "test1.dll#13:test2.dll#21",
            "test1.DLL#13:test3.dll#31",
            "test1.DLL!Function12:test3.dll#33",
        ];
        (forwardings, importUpdates) = PEImports.ParseImportUpdates(arguments);

        var newImports = PEImports.PrepareNewModuleImports(existingImports, importUpdates, forwardings);
        var ind = 0;
        Assert.That(newImports[ind].DllName, Is.EqualTo("TEST0.DLL"));
        Assert.That(newImports[ind].DllNameRva, Is.EqualTo(10));
        Assert.That(newImports[ind].FirstThunks, Is.EqualTo(new FunctionThunk[] {
                new(new FunctionImportByName(10, 11, "Function01")),
                new(new FunctionImportByName(18, 12, "Function02")),
            }));
        ind++;

        Assert.That(newImports[ind].DllName, Is.EqualTo("TEST1.DLL"));
        Assert.That(newImports[ind].DllNameRva, Is.EqualTo(100));
        Assert.That(newImports[ind].FirstThunks, Is.EqualTo(new FunctionThunk[] {
                new(new FunctionImportByName(1100, 11, "Function11")),
                new(new FunctionImportByName(1116, 13, "Function13")),
                new(new FunctionImportByOrdinal(11)),
            }));
        ind++;

        Assert.That(newImports[ind].DllName, Is.EqualTo("TEST2.DLL"));
        Assert.That(newImports[ind].DllNameRva, Is.EqualTo(200));
        Assert.That(newImports[ind].FirstThunks, Is.EqualTo(new FunctionThunk[] {
                new(new FunctionImportByName(2108, 22, "Function22")),
                new(new FunctionImportByOrdinal(21)),
            }));
        ind++;

        Assert.That(newImports[ind].DllName, Is.EqualTo("TEST3.DLL"));
        Assert.That(newImports[ind].DllNameRva, Is.EqualTo(0));
        Assert.That(newImports[ind].FirstThunks, Is.EqualTo(new FunctionThunk[] {
                new(new FunctionImportByOrdinal(31)),
                new(new FunctionImportByOrdinal(33)),
            }));
        ind++;

        Assert.That(newImports.Length, Is.EqualTo(ind));
    }

    [Test]
    public void TestCalculateImportDirectorySize()
    {
        var moduleImports = new ModuleImport[]
        {
                new("TEST0.DLL", 10, 1, 2, [
                    new(new FunctionImportByName(10, 11, "Function01")),
                    new(new FunctionImportByName(18, 12, "Function02")),
                ]),
                new("TEST1.DLL", 0, 0, 0, [
                    new(new FunctionImportByName(0, 0, "Function11")),
                    new(new FunctionImportByName(1108, 12, "Function12")),
                    new(new FunctionImportByName(1116, 13, "Function13")),
                    new(new FunctionImportByOrdinal(13)),
                ])
        };

        var size = PEImports.CalculateImportDirectorySize(moduleImports, false);
        Assert.That(size.ThunksArraySize, Is.EqualTo(
            (moduleImports[1].FirstThunks.Length + 1 /* zero thunk */) * Marshal.SizeOf<IMAGE_THUNK_DATA32>()));
        Assert.That(size.StringsArraySize, Is.EqualTo(
            moduleImports[1].DllName.Length + 1 /* null byte */ +
                ((FunctionImportByName)moduleImports[1].FirstThunks[0].Import).FunctionName.Length + 1 +
                    sizeof(ushort) /* hint */));
        Assert.That(size.ImportDescTableSize, Is.EqualTo(3 * Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>()));

        size = PEImports.CalculateImportDirectorySize(moduleImports, true);
        Assert.That(size.ThunksArraySize, Is.EqualTo(
            (moduleImports[1].FirstThunks.Length + 1 /* zero thunk */) * Marshal.SizeOf<IMAGE_THUNK_DATA64>()));
        Assert.That(size.StringsArraySize, Is.EqualTo(
            moduleImports[1].DllName.Length + 1 /* null byte */ +
                ((FunctionImportByName)moduleImports[1].FirstThunks[0].Import).FunctionName.Length + 1 +
                    sizeof(ushort) /* hint */));
        Assert.That(size.ImportDescTableSize, Is.EqualTo(3 * Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>()));
    }
}