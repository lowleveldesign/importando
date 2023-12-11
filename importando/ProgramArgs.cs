using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace importando;

record ImportUpdate(string ImportName, string DllName, IFunctionImport Import);

internal class ProgramArgs
{
    public static Dictionary<string, List<string>> ParseArgs(string[] flagNames, string[] rawArgs)
    {
        var args = rawArgs.SelectMany(arg => arg.Split(new[] { '=' }, StringSplitOptions.RemoveEmptyEntries)).ToArray();
        bool IsFlag(string v) => Array.IndexOf(flagNames, v) >= 0;

        var result = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var lastOption = "";
        var firstFreeArgPassed = false;

        foreach (var arg in args)
        {
            if (!firstFreeArgPassed && arg.StartsWith("-", StringComparison.Ordinal))
            {
                var option = arg.TrimStart('-');
                if (IsFlag(option))
                {
                    Debug.Assert(lastOption == "");
                    result[option] = [];
                }
                else
                {
                    Debug.Assert(lastOption == "");
                    lastOption = option;
                }
            }
            else
            {
                // the logic is the same for options (lastOption) and free args
                if (result.TryGetValue(lastOption, out var values))
                {
                    values.Add(arg);
                }
                else
                {
                    result[lastOption] = [arg];
                }
                firstFreeArgPassed = lastOption == "";
                lastOption = "";
            }
        }
        return result;
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
}
