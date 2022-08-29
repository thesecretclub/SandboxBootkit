using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace Installer
{
    internal class Program
    {
        static void Error(string message)
        {
            Console.WriteLine("[Error] " + message);
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
            Environment.Exit(1);
        }

        static void Info(string message)
        {
            Console.WriteLine("[Info] " + message);
        }

        class ProcessResult
        {
            public int ExitCode;
            public string Output;
        }

        static ProcessResult Exec(string program, string arguments = "")
        {
            var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = program,
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                },
            };
            p.Start();
            var stdout = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            return new ProcessResult
            {
                ExitCode = p.ExitCode,
                Output = stdout,
            };
        }

        static bool IsNetworkPath(string path)
        {
            var rootPath = Path.GetPathRoot(path);
            try
            {
                var info = new DriveInfo(rootPath);
                if (info.DriveType == DriveType.Network)
                {
                    return true;
                }
                return false;
            }
            catch
            {
                try
                {
                    return new Uri(rootPath).IsUnc;
                }
                catch
                {
                    return false;
                }
            }
        }

        static void Main(string[] args)
        {
            var basePath = AppDomain.CurrentDomain.BaseDirectory;
            if (IsNetworkPath(basePath))
                Error("Running from a network path is not supported");
            var whoResult = Exec("whoami");
            if (whoResult.Output.ToLowerInvariant().Contains("system"))
            {
                try
                {
                    Console.WriteLine("Running as system!");

                    var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                    var baseImages = Path.Combine(programData, "Microsoft", "Windows", "Containers", "BaseImages");
                    if (!Directory.Exists(baseImages))
                        Error($"Directory not found: {baseImages}");
                    Info($"BaseImages: {baseImages}");

                    var guid = Directory.EnumerateDirectories(baseImages).FirstOrDefault();
                    if (string.IsNullOrEmpty(guid))
                        Error($"BaseImages GUID not found, install & start Windows Sandbox");
                    Info($"GUID: {Path.GetFileName(guid)}");

                    var baseLayer = Path.Combine(guid, "BaseLayer");
                    if (!Directory.Exists(baseLayer))
                        Error($"Directory not found: {baseLayer}, install & start Windows Sandbox");
                    Info($"BaseLayer: {baseLayer}");

                    var bootPath = Path.Combine(baseLayer, "Files", "EFI", "Microsoft", "Boot");
                    if (!Directory.Exists(bootPath))
                        Error($"Directory not found: {bootPath}, install & start Windows Sandbox");
                    Info($"Boot: {bootPath}");

                    var bootmgfwPath = Path.Combine(bootPath, "bootmgfw.efi");
                    if (!File.Exists(bootmgfwPath))
                        Error($"File not found: {bootmgfwPath}, install & start Windows Sandbox");
                    Info($"bootmgfw.efi: {bootmgfwPath}");

                    var backupName = "bootmgfw.bak";
                    var bootmgfwBakPath = Path.Combine(bootPath, backupName);
                    if (!File.Exists(bootmgfwBakPath))
                    {
                        Info($"Creating backup of bootmgfw.efi -> {backupName}");
                        File.Copy(bootmgfwPath, bootmgfwBakPath);
                    }

                    var backupPath = Path.Combine(basePath, backupName);
                    if (!File.Exists(backupPath))
                    {
                        Info($"Copying bootmgfw.bak to local directory");
                        File.Copy(bootmgfwBakPath, backupPath);
                    }

                    Info("Injecting SandboxBootkit.efi into bootmgfw.bak");
                    var sandboxBootkit = Path.Combine(basePath, "SandboxBootkit.efi");
                    if (!File.Exists(sandboxBootkit))
                        Error($"Bootkit not found ${sandboxBootkit}, please compile SandboxBootkit");

                    Info("Running injector");

                    var injector = Path.Combine(basePath, "Injector.exe");
                    if (!File.Exists(injector))
                        Error($"Injector not found: {injector}");
                    var bootkitPath = Path.Combine(basePath, "bootmgfw.efi");
                    var pythonResult = Exec(injector, $"\"{backupPath}\" \"{sandboxBootkit}\" \"{bootkitPath}\"");
                    Console.WriteLine(pythonResult.Output.Trim());
                    if (pythonResult.ExitCode != 0)
                        Error($"Failed to inject bootkit!\n" + pythonResult.Output.Trim());

                    Info("Installing bootmgfw.efi with bootkit injected");
                    File.Copy(bootkitPath, bootmgfwPath, true);

                    Info("Bootkit installed: " + bootmgfwPath);
                    Console.WriteLine("Success!");

                    void UpdateBcdFile(string root)
                    {
                        Info($"Setting NOINTEGRITYCHECKS in {root}");
                        var bcdPath = Path.Combine(root, "EFI", "Microsoft", "Boot", "BCD");
                        if (!File.Exists(bcdPath))
                            Error($"Not found: {bcdPath}");
                        var bcdeditResult = Exec("bcdedit", $"/store \"{bcdPath}\" /set {{bootmgr}} nointegritychecks on");
                        Console.WriteLine(bcdeditResult.Output.Trim());
                        if (bcdeditResult.ExitCode != 0)
                            Error($"Failed to update: {bcdPath}");
                    }

                    var debugLayer = Path.Combine(guid, "DebugLayer");
                    if (Directory.Exists(debugLayer))
                    {
                        UpdateBcdFile(debugLayer);
                    }
                    UpdateBcdFile(Path.Combine(baseLayer, "Files"));
                }
                catch (Exception x)
                {
                    Console.WriteLine(x);
                }

                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
            else
            {
                Console.WriteLine($"Running as {whoResult.Output.Trim()}, elevating to TrustedInstaller...");
                var sudo = Path.Combine(basePath, "NSudoLG.exe");
                if (!File.Exists(sudo))
                    Error("Failed to find NSudoLG.exe");
                var selfLocation = Assembly.GetExecutingAssembly().Location;
                Exec(sudo, $"-U:T -P:E -Wait \"{selfLocation}\"");
            }
        }
    }
}
