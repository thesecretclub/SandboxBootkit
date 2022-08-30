using System;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;

namespace Installer
{
    public class InstallException : Exception
    {
        public InstallException(string message)
            : base(message)
        {
        }
    }

    internal class Program
    {
        static void Error(string message)
        {
            throw new InstallException(message);
        }

        static void Info(string message)
        {
            Console.WriteLine("[Info] " + message);
        }

        static void Pause()
        {
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
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

        static void SetDevelopmentMode(bool enabled, string baseLayer, int timeoutMs = 10000)
        {
            var verb = enabled ? "On" : "Off";
            Info($"Turning development mode {verb.ToLower()}");
            var cmDiagResult = Exec("CmDiag", $"DevelopmentMode -{verb}");
            if (cmDiagResult.ExitCode != 0)
                Error($"Failed to turn development mode {verb} (sandbox running?)");

            // It can take a while until the BaseLayer.vhdx is remounted properly
            Info($"Waiting for BaseLayer to remount...");
            for (var i = 0; i < timeoutMs / 100; i++)
            {
                if (Directory.Exists(baseLayer))
                    return;
                Thread.Sleep(100);
            }
            Error($"Could not wait for CmService, try rebooting");
        }

        static bool WaitForService(string service, string expectedStatus, int timeoutMs = 10000)
        {
            Info($"Waiting for {service} to be {expectedStatus}");
            for (var i = 0; i < timeoutMs / 100; i++)
            {
                var scResult = Exec("sc", $"query \"{service}\"");
                if (scResult.Output.Contains(expectedStatus))
                    return true;
                Thread.Sleep(100);
            }
            return false;
        }

        static int Main(string[] args)
        {
            try
            {
                var basePath = AppDomain.CurrentDomain.BaseDirectory;
                if (IsNetworkPath(basePath))
                    Error("Running from a network path is not supported");
                foreach (var file in Directory.EnumerateFiles(basePath))
                {
                    var zoneFile = file + ":Zone.Identifier";
                    if (File.Exists(zoneFile))
                        File.Delete(zoneFile);
                }
                var whoResult = Exec("whoami");
                if (whoResult.Output.ToLowerInvariant().Contains("system"))
                {
                    Info("Running as system!");

                    var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                    var baseImages = Path.Combine(programData, "Microsoft", "Windows", "Containers", "BaseImages");
                    if (!Directory.Exists(baseImages))
                        Error($"Directory not found: {baseImages}, install & start Windows Sandbox");
                    Info($"BaseImages: {baseImages}");

                    var guid = Directory.EnumerateDirectories(baseImages).FirstOrDefault();
                    if (string.IsNullOrEmpty(guid))
                        Error($"BaseImages GUID not found, install & start Windows Sandbox");
                    Info($"GUID: {Path.GetFileName(guid)}");

                    var baseLayer = Path.Combine(guid, "BaseLayer");
                    if (!Directory.Exists(baseLayer))
                        Error($"Directory not found: {baseLayer}, install & start Windows Sandbox");
                    Info($"BaseLayer: {baseLayer}");

                    // Without development mode BaseLayer isn't mounted writable
                    var debugLayer = Path.Combine(guid, "DebugLayer");
                    var developmentMode = Directory.Exists(debugLayer);
                    if (!developmentMode)
                        SetDevelopmentMode(true, baseLayer);

                    try
                    {
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

                        var injector = Path.Combine(basePath, "Injector", "Injector.exe");
                        if (!File.Exists(injector))
                            Error($"Injector not found: {injector}");
                        var bootkitPath = Path.Combine(basePath, "bootmgfw.efi");
                        var injectResult = Exec(injector, $"\"{backupPath}\" \"{sandboxBootkit}\" \"{bootkitPath}\"");
                        Console.WriteLine(injectResult.Output.Trim());
                        if (injectResult.ExitCode != 0)
                            Error($"Failed to inject bootkit!");

                        Info("Installing bootmgfw.efi with bootkit injected");
                        File.Copy(bootkitPath, bootmgfwPath, true);

                        Info("Bootkit installed: " + bootmgfwPath);
                        Console.WriteLine("Success!");

                        void UpdateBcdFile(string root)
                        {
                            Info($"Setting NOINTEGRITYCHECKS in {root}");
                            var bcdFolder = Path.Combine(root, "EFI", "Microsoft", "Boot");
                            var bcdPath = Path.Combine(bcdFolder, "BCD");
                            if (!File.Exists(bcdPath))
                                Error($"Not found: {bcdPath}");
                            var bakPath = bcdPath + ".bak";
                            if (!File.Exists(bakPath))
                                File.Copy(bcdPath, bakPath);
                            var bcdeditResult = Exec("bcdedit", $"/store \"{bcdPath}\" /set {{bootmgr}} nointegritychecks on");
                            Console.WriteLine(bcdeditResult.Output.Trim());
                            if (bcdeditResult.ExitCode != 0)
                                Error($"Failed to update: {bcdPath}");
                        }

                        if (Directory.Exists(debugLayer))
                            UpdateBcdFile(debugLayer);
                        UpdateBcdFile(Path.Combine(baseLayer, "Files"));

                        // Without this the sandbox can use a snapshot and load the original bootmgfw.efi
                        Info($"Deleting sandbox snapshots");
                        var snapshotFolder = Path.Combine(guid, "Snapshot");
                        if (Directory.Exists(snapshotFolder))
                        {
                            Directory.Delete(snapshotFolder, true);
                            Info($"Restarting CmService");
                            Exec("sc", "stop CmService");
                            WaitForService("CmService", "STOPPED");
                            Exec("sc", "start CmService");
                            WaitForService("CmService", "RUNNING");
                        }
                    }
                    finally
                    {
                        // Restore development mode (startup performance is horrendous when development mode is enabled)
                        // This should also restore development mode if something went wrong
                        if (!developmentMode)
                            SetDevelopmentMode(false, baseLayer);
                    }

                    Pause();
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
                return 0;
            }
            catch (InstallException x)
            {
                Console.WriteLine("[Error] " + x.Message);
                Pause();
                return 1;
            }
        }
    }
}
