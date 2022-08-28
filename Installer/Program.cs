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

        static string FindPython()
        {
            string pythonPath = null;
            using (var pythonCore = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Python\PythonCore"))
            {
                if (pythonCore != null)
                {
                    var maxVersion = 0;
                    string maxVersionString = "";
                    foreach (var pythonVersion in pythonCore.GetSubKeyNames())
                    {
                        var s = pythonVersion.Split('.');
                        var major = int.Parse(s[0]);
                        var minor = int.Parse(s[1]);
                        var version = major * 10000 + minor;
                        if (major >= 3 && version > maxVersion)
                        {
                            maxVersion = version;
                            maxVersionString = pythonVersion;
                        }
                    }
                    using (var maxPython = pythonCore.OpenSubKey(maxVersionString + "\\InstallPath"))
                    {
                        if (maxPython != null)
                        {
                            var executablePath = maxPython.GetValue("ExecutablePath") as string;
                            return executablePath;
                        }
                    }
                }
                return pythonPath;
            }
        }

        static void Main(string[] args)
        {
            var basePath = AppDomain.CurrentDomain.BaseDirectory;
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

                    var bootkitPath = Path.Combine(basePath, "bootmgfw.efi");
                    if (File.Exists(bootkitPath))
                    {
                        Info($"Recreating injected bootmgfw.efi");
                        File.Delete(bootkitPath);
                    }

                    Info("Injecting SandboxBootkit.efi into bootmgfw.bak");
                    var sandboxBootkit = Path.Combine(basePath, "SandboxBootkit.efi");
                    if (!File.Exists(sandboxBootkit))
                        Error($"Bootkit not found ${sandboxBootkit}, please compile SandboxBootkit");

                    // TODO: rewrite this in C++
                    Info("Running injector.py");
                    var python = FindPython();
                    if (string.IsNullOrEmpty(python))
                        Error($"Failed to find python 3, download at: https://www.python.org/downloads/ (Note: install for all users)");

                    var injector = Path.Combine(basePath, "injector.py");
                    // TODO: redirect stderr?
                    var pythonResult = Exec(python, $"\"{injector}\" \"{backupPath}\" \"{sandboxBootkit}\"");
                    Console.WriteLine(pythonResult.Output);
                    if (pythonResult.ExitCode != 0)
                        Error($"Failed to inject bootkit!\n" + pythonResult.Output.Trim());

                    Info("Installing bootmgfw.efi with bootkit injected");
                    File.Copy(bootkitPath, bootmgfwPath, true);

                    Info("Bootkit installed: " + bootmgfwPath);
                    Console.WriteLine("Success!");

                    // TODO: disable integrity checks (also in DebugLayer)

                    Console.WriteLine("\nPress any key to exit...");
                    Console.ReadKey();
                }
                catch (Exception x)
                {
                    Console.WriteLine(x);

                    Console.WriteLine("\nPress any key to exit...");
                    Console.ReadKey();
                }
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
