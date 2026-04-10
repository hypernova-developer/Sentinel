using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace bettercpp.sentinel
{
    class SentinelCore
    {
        [DllImport("Wintrust.dll", PreserveSig = true, CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, WinTrustData pWVTData);

        static string version = "2.0.0-LTS";
        static string quarantineDir = @"C:\Tools\Jenny\Quarantine";
        static string currentSelfHash = "";
        static Dictionary<string, ThreatInfo> detectedThreats = new Dictionary<string, ThreatInfo>();

        static List<string> criticalServices = new List<string> {
            "wpcmonsvc", "svchost", "lsass", "services", "wininit",
            "csrss", "smss", "winlogon", "taskhostw", "spoolsv"
        };

        static List<string> developerWorkspaces = new List<string> {
            @"C:\Tools", @"C:\mingw64", @"C:\msys64", @"E:\Developing"
        };

        static List<string> driverWhitelist = new List<string> {
            "pusat k3", "hid.exe", "mouseconfig", "keyboard driver", "peripheral"
        };

        class ThreatInfo {
            public int Score;
            public List<string> Reasons = new List<string>();
        }

        static void Main(string[] args)
        {
            currentSelfHash = GetFileHash(Process.GetCurrentProcess().MainModule.FileName);
            if (!Directory.Exists(quarantineDir)) Directory.CreateDirectory(quarantineDir);

            if (args.Length > 0 && args[0].ToLower() == "--restore") {
                RestoreQuarantine();
                return;
            }

            if (args.Length > 0 && args[0].ToLower() == "--network-scan") {
                ScanNetworkActivity();
                return;
            }

            string path = args.Length > 0 ? args[0] : Environment.CurrentDirectory;
            Console.WriteLine("\n[SENTINEL CORE v" + version + "] Precision Scan Initiated: " + path);

            try {
                ScanDirectoryRecursively(path);
                ReportAndHandleThreats();
            }
            catch (Exception e) { Console.WriteLine("Fatal Error: " + e.Message); }

            Console.WriteLine("\n[PRESS ENTER TO EXIT]");
            Console.ReadLine();
        }

        static void ScanNetworkActivity()
        {
            Console.WriteLine("\n[SENTINEL NETWORK] Analyzing Unsigned & External Connections...");
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            TcpConnectionInformation[] connections = properties.GetActiveTcpConnections();
            string winPath = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
            
            foreach (Process p in Process.GetProcesses())
            {
                try {
                    string path = p.MainModule.FileName;
                    if (IsHardwareDriver(path) || GetFileHash(path) == currentSelfHash) continue;

                    bool isSigned = IsFileSigned(path);
                    bool isTrusted = path.ToLower().Contains("windowsapps") || path.ToLower().Contains("winget");
                    bool isSys = path.ToLower().StartsWith(winPath) || path.ToLower().Contains(@"\windows\");

                    if (!isSigned && !isTrusted && !isSys)
                    {
                        if (connections.Any(c => c.State == TcpState.Established))
                        {
                            if (!detectedThreats.ContainsKey(path))
                                detectedThreats.Add(path, new ThreatInfo { Score = 100, Reasons = new List<string> { "Unsigned process with active network activity" } });
                        }
                    }
                } catch { }
            }
            ReportAndHandleThreats();
        }

        static bool IsHardwareDriver(string path)
        {
            string fileName = Path.GetFileName(path).ToLower();
            string pathLower = path.ToLower();
            return driverWhitelist.Any(d => fileName.Contains(d) || pathLower.Contains(@"\pusat\") || pathLower.Contains(@"\peripheral\"));
        }

        static void ReportAndHandleThreats()
        {
            Console.WriteLine("\n" + new string('-', 50));
            Console.WriteLine("[+] Analysis Finished. Total Threats: " + detectedThreats.Count);

            if (detectedThreats.Count > 0) {
                foreach (KeyValuePair<string, ThreatInfo> entry in detectedThreats) {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n-> " + Path.GetFileName(entry.Key) + " | TOTAL SCORE: " + entry.Value.Score + "/100");
                    Console.ResetColor();
                    foreach (string reason in entry.Value.Reasons) Console.WriteLine("   [!] " + reason);
                    Console.WriteLine("   [#] SHA256: " + GetFileHash(entry.Key));
                }
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("\n[?] Move detected files to secure quarantine? (-y / -n): ");
                if (Console.ReadLine().ToLower() == "-y") {
                    foreach (string file in detectedThreats.Keys) QuarantineFile(file);
                    Console.WriteLine("\n[+] Isolation complete.");
                }
            }
        }

        static void ScanDirectoryRecursively(string root)
        {
            string pathLower = root.ToLower();
            if (pathLower.Contains(@"c:\windows") || pathLower.Contains("winsxs")) return;

            try {
                foreach (string file in Directory.GetFiles(root, "*.exe")) {
                    if (GetFileHash(file) == currentSelfHash) continue;
                    List<string> reasons;
                    int score = AnalyzeFile(file, out reasons);
                    if (score >= 40) detectedThreats.Add(file, new ThreatInfo { Score = Math.Min(score, 100), Reasons = reasons });
                }
                foreach (string dir in Directory.GetDirectories(root)) ScanDirectoryRecursively(dir);
            } catch { }
        }

        static int AnalyzeFile(string fullPath, out List<string> reasons)
        {
            reasons = new List<string>();
            if (IsHardwareDriver(fullPath)) return 0;

            int threatScore = 0;
            string fileName = Path.GetFileNameWithoutExtension(fullPath).ToLower();
            string pathLower = fullPath.ToLower();

            bool isSigned = IsFileSigned(fullPath);
            bool isStartup = CheckStartupStatus(fullPath);
            bool isTrusted = pathLower.Contains(@"\windowsapps\") || pathLower.Contains(@"\microsoft\winget\");

            if (!isSigned) { 
                if (!isTrusted) {
                    threatScore += 50; 
                    reasons.Add("No Valid Digital Signature");
                } else {
                    threatScore += 10;
                    reasons.Add("Unsigned but verified Package Origin");
                }
            }
            
            if (developerWorkspaces.Any(path => fullPath.StartsWith(path, StringComparison.OrdinalIgnoreCase))) {
                threatScore -= 30; 
                reasons.Add("Safe Zone: Developer Workspace");
            }

            if (isStartup && !isSigned && !isTrusted) { 
                threatScore += 50; 
                reasons.Add("Persistence Alert: Unsigned file in Startup"); 
            }

            foreach (string service in criticalServices) {
                if (fileName == service && !pathLower.Contains(@"c:\windows\system32")) {
                    threatScore += 70;
                    reasons.Add("Location Anomaly: " + service + " masquerading");
                }
                if (IsSimilar(fileName, service)) {
                    threatScore += 50;
                    reasons.Add("Typosquatting: Mimicking " + service);
                }
            }
            return threatScore;
        }

        static bool IsFileSigned(string path)
        {
            try {
                Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
                WinTrustFileInfo fileInfo = new WinTrustFileInfo(path);
                WinTrustData wtData = new WinTrustData(fileInfo);
                int result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, wtData);
                bool signed = (result == 0);
                wtData.Dispose();
                fileInfo.Dispose();
                return signed;
            } catch { return false; }
        }

        static bool CheckStartupStatus(string path)
        {
            try {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")) {
                    if (key != null) foreach (string v in key.GetValueNames()) if (key.GetValue(v).ToString().ToLower().Contains(path.ToLower())) return true;
                }
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")) {
                    if (key != null) foreach (string v in key.GetValueNames()) if (key.GetValue(v).ToString().ToLower().Contains(path.ToLower())) return true;
                }
            } catch { }
            return false;
        }

        static bool IsSimilar(string s1, string s2) {
            if (s1 == s2 || Math.Abs(s1.Length - s2.Length) > 1) return false;
            int diffs = 0;
            int minLen = Math.Min(s1.Length, s2.Length);
            for (int i = 0; i < minLen; i++) if (s1[i] != s2[i]) diffs++;
            return diffs > 0 && diffs <= 2;
        }

        static string GetFileHash(string filename) {
            try {
                using (SHA256 sha = SHA256.Create()) {
                    using (FileStream fs = File.OpenRead(filename)) {
                        byte[] hash = sha.ComputeHash(fs);
                        string hashStr = "";
                        foreach (byte b in hash) hashStr += b.ToString("x2");
                        return hashStr;
                    }
                }
            } catch { return "error"; }
        }

        static void QuarantineFile(string sourcePath)
        {
            try {
                string fileName = Path.GetFileName(sourcePath);
                string destPath = Path.Combine(quarantineDir, fileName + ".jny_locked");
                string mapPath = Path.Combine(quarantineDir, fileName + ".map");
                if (File.Exists(sourcePath)) {
                    File.WriteAllText(mapPath, sourcePath);
                    File.Move(sourcePath, destPath);
                }
            } catch { }
        }

        static void RestoreQuarantine()
        {
            foreach (string map in Directory.GetFiles(quarantineDir, "*.map")) {
                try {
                    string originalPath = File.ReadAllText(map).Trim();
                    string lockedFile = map.Replace(".map", ".jny_locked");
                    if (File.Exists(lockedFile)) {
                        string targetDir = Path.GetDirectoryName(originalPath);
                        if (!Directory.Exists(targetDir)) Directory.CreateDirectory(targetDir);
                        File.Move(lockedFile, originalPath);
                        File.Delete(map);
                    }
                } catch { }
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    class WinTrustFileInfo
    {
        Int32 cbStruct = Marshal.SizeOf(typeof(WinTrustFileInfo));
        IntPtr pcwszFilePath;
        IntPtr hFile = IntPtr.Zero;
        IntPtr pgKnownSubject = IntPtr.Zero;
        public WinTrustFileInfo(string path) { pcwszFilePath = Marshal.StringToHGlobalUni(path); }
        public void Dispose() { Marshal.FreeHGlobal(pcwszFilePath); }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    class WinTrustData
    {
        Int32 cbStruct = Marshal.SizeOf(typeof(WinTrustData));
        IntPtr pPolicyCallbackData = IntPtr.Zero;
        IntPtr pSIPClientData = IntPtr.Zero;
        Int32 dwUIChoice = 2; 
        Int32 fdwRevocationChecks = 0;
        Int32 dwUnionChoice = 1;
        IntPtr pFile;
        Int32 dwStateAction = 0;
        IntPtr hWVTStateData = IntPtr.Zero;
        IntPtr pwszURLReference = IntPtr.Zero;
        Int32 dwProvFlags = 0x00000040; 
        Int32 dwUIContext = 0;
        public WinTrustData(WinTrustFileInfo fileInfo) { pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustFileInfo))); Marshal.StructureToPtr(fileInfo, pFile, false); }
        public void Dispose() { Marshal.FreeHGlobal(pFile); }
    }
}