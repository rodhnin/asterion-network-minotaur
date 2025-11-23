using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Models;

namespace Asterion.Checks.CrossPlatform.Windows
{
    /// <summary>
    /// Windows Privilege Escalation Check
    /// Detects misconfigurations that could allow privilege escalation
    /// 
    /// Comprehensive checks including:
    /// - Service executable and directory permissions
    /// - Unquoted service paths with spaces
    /// - Service DLL hijacking opportunities
    /// - Scheduled task executable permissions
    /// - AlwaysInstallElevated registry misconfiguration
    /// - Weak ACLs on system directories
    /// - Writable PATH directories
    /// - AutoRun registry keys with writable targets
    /// - Startup folder permissions
    /// - Token privileges (SeImpersonatePrivilege for Potato attacks)
    /// 
    /// Findings:
    /// - AST-PRIV-WIN-001: Service executable writable by non-admins
    /// - AST-PRIV-WIN-002: Unquoted service path with spaces
    /// - AST-PRIV-WIN-003: Service DLL hijacking possible
    /// - AST-PRIV-WIN-004: Scheduled task with writable executable
    /// - AST-PRIV-WIN-005: AlwaysInstallElevated registry key set
    /// - AST-PRIV-WIN-006: Weak ACLs on system directories
    /// - AST-PRIV-WIN-007: Writable PATH directories
    /// - AST-PRIV-WIN-008: Writable AutoRun registry targets
    /// - AST-PRIV-WIN-009: Writable startup folder
    /// - AST-PRIV-WIN-010: SeImpersonatePrivilege enabled (Potato attack risk)
    /// 
    /// Requirements:
    /// - Windows OS
    /// - Elevated privileges recommended for complete checks
    /// </summary>
    public class PrivEscCheckWin : BaseCheck
    {
        public override string Name => "Windows Privilege Escalation Check";
        
        public override CheckCategory Category => CheckCategory.Windows;
        
        public override string Description => 
            "Comprehensive audit of Windows privilege escalation vectors including service misconfigurations, " +
            "weak file permissions, registry vulnerabilities, and token privilege issues. " +
            "Checks for common attack techniques used by tools like PowerUp, WinPEAS, and PrivescCheck.";

        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        public PrivEscCheckWin(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var findings = new List<Finding>();

            // This check requires local execution
            bool isLocal = targets.Contains("localhost") || 
                          targets.Contains("127.0.0.1") || 
                          targets.Any(t => t.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase));

            if (!isLocal && targets.Any())
            {
                Log.Debug("{CheckName}: Requires local execution, skipping remote targets", Name);
                return findings;
            }

            Log.Information("[{CheckName}] Performing comprehensive Windows privilege escalation audit", Name);

            // Check if running with elevated privileges
            bool isElevated = IsAdministrator();
            if (!isElevated)
            {
                Log.Warning("{CheckName}: Not running with elevated privileges, some checks may be limited", Name);
            }

            try
            {
                // Service-related checks
                findings.AddRange(await CheckServiceExecutablesAsync());
                findings.AddRange(await CheckServiceDirectoriesAsync());
                findings.AddRange(await CheckUnquotedServicePathsAsync());
                findings.AddRange(await CheckServiceDllHijackingAsync());

                // Scheduled tasks
                findings.AddRange(await CheckScheduledTasksAsync());

                // Registry checks
                findings.AddRange(await CheckAlwaysInstallElevatedAsync());
                findings.AddRange(await CheckAutoRunKeysAsync());

                // File system checks
                findings.AddRange(await CheckWeakDirectoryAclsAsync());
                findings.AddRange(await CheckPathDirectoriesAsync());
                findings.AddRange(await CheckStartupFoldersAsync());

                // Token privilege checks
                findings.AddRange(await CheckTokenPrivilegesAsync());
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error during privilege escalation check", Name);
            }

            LogExecution(1, findings.Count); // 1 target = local system
            return findings;
        }

        #region Service Executable Checks

        private Task<List<Finding>> CheckServiceExecutablesAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("{CheckName}: Checking service executable permissions...", Name);

                // Query services running as SYSTEM
                var query = new SelectQuery("SELECT * FROM Win32_Service WHERE StartName = 'LocalSystem' AND State = 'Running'");
                using var searcher = new ManagementObjectSearcher(query);
                var results = searcher.Get();

                foreach (ManagementObject service in results)
                {
                    var name = service["Name"]?.ToString();
                    var displayName = service["DisplayName"]?.ToString();
                    var pathName = service["PathName"]?.ToString();

                    if (string.IsNullOrEmpty(pathName)) continue;

                    // Parse executable path
                    var exePath = ParseExecutablePath(pathName);
                    if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                        continue;

                    // Check if Users have write access
                    var aclInfo = GetAclInfo(exePath);
                    if (aclInfo.WritableByUsers)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-PRIV-WIN-001",
                            title: $"Service executable writable by non-admins: {displayName}",
                            severity: "high",
                            confidence: "high",
                            recommendation: "Restrict permissions on the service executable:\n" +
                                $"1. Right-click '{exePath}' -> Properties -> Security\n" +
                                "2. Remove write permissions for Users group\n" +
                                "3. Ensure only Administrators and SYSTEM have Full Control\n" +
                                "4. Use 'icacls' to verify: icacls \"" + exePath + "\"\n" +
                                "5. Fix with: icacls \"" + exePath + "\" /inheritance:r /grant:r \"Administrators:F\" \"SYSTEM:F\" \"Users:R\""
                        )
                        .WithDescription(
                            $"The executable for service '{displayName}' running as LocalSystem is writable by non-administrative users. " +
                            "This is a critical privilege escalation vector because:\n" +
                            "• An attacker can replace the executable with malicious code\n" +
                            "• The malicious code will run as SYSTEM (highest privilege)\n" +
                            "• Persistence is achieved through service restart/reboot\n" +
                            "• No authentication required to exploit\n\n" +
                            $"Detected permissions: {aclInfo.Details}"
                        )
                        .WithEvidence(
                            type: "path",
                            value: exePath,
                            context: $"Service: {name} ({displayName}), Runs as: LocalSystem, ACL: {aclInfo.Details}"
                        )
                        .WithReferences(
                            "https://attack.mitre.org/techniques/T1574/010/",
                            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/",
                            "https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1"
                        )
                        .WithAffectedComponent($"{Environment.MachineName} - Service: {displayName} - {exePath}"));

                        Log.Warning("{CheckName}: Service executable writable: {Service} at {Path}", 
                            Name, displayName, exePath);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking service executables", Name);
            }

            return Task.FromResult(findings);
        }

        private Task<List<Finding>> CheckServiceDirectoriesAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("{CheckName}: Checking service directory permissions...", Name);

                var query = new SelectQuery("SELECT * FROM Win32_Service WHERE StartName = 'LocalSystem' AND State = 'Running'");
                using var searcher = new ManagementObjectSearcher(query);
                var results = searcher.Get();

                var checkedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (ManagementObject service in results)
                {
                    var name = service["Name"]?.ToString();
                    var displayName = service["DisplayName"]?.ToString();
                    var pathName = service["PathName"]?.ToString();

                    if (string.IsNullOrEmpty(pathName)) continue;

                    var exePath = ParseExecutablePath(pathName);
                    if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                        continue;

                    var directory = Path.GetDirectoryName(exePath);
                    if (string.IsNullOrEmpty(directory) || checkedDirs.Contains(directory))
                        continue;

                    checkedDirs.Add(directory);

                    // Check if directory is writable
                    var aclInfo = GetAclInfo(directory);
                    if (aclInfo.WritableByUsers)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-PRIV-WIN-003",
                            title: $"Service directory writable by non-admins: {Path.GetFileName(directory)}",
                            severity: "high",
                            confidence: "high",
                            recommendation: "Restrict permissions on the service directory:\n" +
                                $"1. Right-click '{directory}' -> Properties -> Security\n" +
                                "2. Remove write permissions for Users group\n" +
                                "3. Ensure only Administrators and SYSTEM have Full Control\n" +
                                $"4. Fix with: icacls \"{directory}\" /inheritance:r /grant:r \"Administrators:F\" \"SYSTEM:F\" \"Users:RX\""
                        )
                        .WithDescription(
                            $"The directory containing service executable(s) is writable by non-administrative users. " +
                            "This allows multiple attack vectors:\n" +
                            "• DLL hijacking: Place malicious DLL in the directory\n" +
                            "• Executable replacement: Replace the service binary\n" +
                            "• Configuration tampering: Modify .config files\n\n" +
                            $"Affected services in this directory include: {displayName}\n" +
                            $"Detected permissions: {aclInfo.Details}"
                        )
                        .WithEvidence(
                            type: "path",
                            value: directory,
                            context: $"Contains service: {displayName}, ACL: {aclInfo.Details}"
                        )
                        .WithReferences(
                            "https://attack.mitre.org/techniques/T1574/001/",
                            "https://attack.mitre.org/techniques/T1574/002/"
                        )
                        .WithAffectedComponent($"{Environment.MachineName} - Directory: {directory}"));

                        Log.Warning("{CheckName}: Service directory writable: {Dir}", Name, directory);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking service directories", Name);
            }

            return Task.FromResult(findings);
        }

        private Task<List<Finding>> CheckUnquotedServicePathsAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("{CheckName}: Checking for unquoted service paths with spaces...", Name);

                var query = new SelectQuery("SELECT * FROM Win32_Service WHERE State = 'Running'");
                using var searcher = new ManagementObjectSearcher(query);
                var results = searcher.Get();

                foreach (ManagementObject service in results)
                {
                    var name = service["Name"]?.ToString();
                    var displayName = service["DisplayName"]?.ToString();
                    var pathName = service["PathName"]?.ToString();
                    var startName = service["StartName"]?.ToString();

                    if (string.IsNullOrEmpty(pathName)) continue;

                    // Check if path is unquoted and contains spaces
                    if (IsUnquotedWithSpaces(pathName))
                    {
                        // Only report if it's a privileged service
                        if (startName != null && (startName.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase) ||
                                                 startName.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase)))
                        {
                            // Calculate potential hijack paths
                            var hijackPaths = GetUnquotedPathVariants(pathName);

                            findings.Add(Finding.Create(
                                id: "AST-PRIV-WIN-002",
                                title: $"Unquoted service path with spaces: {displayName}",
                                severity: "medium",
                                confidence: "high",
                                recommendation: "Quote the service path:\n" +
                                    $"1. Open Registry Editor (regedit) as Administrator\n" +
                                    $"2. Navigate to HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}\n" +
                                    "3. Modify 'ImagePath' value to wrap the path in quotes\n" +
                                    $"4. OR use sc.exe: sc config \"{name}\" binPath= \"\\\"{pathName}\\\"\"\n" +
                                    "5. Restart the service: sc stop \"" + name + "\" && sc start \"" + name + "\""
                            )
                            .WithDescription(
                                $"Service '{displayName}' has an unquoted path containing spaces, running as {startName}. " +
                                "When Windows attempts to execute this service, it will try multiple interpretations:\n" +
                                $"{string.Join("\n", hijackPaths.Select(p => $"• {p}"))}\n\n" +
                                "If an attacker can write to any of these intermediate paths, they can hijack service execution."
                            )
                            .WithEvidence(
                                type: "path",
                                value: pathName,
                                context: $"Service: {name}, Runs as: {startName}\nPotential hijack paths: {hijackPaths.Count}"
                            )
                            .WithReferences(
                                "https://attack.mitre.org/techniques/T1574/009/",
                                "https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html"
                            )
                            .WithAffectedComponent($"{Environment.MachineName} - Service: {displayName}"));

                            Log.Warning("{CheckName}: Unquoted service path: {Service} - {Path}", 
                                Name, displayName, pathName);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking unquoted service paths", Name);
            }

            return Task.FromResult(findings);
        }

        private Task<List<Finding>> CheckServiceDllHijackingAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("{CheckName}: Checking for DLL hijacking opportunities...", Name);

                // Common DLL names that services often load
                var commonDlls = new[] { "version.dll", "dwmapi.dll", "profapi.dll", "cryptsp.dll" };

                var query = new SelectQuery("SELECT * FROM Win32_Service WHERE StartName = 'LocalSystem' AND State = 'Running'");
                using var searcher = new ManagementObjectSearcher(query);
                var results = searcher.Get();

                var checkedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (ManagementObject service in results)
                {
                    var displayName = service["DisplayName"]?.ToString();
                    var pathName = service["PathName"]?.ToString();

                    if (string.IsNullOrEmpty(pathName)) continue;

                    var exePath = ParseExecutablePath(pathName);
                    if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                        continue;

                    var directory = Path.GetDirectoryName(exePath);
                    if (string.IsNullOrEmpty(directory) || checkedDirs.Contains(directory))
                        continue;

                    checkedDirs.Add(directory);

                    // Check if directory is writable (for DLL planting)
                    var aclInfo = GetAclInfo(directory);
                    if (aclInfo.WritableByUsers)
                    {
                        // Check which common DLLs are missing (hijackable)
                        var missingDlls = new List<string>();
                        foreach (var dll in commonDlls)
                        {
                            var dllPath = Path.Combine(directory, dll);
                            if (!File.Exists(dllPath))
                            {
                                missingDlls.Add(dll);
                            }
                        }

                        if (missingDlls.Any())
                        {
                            findings.Add(Finding.Create(
                                id: "AST-PRIV-WIN-003",
                                title: $"Service DLL hijacking possible: {Path.GetFileName(directory)}",
                                severity: "high",
                                confidence: "medium",
                                recommendation: "Mitigate DLL hijacking risks:\n" +
                                    $"1. Restrict write permissions on '{directory}'\n" +
                                    "2. Remove Users group write access\n" +
                                    "3. Enable SafeDllSearchMode (usually enabled by default)\n" +
                                    "4. Consider placing legitimate DLLs in the directory to prevent hijacking\n" +
                                    $"5. Fix with: icacls \"{directory}\" /remove:g \"Users:(W,M)\""
                            )
                            .WithDescription(
                                $"The directory '{directory}' containing SYSTEM service executables is writable by users " +
                                "AND is missing commonly loaded DLLs. This enables DLL hijacking attacks:\n" +
                                "• Attacker places malicious DLL with expected name in the directory\n" +
                                "• Service loads the malicious DLL when started\n" +
                                "• Malicious code runs as SYSTEM\n\n" +
                                $"Missing common DLLs: {string.Join(", ", missingDlls)}\n" +
                                $"Services in this directory: {displayName}"
                            )
                            .WithEvidence(
                                type: "path",
                                value: directory,
                                context: $"Missing DLLs: {string.Join(", ", missingDlls)}, ACL: {aclInfo.Details}"
                            )
                            .WithReferences(
                                "https://attack.mitre.org/techniques/T1574/001/",
                                "https://attack.mitre.org/techniques/T1574/002/",
                                "https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows"
                            )
                            .WithAffectedComponent($"{Environment.MachineName} - {directory}"));

                            Log.Warning("{CheckName}: DLL hijacking possible in: {Dir}", Name, directory);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking DLL hijacking", Name);
            }

            return Task.FromResult(findings);
        }

        #endregion

        #region Scheduled Tasks Check

        private async Task<List<Finding>> CheckScheduledTasksAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("{CheckName}: Checking scheduled tasks for writable executables...", Name);

                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = "/query /fo CSV /v",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) return findings;

                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                if (process.ExitCode != 0) return findings;

                // Parse CSV output
                var lines = output.Split('\n');
                foreach (var line in lines.Skip(1))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    var fields = ParseCsvLine(line);
                    if (fields.Length < 8) continue;

                    var taskName = fields[0].Trim('\"');
                    var taskToRun = fields[7].Trim('\"');
                    var author = fields.Length > 6 ? fields[6].Trim('\"') : "Unknown";

                    // Skip system tasks and COM handlers
                    if (string.IsNullOrEmpty(taskToRun) || 
                        taskToRun.Contains("COM handler") ||
                        taskToRun.StartsWith("%"))
                        continue;

                    var exePath = ParseExecutablePath(taskToRun);
                    if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                        continue;

                    // Check if writable by users
                    var aclInfo = GetAclInfo(exePath);
                    if (aclInfo.WritableByUsers)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-PRIV-WIN-004",
                            title: $"Scheduled task with writable executable: {taskName}",
                            severity: "high",
                            confidence: "high",
                            recommendation: "Restrict permissions on the task executable:\n" +
                                $"1. Right-click '{exePath}' -> Properties -> Security\n" +
                                "2. Remove write permissions for Users group\n" +
                                "3. Ensure only Administrators and SYSTEM have Full Control\n" +
                                "4. Review task scheduling permissions:\n" +
                                $"   schtasks /query /tn \"{taskName}\" /xml\n" +
                                $"5. Fix ACL: icacls \"{exePath}\" /inheritance:r /grant:r \"Administrators:F\" \"SYSTEM:F\" \"Users:R\""
                        )
                        .WithDescription(
                            $"Scheduled task '{taskName}' runs an executable that is writable by non-administrative users. " +
                            "This allows privilege escalation if the task runs with elevated privileges:\n" +
                            "• Attacker replaces the executable with malicious code\n" +
                            "• Task executes malicious code at scheduled time\n" +
                            "• Code runs with task's configured privileges\n\n" +
                            $"Task author: {author}\n" +
                            $"Detected permissions: {aclInfo.Details}"
                        )
                        .WithEvidence(
                            type: "path",
                            value: exePath,
                            context: $"Task: {taskName}, Author: {author}, ACL: {aclInfo.Details}"
                        )
                        .WithReferences(
                            "https://attack.mitre.org/techniques/T1053/005/",
                            "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events"
                        )
                        .WithAffectedComponent($"{Environment.MachineName} - Task: {taskName} - {exePath}"));

                        Log.Warning("{CheckName}: Scheduled task with writable executable: {Task}", Name, taskName);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking scheduled tasks", Name);
            }

            return findings;
        }

        #endregion

        #region Registry Checks

        private Task<List<Finding>> CheckAlwaysInstallElevatedAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("{CheckName}: Checking AlwaysInstallElevated registry keys...", Name);

                bool hklmSet = false;
                bool hkcuSet = false;

                // Check HKLM
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Installer"))
                {
                    if (key != null)
                    {
                        var value = key.GetValue("AlwaysInstallElevated");
                        if (value != null && Convert.ToInt32(value) == 1)
                        {
                            hklmSet = true;
                        }
                    }
                }

                // Check HKCU
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Installer"))
                {
                    if (key != null)
                    {
                        var value = key.GetValue("AlwaysInstallElevated");
                        if (value != null && Convert.ToInt32(value) == 1)
                        {
                            hkcuSet = true;
                        }
                    }
                }

                // Both must be set for the vulnerability
                if (hklmSet && hkcuSet)
                {
                    findings.Add(Finding.Create(
                        id: "AST-PRIV-WIN-005",
                        title: "AlwaysInstallElevated registry keys enabled",
                        severity: "critical",
                        confidence: "high",
                        recommendation: "CRITICAL - Disable AlwaysInstallElevated immediately:\n" +
                            "1. Open Group Policy Editor (gpedit.msc) as Administrator\n" +
                            "2. Navigate to: Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer\n" +
                            "3. Set 'Always install with elevated privileges' to Disabled\n" +
                            "4. Also check User Configuration -> same path -> Set to Disabled\n" +
                            "5. OR delete registry keys manually:\n" +
                            "   reg delete \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v AlwaysInstallElevated /f\n" +
                            "   reg delete \"HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v AlwaysInstallElevated /f\n" +
                            "6. Run 'gpupdate /force' to apply changes"
                    )
                    .WithDescription(
                        "CRITICAL VULNERABILITY: The 'AlwaysInstallElevated' registry keys are enabled in both HKLM and HKCU. " +
                        "This configuration allows ANY user to install MSI packages with SYSTEM privileges, enabling trivial privilege escalation:\n" +
                        "• Any user can create a malicious MSI package\n" +
                        "• The MSI installs with SYSTEM privileges\n" +
                        "• Attacker gains full system control\n" +
                        "• No authentication or exploitation required\n\n" +
                        "This is one of the easiest privilege escalation vectors and is actively exploited in the wild. " +
                        "Attack tools like Metasploit have built-in modules to exploit this."
                    )
                    .WithEvidence(
                        type: "config",
                        value: "AlwaysInstallElevated=1 in both HKLM and HKCU",
                        context: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated = 1\n" +
                                 "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated = 1"
                    )
                    .WithReferences(
                        "https://attack.mitre.org/techniques/T1548/002/",
                        "https://pentestlab.blog/2017/02/28/always-install-elevated/",
                        "https://docs.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated",
                        "https://www.rapid7.com/db/modules/exploit/windows/local/always_install_elevated/"
                    )
                    .WithAffectedComponent($"{Environment.MachineName} - System Configuration"));

                    Log.Error("{CheckName}: CRITICAL - AlwaysInstallElevated enabled!", Name);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking AlwaysInstallElevated keys", Name);
            }

            return Task.FromResult(findings);
        }

        private Task<List<Finding>> CheckAutoRunKeysAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("{CheckName}: Checking AutoRun registry keys...", Name);

                var autoRunKeys = new[]
                {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
                };

                var writableTargets = new List<(string keyPath, string valueName, string target, string aclDetails)>();

                foreach (var keyPath in autoRunKeys)
                {
                    try
                    {
                        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath);
                        if (key == null) continue;

                        foreach (var valueName in key.GetValueNames())
                        {
                            var value = key.GetValue(valueName)?.ToString();
                            if (string.IsNullOrEmpty(value)) continue;

                            var exePath = ParseExecutablePath(value);
                            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                                continue;

                            var aclInfo = GetAclInfo(exePath);
                            if (aclInfo.WritableByUsers)
                            {
                                writableTargets.Add((keyPath, valueName, exePath, aclInfo.Details));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Debug(ex, "{CheckName}: Error checking AutoRun key {Key}", Name, keyPath);
                    }
                }

                if (writableTargets.Any())
                {
                    var targetList = string.Join("\n", writableTargets.Select(t => $"• {t.valueName}: {t.target}"));

                    findings.Add(Finding.Create(
                        id: "AST-PRIV-WIN-008",
                        title: "Writable AutoRun registry targets detected",
                        severity: "high",
                        confidence: "high",
                        recommendation: "Secure AutoRun executables:\n" +
                            "1. Review each writable AutoRun target\n" +
                            "2. Remove write permissions for Users group:\n" +
                            "   icacls \"<path>\" /remove:g \"Users:(W,M)\"\n" +
                            "3. Ensure only Administrators can modify AutoRun entries\n" +
                            "4. Consider removing unnecessary AutoRun entries\n" +
                            "5. Use Process Monitor to identify what loads at startup"
                    )
                    .WithDescription(
                        $"Found {writableTargets.Count} AutoRun registry entries pointing to executables writable by non-administrative users. " +
                        "AutoRun keys execute programs automatically at user login or system startup. If these executables are writable:\n" +
                        "• Attacker replaces executable with malicious code\n" +
                        "• Malicious code runs automatically at next login/startup\n" +
                        "• Persistence is achieved\n" +
                        "• Privilege escalation if AutoRun runs as SYSTEM\n\n" +
                        "Writable AutoRun targets:\n" + targetList
                    )
                    .WithEvidence(
                        type: "config",
                        value: $"{writableTargets.Count} writable AutoRun targets",
                        context: targetList
                    )
                    .WithReferences(
                        "https://attack.mitre.org/techniques/T1547/001/",
                        "https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys"
                    )
                    .WithAffectedComponent($"{Environment.MachineName} - AutoRun Registry"));

                    Log.Warning("{CheckName}: Found {Count} writable AutoRun targets", Name, writableTargets.Count);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking AutoRun keys", Name);
            }

            return Task.FromResult(findings);
        }

        #endregion

        #region Directory ACL Checks

        private Task<List<Finding>> CheckWeakDirectoryAclsAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("{CheckName}: Checking ACLs on system directories...", Name);

                var criticalDirs = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "config")
                };

                foreach (var dir in criticalDirs)
                {
                    if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;

                    try
                    {
                        var aclInfo = GetAclInfo(dir);
                        if (aclInfo.WritableByUsers)
                        {
                            findings.Add(Finding.Create(
                                id: "AST-PRIV-WIN-006",
                                title: $"Weak ACLs on system directory: {Path.GetFileName(dir)}",
                                severity: "high",
                                confidence: "high",
                                recommendation: "Restrict permissions on system directories:\n" +
                                    $"1. Right-click '{dir}' -> Properties -> Security\n" +
                                    "2. Remove write permissions for Users group\n" +
                                    "3. Ensure inheritance is properly configured\n" +
                                    $"4. Fix with: icacls \"{dir}\" /inheritance:r /grant:r \"Administrators:F\" \"SYSTEM:F\" \"Users:RX\"\n" +
                                    "5. Verify subfolders: icacls \"" + dir + "\" /T /C"
                            )
                            .WithDescription(
                                $"The system directory '{dir}' is writable by non-administrative users. " +
                                "This critical misconfiguration enables multiple privilege escalation techniques:\n" +
                                "• DLL hijacking: Place malicious DLLs in system directories\n" +
                                "• Executable replacement: Replace system binaries\n" +
                                "• Configuration tampering: Modify system config files\n\n" +
                                $"Detected permissions: {aclInfo.Details}"
                            )
                            .WithEvidence(
                                type: "path",
                                value: dir,
                                context: $"ACL: {aclInfo.Details}"
                            )
                            .WithReferences(
                                "https://attack.mitre.org/techniques/T1574/",
                                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment"
                            )
                            .WithAffectedComponent($"{Environment.MachineName} - {dir}"));

                            Log.Warning("{CheckName}: Weak ACL on system directory: {Dir}", Name, dir);
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        // Expected for some protected directories
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking directory ACLs", Name);
            }

            return Task.FromResult(findings);
        }

        private Task<List<Finding>> CheckPathDirectoriesAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("{CheckName}: Checking PATH directories for write access...", Name);

                var pathVar = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine);
                if (string.IsNullOrEmpty(pathVar)) return Task.FromResult(findings);

                var pathDirs = pathVar.Split(';')
                    .Where(p => !string.IsNullOrWhiteSpace(p))
                    .Select(p => p.Trim())
                    .Distinct()
                    .ToList();

                var writablePaths = new List<(string path, string aclDetails)>();

                foreach (var dir in pathDirs)
                {
                    if (!Directory.Exists(dir)) continue;

                    try
                    {
                        var aclInfo = GetAclInfo(dir);
                        if (aclInfo.WritableByUsers)
                        {
                            writablePaths.Add((dir, aclInfo.Details));
                        }
                    }
                    catch { }
                }

                if (writablePaths.Any())
                {
                    var pathList = string.Join("\n", writablePaths.Select(p => $"• {p.path}"));

                    findings.Add(Finding.Create(
                        id: "AST-PRIV-WIN-007",
                        title: "Writable directories in system PATH",
                        severity: "medium",
                        confidence: "high",
                        recommendation: "Remove write permissions from PATH directories:\n" +
                            "1. Review each writable directory in the list\n" +
                            "2. Remove write permissions for Users group:\n" +
                            "   icacls \"<directory>\" /remove:g \"Users:(W)\"\n" +
                            "3. Consider removing unnecessary directories from system PATH\n" +
                            "4. User-specific paths should be in User PATH, not System PATH\n" +
                            "5. Verify with: echo %PATH%"
                    )
                    .WithDescription(
                        $"Found {writablePaths.Count} directories in the system PATH that are writable by non-administrative users. " +
                        "This enables PATH hijacking attacks:\n" +
                        "• Attacker places malicious executable with common name (e.g., 'whoami.exe')\n" +
                        "• When system or user runs the command, attacker's version executes\n" +
                        "• If writable PATH directory is early in search order, hijacking is trivial\n\n" +
                        "Writable PATH directories:\n" + pathList
                    )
                    .WithEvidence(
                        type: "config",
                        value: $"{writablePaths.Count} writable PATH directories",
                        context: pathList
                    )
                    .WithReferences(
                        "https://attack.mitre.org/techniques/T1574/007/"
                    )
                    .WithAffectedComponent($"{Environment.MachineName} - System PATH"));

                    Log.Warning("{CheckName}: Found {Count} writable PATH directories", Name, writablePaths.Count);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking PATH directories", Name);
            }

            return Task.FromResult(findings);
        }

        private Task<List<Finding>> CheckStartupFoldersAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("{CheckName}: Checking Startup folder permissions...", Name);

                var startupFolders = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                    Environment.GetFolderPath(Environment.SpecialFolder.Startup)
                };

                foreach (var folder in startupFolders)
                {
                    if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;

                    var aclInfo = GetAclInfo(folder);
                    if (aclInfo.WritableByUsers)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-PRIV-WIN-009",
                            title: $"Writable Startup folder: {Path.GetFileName(folder)}",
                            severity: "medium",
                            confidence: "high",
                            recommendation: "Restrict Startup folder permissions:\n" +
                                $"1. Right-click '{folder}' -> Properties -> Security\n" +
                                "2. Remove write permissions for Users group\n" +
                                $"3. Fix with: icacls \"{folder}\" /remove:g \"Users:(W,M)\"\n" +
                                "4. Regularly audit Startup folder contents"
                        )
                        .WithDescription(
                            $"The Startup folder '{folder}' is writable by non-administrative users. " +
                            "Programs in Startup folders execute automatically when users log in. If writable:\n" +
                            "• Attacker places malicious executable or shortcut\n" +
                            "• Malicious program runs automatically at next login\n" +
                            "• Persistence is achieved\n\n" +
                            $"Detected permissions: {aclInfo.Details}"
                        )
                        .WithEvidence(
                            type: "path",
                            value: folder,
                            context: $"ACL: {aclInfo.Details}"
                        )
                        .WithReferences(
                            "https://attack.mitre.org/techniques/T1547/001/"
                        )
                        .WithAffectedComponent($"{Environment.MachineName} - {folder}"));

                        Log.Warning("{CheckName}: Writable Startup folder: {Folder}", Name, folder);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking Startup folders", Name);
            }

            return Task.FromResult(findings);
        }

        #endregion

        #region Token Privilege Checks

        private Task<List<Finding>> CheckTokenPrivilegesAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("{CheckName}: Checking token privileges...", Name);

                // Check if current user has SeImpersonatePrivilege
                // This is used in Potato attacks (JuicyPotato, RoguePotato, etc.)
                if (HasPrivilege("SeImpersonatePrivilege"))
                {
                    findings.Add(Finding.Create(
                        id: "AST-PRIV-WIN-010",
                        title: "SeImpersonatePrivilege enabled (Potato attack risk)",
                        severity: "high",
                        confidence: "high",
                        recommendation: "Mitigate SeImpersonatePrivilege risks:\n" +
                            "1. Review which service accounts have this privilege\n" +
                            "2. Remove privilege if not needed: secpol.msc -> Local Policies -> User Rights Assignment\n" +
                            "3. Apply Windows patches to mitigate known Potato exploits\n" +
                            "4. Use least-privilege service accounts\n" +
                            "5. Monitor for suspicious DCOM/RPC activity"
                    )
                    .WithDescription(
                        "The current user or service account has SeImpersonatePrivilege enabled. " +
                        "This privilege allows impersonation of other users' security contexts and is exploitable via Potato attacks:\n" +
                        "• JuicyPotato: Exploits DCOM to get SYSTEM shell\n" +
                        "• RoguePotato: Similar technique using different RPC endpoints\n" +
                        "• PrintSpoofer: Exploits Print Spooler service\n\n" +
                        "Common on IIS application pools and SQL Server service accounts. " +
                        "If an attacker compromises this account, they can escalate to SYSTEM."
                    )
                    .WithEvidence(
                        type: "config",
                        value: "SeImpersonatePrivilege enabled",
                        context: $"User: {WindowsIdentity.GetCurrent().Name}"
                    )
                    .WithReferences(
                        "https://attack.mitre.org/techniques/T1134/001/",
                        "https://github.com/ohpe/juicy-potato",
                        "https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/"
                    )
                    .WithAffectedComponent($"{Environment.MachineName} - User: {WindowsIdentity.GetCurrent().Name}"));

                    Log.Warning("{CheckName}: SeImpersonatePrivilege enabled for current user", Name);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking token privileges", Name);
            }

            return Task.FromResult(findings);
        }

        #endregion

        #region Helper Methods

        private string ParseExecutablePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return string.Empty;

            // Remove quotes
            path = path.Trim().Trim('"');

            // Find first space that's not part of the path
            if (path.Contains(".exe ", StringComparison.OrdinalIgnoreCase))
            {
                var index = path.IndexOf(".exe ", StringComparison.OrdinalIgnoreCase);
                if (index > 0)
                {
                    path = path.Substring(0, index + 4);
                }
            }

            // Expand environment variables
            path = Environment.ExpandEnvironmentVariables(path);

            return path;
        }

        private bool IsUnquotedWithSpaces(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            if (path.TrimStart().StartsWith("\"")) return false;
            if (!path.Contains(" ")) return false;

            var exePath = ParseExecutablePath(path);
            return exePath.Contains(" ");
        }

        private List<string> GetUnquotedPathVariants(string path)
        {
            var variants = new List<string>();
            var parts = path.Split(' ');

            for (int i = 1; i < parts.Length; i++)
            {
                var variant = string.Join(" ", parts.Take(i)) + ".exe";
                variants.Add(variant);
            }

            return variants;
        }

        private (bool WritableByUsers, string Details) GetAclInfo(string path)
        {
            try
            {
                AuthorizationRuleCollection rules;
                
                if (File.Exists(path))
                {
                    var fileInfo = new FileInfo(path);
                    var security = fileInfo.GetAccessControl();
                    rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
                }
                else if (Directory.Exists(path))
                {
                    var dirInfo = new DirectoryInfo(path);
                    var security = dirInfo.GetAccessControl();
                    rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
                }
                else
                {
                    return (false, "Path not found");
                }

                var usersGroup = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
                var authenticatedUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
                var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

                var detailsBuilder = new StringBuilder();
                bool isWritable = false;

                foreach (FileSystemAccessRule rule in rules)
                {
                    if (rule.IdentityReference.Equals(usersGroup) || 
                        rule.IdentityReference.Equals(authenticatedUsers) ||
                        rule.IdentityReference.Equals(everyone))
                    {
                        var rights = rule.FileSystemRights;
                        var hasWrite = (rights & (FileSystemRights.Write | FileSystemRights.Modify | FileSystemRights.FullControl)) != 0;

                        if (hasWrite && rule.AccessControlType == AccessControlType.Allow)
                        {
                            isWritable = true;
                            var identity = rule.IdentityReference.Translate(typeof(NTAccount)).Value;
                            detailsBuilder.AppendLine($"{identity}: {rights} ({rule.AccessControlType})");
                        }
                    }
                }

                return (isWritable, detailsBuilder.ToString().TrimEnd());
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "{CheckName}: Error getting ACL info for {Path}", Name, path);
                return (false, $"Error: {ex.Message}");
            }
        }

        private bool IsAdministrator()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private bool HasPrivilege(string privilegeName)
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var tokenPrivileges = new byte[1024];
                
                // This is a simplified check - a full implementation would use P/Invoke ---> I will update this one in the future
                // For now, check if user is in specific groups that typically have this privilege
                var principal = new WindowsPrincipal(identity);
                
                // SeImpersonatePrivilege is typically granted to:
                // - Administrators
                // - Service accounts
                // - IIS_IUSRS
                // - SQL Server service accounts
                
                return principal.IsInRole(WindowsBuiltInRole.Administrator) ||
                       identity.Name.Contains("IIS") ||
                       identity.Name.Contains("SQL");
            }
            catch
            {
                return false;
            }
        }

        private string[] ParseCsvLine(string line)
        {
            var result = new List<string>();
            var current = new StringBuilder();
            bool inQuotes = false;

            foreach (char c in line)
            {
                if (c == '"')
                {
                    inQuotes = !inQuotes;
                }
                else if (c == ',' && !inQuotes)
                {
                    result.Add(current.ToString());
                    current.Clear();
                }
                else
                {
                    current.Append(c);
                }
            }

            result.Add(current.ToString());
            return result.ToArray();
        }

        #endregion
    }
}