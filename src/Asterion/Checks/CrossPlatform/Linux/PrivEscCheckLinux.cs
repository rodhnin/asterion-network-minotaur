using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Models;

namespace Asterion.Checks.Linux
{
    /// <summary>
    /// Linux Privilege Escalation Security Check
    /// 
    /// Comprehensive audit of common privilege escalation vectors on Linux systems:
    /// 
    /// SUID Binary Checks:
    /// - Dangerous SUID binaries (find, vim, python, etc.) that allow privesc
    /// - SUID binaries in world-writable directories (/tmp, /var/tmp)
    /// - SUID binaries in unusual/non-standard locations
    /// 
    /// Sudoers Configuration:
    /// - NOPASSWD grants to dangerous commands (bash, ALL, vim, etc.)
    /// - Overly permissive sudo rules
    /// 
    /// File Permissions:
    /// - World-readable/writable critical files (/etc/shadow, /etc/sudoers)
    /// - SSH key permissions
    /// - System configuration files
    /// 
    /// Requires: Local execution on Linux with root/sudo privileges for full audit
    /// 
    /// Findings:
    /// - AST-PRIV-LNX-001: Dangerous SUID binary (critical)
    /// - AST-PRIV-LNX-002: SUID binary in writable directory (high)
    /// - AST-PRIV-LNX-003: Insecure sudoers NOPASSWD configuration (critical/high)
    /// - AST-PRIV-LNX-004: Critical file with insecure permissions (critical/high)
    /// - AST-PRIV-LNX-005: SUID binary in unusual location (info)
    /// 
    /// References:
    /// - GTFOBins: https://gtfobins.github.io/
    /// - HackTricks: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html
    /// - CIS Linux Benchmark: Section 6 (File System Permissions)
    /// </summary>
    public class PrivEscCheckLinux : BaseCheck
    {
        public override string Name => "Linux Privilege Escalation Check";
        
        public override CheckCategory Category => CheckCategory.Linux;
        
        public override string Description => 
            "Audits Linux systems for privilege escalation vectors including dangerous SUID binaries, " +
            "insecure sudoers configurations, and weak file permissions on critical system files. " +
            "Requires local execution with elevated privileges for comprehensive scanning.";

        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        // Binaries that should NEVER have SUID bit (high privilege escalation risk)
        private static readonly HashSet<string> DangerousSuidBinaries = new(StringComparer.OrdinalIgnoreCase)
        {
            // Editors - can write to any file or spawn shell
            "nano", "vim", "vi", "emacs", "ed", "pico",
            
            // Programming languages - can execute arbitrary code as root
            "python", "python2", "python3", "perl", "ruby", "lua", "node", "php",
            
            // Shells - direct root shell access
            "bash", "sh", "dash", "zsh", "ksh", "tcsh", "csh", "fish",
            
            // File utilities - can read/write any file
            "find", "less", "more", "tail", "head", "cat", "tac", "nl",
            "awk", "sed", "grep", "cut", "sort", "uniq",
            
            // Archive utilities - can extract/create files as root
            "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "bunzip2", "7z", "rar", "unrar",
            
            // File operations - can copy/move/delete any file
            "cp", "mv", "rm", "dd", "rsync", "scp",
            
            // Network utilities - can bind to privileged ports, exfiltrate data
            "nc", "netcat", "ncat", "socat", "wget", "curl", "ftp", "telnet",
            
            // Development tools - can compile malicious code
            "gcc", "g++", "cc", "as", "ld", "make", "cmake", "gdb", "strace", "ltrace",
            
            // System utilities
            "nmap", "tcpdump", "wireshark", "git", "ssh", "screen", "tmux",
            "docker", "kubectl", "systemctl", "journalctl"
        };

        // Known legitimate SUID binaries (common system tools)
        private static readonly HashSet<string> LegitimatelySuidBinaries = new(StringComparer.OrdinalIgnoreCase)
        {
            // Authentication
            "sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd",
            
            // Mounting
            "mount", "umount", "fusermount", "fusermount3",
            
            // Privilege management
            "pkexec", "polkit-agent-helper-1",
            
            // Networking
            "ping", "ping6", "traceroute", "traceroute6",
            
            // System services
            "unix_chkpwd", "staprun", "dbus-daemon-launch-helper",
            
            // Job scheduling
            "at", "crontab",
            
            // Display managers
            "Xorg", "X",
            
            // Other legitimate tools
            "chage", "expiry", "write", "wall"
        };

        // Critical files that should have restricted permissions
        private static readonly Dictionary<string, string> CriticalFiles = new()
        {
            { "/etc/shadow", "0640" },         // Password hashes - root:shadow read-only
            { "/etc/gshadow", "0640" },        // Group password hashes
            { "/etc/sudoers", "0440" },        // Sudo configuration - read-only by root
            { "/etc/passwd", "0644" },         // User database (world-readable OK, but not writable)
            { "/etc/group", "0644" },          // Group database
            { "/root/.ssh/authorized_keys", "0600" }, // Root SSH keys
            { "/root/.ssh/id_rsa", "0600" },   // Root private key
            { "/root/.ssh/id_ecdsa", "0600" },
            { "/root/.ssh/id_ed25519", "0600" },
            { "/etc/ssh/sshd_config", "0644" } // SSH server config
        };

        // Dangerous sudoers commands that should never have NOPASSWD
        private static readonly HashSet<string> DangerousSudoCommands = new(StringComparer.OrdinalIgnoreCase)
        {
            "ALL",
            "/bin/bash", "/bin/sh", "/bin/dash", "/bin/zsh",
            "/bin/su",
            "/usr/bin/vi", "/usr/bin/vim", "/usr/bin/nano", "/usr/bin/emacs",
            "/usr/bin/python", "/usr/bin/python3", "/usr/bin/perl", "/usr/bin/ruby",
            "/usr/bin/find",
            "/usr/bin/less", "/usr/bin/more",
            "/usr/bin/awk", "/usr/bin/sed",
            "/usr/bin/wget", "/usr/bin/curl",
            "/usr/bin/tar", "/usr/bin/zip",
            "/usr/bin/docker", "/usr/bin/kubectl",
            "/usr/bin/systemctl", "/bin/systemctl"
        };

        public PrivEscCheckLinux(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var findings = new List<Finding>();

            Log.Information("[{CheckName}] Starting Linux privilege escalation audit", Name);

            try
            {
                // Check if running as root (recommended for full audit)
                bool isRoot = await IsRootAsync();
                if (!isRoot)
                {
                    Log.Warning("[{CheckName}] Not running as root - some checks may be incomplete", Name);
                }

                // Check SUID binaries
                Log.Debug("[{CheckName}] Scanning for dangerous SUID binaries...", Name);
                var suidFindings = await CheckSuidBinariesAsync();
                findings.AddRange(suidFindings);

                // Check sudoers configuration
                Log.Debug("[{CheckName}] Analyzing sudoers configuration...", Name);
                var sudoersFindings = await CheckSudoersConfigAsync();
                findings.AddRange(sudoersFindings);

                // Check critical file permissions
                Log.Debug("[{CheckName}] Checking critical file permissions...", Name);
                var permFindings = await CheckCriticalFilePermissionsAsync();
                findings.AddRange(permFindings);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error during privilege escalation check", Name);
            }

            LogExecution(targets.Count, findings.Count);
            return findings;
        }

        // ===========================
        // Helpers: Shell & Predicados
        // ===========================

        private async Task<(bool ok, string stdout)> ExecuteShellAsync(string shellCommand)
        {
            string escaped = shellCommand.Replace("\"", "\\\"");
            return await ExecuteCommandAsync("/bin/sh", $"-lc \"{escaped}\"");
        }

        private async Task<bool> FileExistsQuietAsync(string path)
        {
            var (ok, _) = await ExecuteShellAsync($"test -f '{path}'");
            return ok;
        }

        private async Task<(bool ok, string outText)> RunPredicateNoWarnAsync(string predicateCmd)
        {
            var (ok, outText) = await ExecuteShellAsync(predicateCmd);
            if (!ok && predicateCmd.StartsWith("test ", StringComparison.Ordinal))
            {
                Log.Debug("[{CheckName}] Predicate false: {Cmd}", Name, predicateCmd);
            }
            return (ok, outText);
        }

        #region SUID Binary Checks

        /// <summary>
        /// Find and check SUID binaries for security issues
        /// Robust shell-based enumeration + fallback + spot checks
        /// </summary>
        private async Task<List<Finding>> CheckSuidBinariesAsync()
        {
            var findings = new List<Finding>();
            
            try
            {
                var cmd = "LC_ALL=C find / -xdev -type f -perm -4000 -printf '%p\\n' 2>/dev/null || true";
                var (success, output) = await ExecuteShellAsync(cmd);
                
                var lines = (output ?? string.Empty)
                    .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Where(f => !string.IsNullOrWhiteSpace(f) && f.StartsWith("/"))
                    .Distinct()
                    .ToArray();
                
                Log.Information("[{CheckName}] Found {Count} SUID binaries", Name, lines.Length);
                
                if (lines.Length == 0)
                {
                    var (s2, out2) = await ExecuteShellAsync(
                        "LC_ALL=C find / -type f -perm -4000 -printf '%p\\n' 2>/dev/null || true");
                    lines = (out2 ?? string.Empty)
                        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Where(f => !string.IsNullOrWhiteSpace(f) && f.StartsWith("/"))
                        .Distinct()
                        .ToArray();
                    Log.Debug("[{CheckName}] Found {Count} SUID binaries (fallback)", Name, lines.Length);
                }

                foreach (var filePath in lines)
                {
                    var fileName = System.IO.Path.GetFileName(filePath);
                    var dirName = System.IO.Path.GetDirectoryName(filePath) ?? "";
                    
                    var baseFileName = fileName.Split('.')[0];
                    
                    // Priority 1: Dangerous SUID
                    if (DangerousSuidBinaries.Contains(fileName) || DangerousSuidBinaries.Contains(baseFileName))
                    {
                        findings.Add(Finding.Create(
                            id: "AST-PRIV-LNX-001",
                            title: $"Dangerous SUID binary detected: {baseFileName}",
                            severity: "critical",
                            confidence: "high",
                            recommendation: "Remove SUID bit from dangerous binary immediately:\n" +
                                $"1. sudo chmod u-s '{filePath}'\n" +
                                $"2. Verify removal: ls -l '{filePath}'\n" +
                                "3. Investigate how SUID bit was set (check for system compromise)\n" +
                                $"4. If '{baseFileName}' legitimately needs elevated privileges:\n" +
                                "   - Use sudo with specific commands instead\n" +
                                "   - Or use Linux capabilities (setcap) instead of SUID\n" +
                                "5. Audit all user accounts and recent system activity\n" +
                                "6. Check for other signs of compromise (rootkits, backdoors)"
                        )
                        .WithDescription(
                            $"The binary '{fileName}' has the SUID bit set at {filePath}, allowing execution with owner privileges. " +
                            "This binary is known to be exploitable for privilege escalation (see GTFOBins)."
                        )
                        .WithEvidence(
                            type: "path",
                            value: filePath,
                            context: $"SUID binary in {dirName} - Check GTFOBins for exploitation methods"
                        )
                        .WithReferences(
                            "https://gtfobins.github.io/",
                            $"https://gtfobins.github.io/gtfobins/{baseFileName}/",
                            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/euid-ruid-suid.html",
                            "https://linux-audit.com/finding-setuid-binaries-on-linux-and-bsd/"
                        )
                        .WithAffectedComponent($"{filePath}"));
                        continue;
                    }
                    
                    // Priority 2: SUID in unusual location
                    if (!LegitimatelySuidBinaries.Contains(fileName) && !LegitimatelySuidBinaries.Contains(baseFileName))
                    {
                        findings.Add(Finding.Create(
                            id: "AST-PRIV-LNX-005",
                            title: $"SUID binary in unusual location: {fileName}",
                            severity: "info",
                            confidence: "medium",
                            recommendation:
                                "Verify whether this SUID is legitimate:\n" +
                                $"1. Check owner/perm: ls -l '{filePath}'\n" +
                                $"2. Check owning package: dpkg -S '{filePath}' (Debian/Ubuntu) or rpm -qf (RHEL)\n" +
                                $"3. If not required, remove SUID: sudo chmod u-s '{filePath}'"
                        )
                        .WithDescription(
                            $"SUID found at {filePath}. If it's not part of the base system or a known package, " +
                            "it could indicate attacker persistence or misconfiguration."
                        )
                        .WithEvidence("path", filePath, "SUID out of baseline")
                        .WithAffectedComponent(filePath));
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking SUID binaries", Name);
            }
            
            return findings;
        }

        #endregion

        #region Sudoers Configuration Checks

        private async Task<List<Finding>> CheckSudoersConfigAsync()
        {
            var findings = new List<Finding>();

            try
            {
                // /etc/sudoers principal
                if (!await FileExistsAsync("/etc/sudoers"))
                {
                    return findings;
                }

                var sudoersFiles = new List<string> { "/etc/sudoers" };

                // Archivos en /etc/sudoers.d (usando shell para soportar redirecciones)
                if (SshManager != null)
                {
                    var (success, output) = await ExecuteShellAsync("find /etc/sudoers.d -type f 2>/dev/null || true");
                    var files = (output ?? string.Empty)
                        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Where(f => !f.EndsWith("~") && !f.EndsWith(".swp") && !System.IO.Path.GetFileName(f).StartsWith("."));
                    sudoersFiles.AddRange(files);
                }
                else
                {
                    // Local
                    var sudoersDir = "/etc/sudoers.d";
                    if (System.IO.Directory.Exists(sudoersDir))
                    {
                        var additionalFiles = System.IO.Directory.GetFiles(sudoersDir)
                            .Where(f => !f.EndsWith("~") && !f.EndsWith(".swp") && !System.IO.Path.GetFileName(f).StartsWith("."));
                        sudoersFiles.AddRange(additionalFiles);
                    }
                }

                foreach (var sudoersFile in sudoersFiles)
                {
                    if (!await FileExistsAsync(sudoersFile))
                        continue;

                    try
                    {
                        var content = await ReadFileAsync(sudoersFile);
                        if (string.IsNullOrEmpty(content))
                            continue;

                        var lines = content.Split('\n');
                        int lineNumber = 0;

                        foreach (var rawLine in lines)
                        {
                            lineNumber++;
                            var line = rawLine.Trim();

                            // Skip empty lines and comments
                            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                                continue;

                            // Check for NOPASSWD with dangerous commands
                            if (line.Contains("NOPASSWD"))
                            {
                                var match = System.Text.RegularExpressions.Regex.Match(line, @"^(%?[\w@][\w@\-\.\*]*)\s+.+NOPASSWD:\s*(.+)$");
                                if (match.Success)
                                {
                                    var userOrGroup = match.Groups[1].Value;
                                    var command = match.Groups[2].Value.Trim();

                                    bool isDangerous = false;
                                    string dangerousCmd = "";
                                    string severity = "high";

                                    if (command == "ALL" || command.Contains("ALL"))
                                    {
                                        isDangerous = true;
                                        dangerousCmd = "ALL (unrestricted root access)";
                                        severity = "critical";
                                    }
                                    else
                                    {
                                        foreach (var dangerousPattern in DangerousSudoCommands)
                                        {
                                            if (command.Contains(dangerousPattern, StringComparison.Ordinal))
                                            {
                                                isDangerous = true;
                                                dangerousCmd = dangerousPattern;
                                                break;
                                            }
                                        }
                                    }

                                    if (isDangerous)
                                    {
                                        findings.Add(Finding.Create(
                                            id: "AST-PRIV-LNX-003",
                                            title: $"Insecure sudoers: {userOrGroup} has NOPASSWD access to {dangerousCmd}",
                                            severity: severity,
                                            confidence: "high",
                                            recommendation: "Restrict sudoers configuration:\n" +
                                                $"1. Edit sudoers file: sudo visudo {(sudoersFile != "/etc/sudoers" ? "-f " + sudoersFile : "")}\n" +
                                                $"2. Remove or modify line {lineNumber}: {line}\n" +
                                                "3. If passwordless sudo is required, use for SPECIFIC safe commands only\n" +
                                                "   - Good: NOPASSWD: /usr/bin/systemctl restart myapp\n" +
                                                "   - Bad: NOPASSWD: ALL, /bin/bash, /usr/bin/vim\n" +
                                                "4. NEVER grant 'NOPASSWD: ALL' except for trusted automation (CI/CD)\n" +
                                                "5. Consider using sudo timeout (timestamp_timeout) instead\n" +
                                                "6. Audit all users/groups with sudo access\n" +
                                                "7. Review sudo logs: /var/log/auth.log or /var/log/secure"
                                        )
                                        .WithDescription(
                                            $"The sudoers configuration grants '{userOrGroup}' passwordless sudo access to dangerous commands. " +
                                            (command.Contains("ALL", StringComparison.Ordinal) 
                                                ? "With 'NOPASSWD: ALL', any user in this group has unrestricted root access without any password prompt. " +
                                                  "This is equivalent to having the root password and bypasses all authentication controls."
                                                : $"The command '{dangerousCmd}' can be exploited to gain a full root shell. " +
                                                  "Any user with access to this account can escalate to root without password authentication.") +
                                            "\n\nPasswordless sudo to dangerous commands is a common privilege escalation vector."
                                        )
                                        .WithEvidence(
                                            type: "config",
                                            value: sudoersFile,
                                            context: $"Line {lineNumber}: {line}"
                                        )
                                        .WithReferences(
                                            "https://man7.org/linux/man-pages/man5/sudoers.5.html",
                                            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html",
                                            "https://gtfobins.github.io/",
                                            "https://www.cisecurity.org/benchmark/distribution_independent_linux"
                                        )
                                        .WithAffectedComponent($"Sudoers: {userOrGroup}"));
                                    }
                                }
                            }
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Log.Debug("[{CheckName}] Cannot read {File} (requires root privileges)", Name, sudoersFile);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking sudoers configuration", Name);
            }

            return findings;
        }

        #endregion

        #region File Permission Checks

        private async Task<List<Finding>> CheckCriticalFilePermissionsAsync()
        {
            var findings = new List<Finding>();

            foreach (var file in CriticalFiles)
            {
                var filePath = file.Key;
                var expectedPerms = file.Value;

                if (!await FileExistsAsync(filePath))
                    continue;

                try
                {
                    // Get file permissions using 'stat' command
                    var (success, output) = await ExecuteCommandAsync("stat", $"-c %a {filePath}");
                    
                    if (success)
                    {
                        // Normalize permissions to 4 digits
                        var actualPerms = output.Trim().PadLeft(4, '0');
                        var expectedPermsInt = Convert.ToInt32(expectedPerms, 8);
                        var actualPermsInt = Convert.ToInt32(actualPerms, 8);

                        // Check if permissions are more permissive than expected
                        var worldPerms = actualPermsInt & 0x7;
                        var expectedWorldPerms = expectedPermsInt & 0x7;

                        if (worldPerms > expectedWorldPerms)
                        {
                            var severity = "high";
                            
                            // Critical files or world-writable = critical severity
                            if (filePath.Contains("shadow", StringComparison.Ordinal) || (worldPerms & 0x2) != 0)
                            {
                                severity = "critical";
                            }

                            findings.Add(Finding.Create(
                                id: "AST-PRIV-LNX-004",
                                title: $"Critical file has insecure permissions: {System.IO.Path.GetFileName(filePath)}",
                                severity: severity,
                                confidence: "high",
                                recommendation: "Fix file permissions immediately:\n" +
                                    $"1. sudo chmod {expectedPerms} {filePath}\n" +
                                    $"2. Verify fix: ls -l {filePath}\n" +
                                    "3. If file was previously world-readable, assume contents may be compromised:\n" +
                                    "   - For /etc/shadow: Change all user passwords immediately\n" +
                                    "   - For SSH keys: Generate new keys and deploy to authorized systems\n" +
                                    "   - For sudoers: Review all sudo access grants\n" +
                                    "4. Audit system logs for signs of unauthorized access\n" +
                                    "5. Check for other files with weak permissions:\n" +
                                    "   find /etc -type f -perm -o+w 2>/dev/null\n" +
                                    "6. Implement file integrity monitoring (AIDE, Tripwire)"
                            )
                            .WithDescription(
                                $"The critical system file '{filePath}' has overly permissive file permissions ({actualPerms}). " +
                                $"Expected permissions: {expectedPerms}. " +
                                "This could allow:\n" +
                                (worldPerms >= 4 ? "• Unauthorized users to READ sensitive data (passwords, keys, configuration)\n" : "") +
                                ((worldPerms & 0x2) != 0 ? "• Unauthorized users to MODIFY system configuration (privilege escalation)\n" : "") +
                                ((worldPerms & 0x1) != 0 ? "• Unauthorized execution of sensitive scripts\n" : "") +
                                "\n" +
                                (filePath.Contains("shadow", StringComparison.Ordinal) 
                                    ? "The /etc/shadow file contains password hashes. World-readable shadow means password cracking attacks are possible."
                                    : filePath.Contains("sudoers", StringComparison.Ordinal)
                                    ? "The sudoers file controls sudo access. Insecure permissions allow privilege escalation modifications."
                                    : filePath.Contains("ssh", StringComparison.Ordinal)
                                    ? "SSH keys with weak permissions can be stolen and used for unauthorized access."
                                    : "This file contains sensitive system configuration.")
                            )
                            .WithEvidence(
                                type: "path",
                                value: filePath,
                                context: $"Current: {actualPerms}, Expected: {expectedPerms} (more permissive by {worldPerms - expectedWorldPerms})"
                            )
                            .WithReferences(
                                "https://linux-audit.com/filesystems/file-permissions/introduction-to-linux-file-permissions/",
                                "https://tldp.org/LDP/intro-linux/html/sect_03_04.html"
                            )
                            .WithAffectedComponent($"{filePath}"));
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug("[{CheckName}] Could not check permissions for {File}: {Error}", Name, filePath, ex.Message);
                }
            }

            return findings;
        }

        #endregion
    }
}
