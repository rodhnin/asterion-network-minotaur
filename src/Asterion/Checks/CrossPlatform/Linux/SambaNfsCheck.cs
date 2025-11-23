using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Models;

namespace Asterion.Checks.Linux
{
    /// <summary>
    /// Linux Samba and NFS Configuration Security Check
    /// 
    /// Detects:
    /// - AST-SAMBA-LNX-001: Samba share with guest access enabled
    /// - AST-SAMBA-LNX-002: SMBv1 protocol enabled (obsolete, EternalBlue vector)
    /// - AST-NFS-LNX-001: NFS export with no_root_squash (critical privilege escalation)
    /// - AST-NFS-LNX-002: NFS export to world (*(rw)) without restrictions
    /// 
    /// Requirements:
    /// - Linux platform (local or remote via SSH)
    /// - Read access to /etc/samba/smb.conf and /etc/exports
    /// - Typically requires root/sudo for full visibility
    /// 
    /// Execution Modes:
    /// - Local: Direct file access on Linux host
    /// - Remote: Via SSH connection (using BaseCheck helpers)
    /// 
    /// Configuration Files Analyzed:
    /// - /etc/samba/smb.conf: Samba server configuration
    /// - /etc/exports: NFS export definitions
    /// </summary>
    public class SambaNfsCheck : BaseCheck
    {
        private const string SambaConfigPath = "/etc/samba/smb.conf";
        private const string NfsExportsPath = "/etc/exports";

        public override string Name => "Samba/NFS Configuration Check";
        
        public override CheckCategory Category => CheckCategory.Linux;
        
        public override string Description => 
            "Audits Samba and NFS server configurations for security misconfigurations including " +
            "guest access, SMBv1 usage, no_root_squash, and world-writable NFS exports. " +
            "Supports both local execution and remote auditing via SSH.";

        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        public SambaNfsCheck(Config config) : base(config) { }

        /// <summary>
        /// Platform validation - requires Linux
        /// </summary>
        public override bool CanExecute()
        {
            if (!base.CanExecute())
                return false;

            // BaseCheck already validates Linux platform via Category
            return true;
        }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var findings = new List<Finding>();

            Log.Information("[{CheckName}] Checking Samba and NFS configurations", Name);

            try
            {
                // ============================================================================
                // Check Samba configuration (local or remote)
                // ============================================================================
                if (await FileExistsAsync(SambaConfigPath))
                {
                    Log.Debug("Found Samba config: {Path}", SambaConfigPath);
                    var sambaFindings = await CheckSambaConfigAsync(SambaConfigPath);
                    findings.AddRange(sambaFindings);
                }
                else
                {
                    Log.Debug("Samba config not found: {Path} (service may not be installed)", SambaConfigPath);
                }

                // ============================================================================
                // Check NFS exports (local or remote)
                // ============================================================================
                if (await FileExistsAsync(NfsExportsPath))
                {
                    Log.Debug("Found NFS exports: {Path}", NfsExportsPath);
                    var nfsFindings = await CheckNfsExportsAsync(NfsExportsPath);
                    findings.AddRange(nfsFindings);
                }
                else
                {
                    Log.Debug("NFS exports not found: {Path} (service may not be installed)", NfsExportsPath);
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                Log.Warning("Permission denied reading Samba/NFS configs: {Message}", ex.Message);
                Log.Information("ℹ️ Tip: Run Asterion as root or with sudo for complete checks");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error during Samba/NFS configuration check");
            }

            LogExecution(1, findings.Count); // 1 target = system being audited (local or remote)
            return findings;
        }

        /// <summary>
        /// Check Samba configuration for security issues
        /// </summary>
        private async Task<List<Finding>> CheckSambaConfigAsync(string configPath)
        {
            var findings = new List<Finding>();

            try
            {
                // ============================================================================
                // Read file content (local or remote via SSH)
                // ============================================================================
                var content = await ReadFileAsync(configPath);
                
                if (string.IsNullOrEmpty(content))
                {
                    Log.Debug("Samba config file is empty or could not be read: {Path}", configPath);
                    return findings;
                }

                var lines = content.Split('\n');

                // Parse Samba config into sections
                var config = ParseSambaConfig(lines);

                // ============================================================
                // Check [global] section for SMBv1
                // ============================================================
                if (config.TryGetValue("global", out var globalSection))
                {
                    // Check for SMBv1 (NT1 protocol)
                    if (globalSection.TryGetValue("server min protocol", out var minProtocol))
                    {
                        if (minProtocol.ToLower().Contains("nt1") || 
                            minProtocol.ToLower().Contains("smb1"))
                        {
                            findings.Add(Finding.Create(
                                id: "AST-SAMBA-LNX-002",
                                title: "SMBv1 protocol enabled in Samba (obsolete)",
                                severity: "high",
                                confidence: "high",
                                recommendation: "Disable SMBv1 in Samba configuration:\n" +
                                    "1. Edit /etc/samba/smb.conf\n" +
                                    "2. In [global] section, set: server min protocol = SMB2\n" +
                                    "   (or better: server min protocol = SMB3)\n" +
                                    "3. Restart Samba: sudo systemctl restart smbd nmbd\n" +
                                    "4. Verify clients support SMB2/3 before applying:\n" +
                                    "   smbclient -L //server -U username\n" +
                                    "5. Monitor logs after change: sudo tail -f /var/log/samba/log.smbd"
                            )
                            .WithDescription(
                                "The Samba server is configured to allow SMBv1 (NT1) protocol, which is obsolete and has multiple critical vulnerabilities:\n" +
                                "• EternalBlue (MS17-010): Remote code execution exploited by WannaCry and NotPetya\n" +
                                "• CVE-2017-7494 (SambaCry): Remote code execution in Samba\n" +
                                "• No encryption or strong authentication\n" +
                                "• Poor performance compared to SMB2/3\n\n" +
                                "SMBv1 should be disabled on all modern systems. Microsoft deprecated it in 2014."
                            )
                            .WithEvidence(
                                type: "config",
                                value: $"server min protocol = {minProtocol}",
                                context: $"File: {configPath}, Section: [global]"
                            )
                            .WithReferences(
                                "https://wiki.samba.org/index.php/Setting_up_Audit_Logging",
                                "https://www.samba.org/samba/security/CVE-2017-7494.html",
                                "https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows"
                            )
                            .WithCve("CVE-2017-7494", "MS17-010")
                            .WithAffectedComponent("Samba Server (Global Configuration)"));
                        }
                    }

                    // Check for map to guest = Bad User (allows anonymous)
                    if (globalSection.TryGetValue("map to guest", out var mapToGuest))
                    {
                        if (mapToGuest.ToLower().Contains("bad user"))
                        {
                            Log.Debug("Samba configured with 'map to guest = Bad User' (allows anonymous login)");
                            // This is often intentional, but combined with guest ok=yes on shares, it's a problem
                        }
                    }
                }

                // ============================================================
                // Check each [share] section for guest access
                // ============================================================
                foreach (var section in config)
                {
                    // Skip special sections
                    if (section.Key.Equals("global", StringComparison.OrdinalIgnoreCase) || 
                        section.Key.Equals("printers", StringComparison.OrdinalIgnoreCase) || 
                        section.Key.Equals("print$", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var shareConfig = section.Value;
                    
                    // Check for guest/public access
                    bool hasGuestOk = shareConfig.TryGetValue("guest ok", out var guestOk) && 
                                     guestOk.ToLower() == "yes";
                    bool hasPublic = shareConfig.TryGetValue("public", out var publicVal) && 
                                    publicVal.ToLower() == "yes";

                    if (hasGuestOk || hasPublic)
                    {
                        // Determine if writable
                        bool isWritable = shareConfig.TryGetValue("writable", out var writable) && 
                                         writable.ToLower() == "yes";
                        bool isReadOnly = shareConfig.TryGetValue("read only", out var readOnly) && 
                                         readOnly.ToLower() == "yes";

                        string accessType = "READ-ONLY";
                        string severityLevel = "medium";

                        if (isWritable || !isReadOnly)
                        {
                            accessType = "READ-WRITE";
                            severityLevel = "high";
                        }

                        shareConfig.TryGetValue("path", out var sharePath);

                        findings.Add(Finding.Create(
                            id: "AST-SAMBA-LNX-001",
                            title: $"Samba share '{section.Key}' accessible to guest/anonymous",
                            severity: severityLevel,
                            confidence: "high",
                            recommendation: "Disable guest/anonymous access on Samba shares:\n" +
                                $"1. Edit /etc/samba/smb.conf\n" +
                                $"2. In [{section.Key}] section:\n" +
                                "   - Set: guest ok = no\n" +
                                "   - Set: public = no\n" +
                                "3. Configure proper user authentication:\n" +
                                "   valid users = @groupname or user1 user2\n" +
                                "4. Add Samba users: sudo smbpasswd -a username\n" +
                                "5. Restart Samba: sudo systemctl restart smbd nmbd\n" +
                                "6. Test access: smbclient //server/share -U username\n" +
                                "7. If anonymous access is required:\n" +
                                "   - Set to read-only: read only = yes\n" +
                                "   - Limit content to non-sensitive files\n" +
                                "   - Document business justification"
                        )
                        .WithDescription(
                            $"The Samba share '{section.Key}' is configured with guest/public access, allowing unauthenticated users to access files. " +
                            $"Access mode: {accessType}. " +
                            (sharePath != null ? $"Share path: {sharePath}. " : "") +
                            "This configuration:\n" +
                            "• Exposes data to anyone on the network without authentication\n" +
                            "• Bypasses auditing and access control\n" +
                            "• May violate compliance requirements (GDPR, HIPAA, PCI-DSS)\n" +
                            (accessType == "READ-WRITE" ? "• Allows anonymous users to modify/delete files (HIGH RISK)\n" : "") +
                            "• Can be exploited for data exfiltration or malware distribution"
                        )
                        .WithEvidence(
                            type: "config",
                            value: $"[{section.Key}]\nguest ok = yes" + 
                                   (sharePath != null ? $"\npath = {sharePath}" : "") +
                                   $"\naccess = {accessType}",
                            context: $"File: {configPath}"
                        )
                        .WithReferences(
                            "https://wiki.samba.org/index.php/Setting_up_a_Share_Using_POSIX_ACLs",
                            "https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html",
                            "CIS Benchmark for Samba - Section 3.2"
                        )
                        .WithAffectedComponent($"Samba Share: [{section.Key}]"));
                    }
                }

                Log.Debug("Samba config check completed: {Count} finding(s)", findings.Count);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error parsing Samba config: {Path}", configPath);
            }

            return findings;
        }

        /// <summary>
        /// Parse Samba config into sections
        /// Format: [section_name]
        ///         key = value
        /// </summary>
        private Dictionary<string, Dictionary<string, string>> ParseSambaConfig(string[] lines)
        {
            var config = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
            string currentSection = "global";
            var currentSectionData = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var rawLine in lines)
            {
                var line = rawLine.Trim();

                // Skip empty lines and comments
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#") || line.StartsWith(";"))
                {
                    continue;
                }

                // Check for section header [name]
                if (line.StartsWith("[") && line.EndsWith("]"))
                {
                    // Save previous section
                    if (currentSectionData.Count > 0)
                    {
                        config[currentSection] = currentSectionData;
                    }

                    // Start new section
                    currentSection = line.Trim('[', ']');
                    currentSectionData = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    continue;
                }

                // Parse key = value
                var parts = line.Split(new[] { '=' }, 2);
                if (parts.Length == 2)
                {
                    var key = parts[0].Trim();
                    var value = parts[1].Trim();
                    currentSectionData[key] = value;
                }
            }

            // Save last section
            if (currentSectionData.Count > 0)
            {
                config[currentSection] = currentSectionData;
            }

            Log.Debug("Parsed Samba config: {SectionCount} sections", config.Count);
            return config;
        }

        /// <summary>
        /// Check NFS exports for security issues
        /// Format: /path host1(options) host2(options) ...
        /// Example: /srv/backups *(rw,no_root_squash)
        /// </summary>
        private async Task<List<Finding>> CheckNfsExportsAsync(string exportsPath)
        {
            var findings = new List<Finding>();

            try
            {
                // ============================================================================
                // Read file content (local or remote via SSH)
                // ============================================================================
                var content = await ReadFileAsync(exportsPath);
                
                if (string.IsNullOrEmpty(content))
                {
                    Log.Debug("NFS exports file is empty or could not be read: {Path}", exportsPath);
                    return findings;
                }

                var lines = content.Split('\n');

                foreach (var rawLine in lines)
                {
                    var line = rawLine.Trim();

                    // Skip empty lines and comments
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                    {
                        continue;
                    }

                    // Parse NFS export line
                    var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2)
                    {
                        continue;
                    }

                    var exportPath = parts[0];

                    // ============================================================
                    // CRITICAL: Check for no_root_squash
                    // ============================================================
                    if (line.Contains("no_root_squash"))
                    {
                        findings.Add(Finding.Create(
                            id: "AST-NFS-LNX-001",
                            title: $"NFS export with no_root_squash: {exportPath}",
                            severity: "critical",
                            confidence: "high",
                            recommendation: "🚨 URGENT: Remove no_root_squash from NFS exports immediately:\n" +
                                "1. Edit /etc/exports\n" +
                                $"2. For export '{exportPath}', REMOVE 'no_root_squash' option\n" +
                                "3. Use 'root_squash' (default) or 'all_squash' instead:\n" +
                                $"   {exportPath} client(rw,sync,root_squash)\n" +
                                "4. Restrict clients - replace '*' with specific hosts/subnets:\n" +
                                $"   {exportPath} 192.168.1.0/24(rw,sync,root_squash)\n" +
                                "5. Reload exports: sudo exportfs -ra\n" +
                                "6. Verify: sudo exportfs -v | grep " + exportPath + "\n" +
                                "7. Audit existing files for unauthorized modifications:\n" +
                                "   sudo find " + exportPath + " -uid 0 -ls\n" +
                                "8. Consider Kerberized NFS for strong authentication:\n" +
                                "   sec=krb5 or sec=krb5p (encrypted)"
                        )
                        .WithDescription(
                            "🔥 CRITICAL PRIVILEGE ESCALATION VULNERABILITY:\n\n" +
                            "An NFS export is configured with 'no_root_squash', which allows remote root users to retain root privileges on the NFS server. " +
                            "This is one of the most dangerous NFS misconfigurations.\n\n" +
                            "**Attack Scenario:**\n" +
                            "1. Attacker mounts the NFS share from a compromised client\n" +
                            "2. Attacker creates files as root (uid 0) on the NFS server\n" +
                            "3. Attacker can:\n" +
                            "   • Create SUID root binaries for privilege escalation\n" +
                            "   • Modify system files (ssh keys, sudoers, cron jobs)\n" +
                            "   • Plant backdoors with root privileges\n" +
                            "   • Access/modify any file on the exported filesystem\n\n" +
                            "**Impact:** Complete system compromise of the NFS server.\n\n" +
                            "**Why it exists:** Historically used for diskless workstations booting from NFS. Rarely needed today."
                        )
                        .WithEvidence(
                            type: "config",
                            value: line,
                            context: $"File: {exportsPath}\nExport contains 'no_root_squash' - remote root = local root"
                        )
                        .WithReferences(
                            "https://linux.die.net/man/5/exports",
                            "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe",
                            "CIS Linux Benchmark - Section 2.2.7 (NFS Exports)"
                        )
                        .WithAffectedComponent($"NFS Export: {exportPath}"));
                    }

                    // ============================================================
                    // HIGH: Check for world-writable exports: *(rw)
                    // ============================================================
                    if (Regex.IsMatch(line, @"\*\s*\(\s*rw"))
                    {
                        findings.Add(Finding.Create(
                            id: "AST-NFS-LNX-002",
                            title: $"NFS export to world with read-write: {exportPath}",
                            severity: "high",
                            confidence: "high",
                            recommendation: "Restrict NFS export access:\n" +
                                "1. Edit /etc/exports\n" +
                                $"2. For export '{exportPath}', replace '*' with specific clients:\n" +
                                "   Option A - Subnet:\n" +
                                $"   {exportPath} 192.168.1.0/24(rw,sync,root_squash)\n" +
                                "   Option B - Specific hosts:\n" +
                                $"   {exportPath} client1(rw) client2(ro) client3(ro)\n" +
                                "3. Use 'ro' (read-only) unless write access is absolutely required\n" +
                                "4. Add security options:\n" +
                                "   - sync: prevent data loss\n" +
                                "   - root_squash: map remote root to nobody\n" +
                                "   - all_squash: map all users to nobody (highest security)\n" +
                                "5. Reload exports: sudo exportfs -ra\n" +
                                "6. Verify: sudo exportfs -v\n" +
                                "7. Configure firewall to restrict NFS ports:\n" +
                                "   sudo ufw allow from 192.168.1.0/24 to any port 2049,111"
                        )
                        .WithDescription(
                            "An NFS export is configured to allow ANY host ('*') with read-write access. " +
                            "This exposes the filesystem to the entire network without authentication or host restrictions.\n\n" +
                            "**Risks:**\n" +
                            "• Any system that can reach the NFS server can mount this filesystem\n" +
                            "• Attackers can read sensitive data\n" +
                            "• Attackers can modify or delete files\n" +
                            "• Can be used for:\n" +
                            "  - Data exfiltration\n" +
                            "  - Ransomware deployment\n" +
                            "  - Lateral movement in networks\n" +
                            "• No authentication required\n" +
                            "• No access control or auditing\n\n" +
                            "NFS security relies entirely on network restrictions and proper client authentication."
                        )
                        .WithEvidence(
                            type: "config",
                            value: line,
                            context: $"File: {exportsPath}\nWildcard '*' allows any host, 'rw' allows write access"
                        )
                        .WithReferences(
                            "https://linux.die.net/man/5/exports",
                            "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/storage_administration_guide/nfs-serverconfig",
                            "https://wiki.archlinux.org/title/NFS"
                        )
                        .WithAffectedComponent($"NFS Export: {exportPath}"));
                    }

                    // Check for anonuid=0 (maps anonymous to root)
                    if (Regex.IsMatch(line, @"anonuid\s*=\s*0"))
                    {
                        Log.Warning("NFS export {Path} has anonuid=0 (maps anonymous users to root)", exportPath);
                        // This is extremely dangerous but covered by no_root_squash check
                    }
                }

                Log.Debug("NFS exports check completed: {Count} finding(s)", findings.Count);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error parsing NFS exports: {Path}", exportsPath);
            }

            return findings;
        }
    }
}