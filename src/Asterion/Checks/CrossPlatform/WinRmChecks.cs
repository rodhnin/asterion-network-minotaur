using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Models;

namespace Asterion.Checks.CrossPlatform
{
    /// <summary>
    /// Cross-platform Windows remote audit via WinRM/PowerShell.
    ///
    /// This is the SINGLE file that covers ALL Windows checks when Asterion runs on Linux.
    /// On Windows, the native check classes (WinFirewallCheck, WinRegistryCheck, etc.) handle
    /// both local and WinRM execution. On Linux those classes are excluded from compilation
    /// (&lt;Compile Remove="**/Windows/**/*.cs" /&gt;), so this class replaces all of them
    /// via PowerShell commands sent over WinRM.
    ///
    /// Finding codes produced (port of all Windows check classes):
    ///   Firewall:  AST-FW-WIN-001..004
    ///   Registry:  AST-REG-WIN-001..008, AST-REG-WIN-011..012
    ///   Services:  AST-IIS-WIN-001..005, AST-SQL-WIN-001..003, AST-EXCH-WIN-001, AST-SVC-WIN-001/003
    ///   PrivEsc:   AST-PRIV-WIN-001..010
    /// </summary>
    public class WinRmChecks : BaseCheck
    {
        public override string Name => "Windows Remote Checks via WinRM";
        public override CheckCategory Category => CheckCategory.CrossPlatform;
        public override string Description =>
            "Remote Windows security audit via WinRM/PowerShell. Checks firewall, registry, " +
            "services (IIS/SQL/Exchange), and privilege escalation vectors on a remote Windows " +
            "host. Port of WinFirewallCheck, WinRegistryCheck, WinServicesCheck, PrivEscCheckWin.";
        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        public WinRmChecks(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var winRm = WinRmManager;
            if (winRm == null || !winRm.IsConnected)
            {
                Log.Debug("{CheckName}: WinRM manager not connected — skipping", Name);
                return new List<Finding>();
            }

            var findings = new List<Finding>();
            Log.Information("[{CheckName}] Starting remote Windows audit on {Host} via WinRM", Name, winRm.Host);

            try
            {
                Log.Debug("[{CheckName}] Running firewall checks", Name);
                findings.AddRange(await CheckFirewallAsync(winRm));

                Log.Debug("[{CheckName}] Running registry checks", Name);
                findings.AddRange(await CheckRegistryAsync(winRm));

                Log.Debug("[{CheckName}] Running services checks (IIS/SQL/Exchange)", Name);
                findings.AddRange(await CheckServicesAsync(winRm));

                Log.Debug("[{CheckName}] Running AD policy checks", Name);
                findings.AddRange(await CheckAdPolicyAsync(winRm));

                Log.Debug("[{CheckName}] Running privilege escalation checks", Name);
                findings.AddRange(await CheckPrivEscAsync(winRm));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] WinRM remote audit failed", Name);
            }

            LogExecution(1, findings.Count);
            return findings;
        }

        // ════════════════════════════════════════════════════════════════════════
        // FIREWALL  (port of WinFirewallCheck.cs)
        // AST-FW-WIN-001..004
        // ════════════════════════════════════════════════════════════════════════

        private async Task<List<Finding>> CheckFirewallAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            // ── Firewall service status ──────────────────────────────────────────
            var svcJson = await winRm.ExecutePowerShellAsync(
                "Get-Service -Name 'mpssvc' -ErrorAction SilentlyContinue | " +
                "Select-Object Status,StartType | ConvertTo-Json");

            if (!string.IsNullOrWhiteSpace(svcJson) && svcJson.Trim() != "null")
            {
                try
                {
                    var svc = JsonSerializer.Deserialize<JsonElement>(svcJson);
                    if (TryGetInt(svc, "Status", out int status) && status != 4)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-FW-WIN-004",
                            title: "Windows Firewall service is not running",
                            severity: "critical", confidence: "high",
                            recommendation:
                                "Start the firewall service immediately:\n" +
                                "Start-Service -Name mpssvc\n" +
                                "Set-Service -Name mpssvc -StartupType Automatic")
                            .WithDescription(
                                "The Windows Defender Firewall service (mpssvc) is stopped. " +
                                "The system has NO network packet filtering regardless of policy settings. " +
                                "Fully exposed to network-based attacks, port scanning, and lateral movement.")
                            .WithEvidence(type: "service", value: $"mpssvc Status={status}")
                            .WithAffectedComponent("Windows Defender Firewall Service"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse firewall service JSON", Name); }
            }

            // ── Firewall profiles ────────────────────────────────────────────────
            var profileJson = await winRm.ExecutePowerShellAsync(
                "Get-NetFirewallProfile | " +
                "Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogBlocked | " +
                "ConvertTo-Json");

            bool firewallFullyDisabled = false;
            if (!string.IsNullOrWhiteSpace(profileJson) && profileJson.Trim() != "null")
            {
                try
                {
                    var profiles = ParseAsArray(profileJson);
                    var disabledNames = new List<string>();
                    var allowInboundNames = new List<string>();
                    var noLoggingNames = new List<string>();

                    foreach (var p in profiles)
                    {
                        var name = p.TryGetProperty("Name", out var n) ? n.GetString() ?? "?" : "?";
                        // Enabled: PowerShell ConvertTo-Json serializes bool as 0/1
                        if (p.TryGetProperty("Enabled", out var enabled) && !GetBoolOrInt(enabled))
                            disabledNames.Add(name);
                        // DefaultInboundAction: 1 = Allow (bad), 2 = Block (good)
                        if (p.TryGetProperty("DefaultInboundAction", out var inbound) &&
                            TryGetInt(inbound, out int inboundVal) && inboundVal == 1)
                            allowInboundNames.Add(name);
                        // LogBlocked: 1 = False (not logging), 2 = True (logging)
                        if (p.TryGetProperty("LogBlocked", out var logBlocked) &&
                            TryGetInt(logBlocked, out int logVal) && logVal == 1)
                            noLoggingNames.Add(name);
                    }

                    // Track whether ALL profiles are disabled (skip rules enumeration if so)
                    firewallFullyDisabled = disabledNames.Count == profiles.Count && profiles.Count > 0;

                    if (disabledNames.Count > 0)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-FW-WIN-001",
                            title: $"Windows Firewall disabled on profiles: {string.Join(", ", disabledNames)}",
                            severity: "high", confidence: "high",
                            recommendation:
                                $"Enable firewall:\n" +
                                "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block")
                            .WithDescription(
                                $"Windows Defender Firewall is disabled for {string.Join(", ", disabledNames)} profile(s). " +
                                "All inbound connections are unrestricted — attack surface includes every open port.")
                            .WithEvidence(type: "config", value: $"Disabled: {string.Join(", ", disabledNames)}")
                            .WithAffectedComponent($"Windows Firewall - {string.Join(", ", disabledNames)} Profile(s)"));
                    }

                    if (allowInboundNames.Count > 0)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-FW-WIN-001",
                            title: $"Windows Firewall default inbound action is Allow on: {string.Join(", ", allowInboundNames)}",
                            severity: "high", confidence: "high",
                            recommendation:
                                "Change default inbound policy to Block:\n" +
                                $"Set-NetFirewallProfile -Profile {string.Join(",", allowInboundNames)} -DefaultInboundAction Block")
                            .WithDescription(
                                "DefaultInboundAction=Allow means the firewall accepts all connections unless explicitly blocked. " +
                                "This inverts firewall security — best practice requires block-by-default with explicit allow rules.")
                            .WithEvidence(type: "config", value: $"AllowInbound profiles: {string.Join(", ", allowInboundNames)}")
                            .WithAffectedComponent("Windows Firewall - Inbound Policy"));
                    }

                    if (noLoggingNames.Count > 0)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-FW-WIN-003",
                            title: $"Windows Firewall logging disabled on {noLoggingNames.Count} profile(s)",
                            severity: "low", confidence: "high",
                            recommendation:
                                "Enable firewall logging for security monitoring:\n" +
                                "Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384")
                            .WithDescription(
                                $"Firewall logging disabled on: {string.Join(", ", noLoggingNames)}. " +
                                "No audit trail of blocked connections — cannot detect port scans, brute force, or lateral movement attempts.")
                            .WithEvidence(type: "config", value: $"No logging: {string.Join(", ", noLoggingNames)}")
                            .WithAffectedComponent("Windows Firewall - Logging Configuration"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse firewall profiles JSON", Name); }
            }

            // ── Overly permissive inbound rules (Any → critical ports) ────────────
            // Skip if firewall is already disabled — all ports are exposed, no need to enumerate rules.
            string? rulesJson = null;
            if (!firewallFullyDisabled)
            {
                // Use a fast query: fetch port filters for only critical ports, then look up rule+address.
                // This avoids the N×WMI problem of calling Get-NetFirewallAddressFilter per rule.
                rulesJson = await winRm.ExecutePowerShellAsync(@"
$crit = @('135','139','445','1433','3389','5985','5986','3306','5432','1521')
$res  = @()
try {
    $pfs = Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
           Where-Object { $crit -contains $_.LocalPort } |
           Select-Object -First 50
    foreach ($pf in $pfs) {
        $rule = Get-NetFirewallRule -AssociatedNetFirewallPortFilter $pf -ErrorAction SilentlyContinue
        if ($rule -and $rule.Enabled -eq 'True' -and $rule.Direction -eq 'Inbound' -and $rule.Action -eq 'Allow') {
            $af = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
            if ($af -and ($af.RemoteAddress -eq 'Any' -or $af.RemoteAddress -eq '*')) {
                $res += [PSCustomObject]@{ Name=$rule.DisplayName; Port=$pf.LocalPort }
            }
        }
    }
} catch {}
if ($res.Count -gt 0) { $res | ConvertTo-Json -Depth 2 } else { '[]' }");
            }

            if (!string.IsNullOrWhiteSpace(rulesJson) && rulesJson.Trim() != "[]" && rulesJson.Trim() != "null")
            {
                try
                {
                    var rules = ParseAsArray(rulesJson);
                    if (rules.Count > 0)
                    {
                        var ruleList = string.Join(", ", rules.Take(10).Select(r =>
                        {
                            var rName = r.TryGetProperty("Name", out var n) ? n.GetString() : "?";
                            var port  = r.TryGetProperty("Port", out var po) ? po.GetString() : "?";
                            return $"{rName} (:{port})";
                        }));

                        findings.Add(Finding.Create(
                            id: "AST-FW-WIN-002",
                            title: $"Windows Firewall has {rules.Count} overly permissive rules exposing critical ports",
                            severity: rules.Count >= 5 ? "high" : "medium", confidence: "high",
                            recommendation:
                                "Restrict rules to specific IP ranges:\n" +
                                "Get-NetFirewallRule -DisplayName '<rule>' | Get-NetFirewallAddressFilter | " +
                                "Set-NetFirewallAddressFilter -RemoteAddress '10.0.0.0/8'")
                            .WithDescription(
                                $"{rules.Count} inbound Allow rules with RemoteAddress=Any targeting critical ports. " +
                                "Attackers can reach these services from any IP without additional filtering.")
                            .WithEvidence(type: "config", value: $"{rules.Count} permissive rules", context: ruleList)
                            .WithReferences("https://attack.mitre.org/techniques/T1071/")
                            .WithAffectedComponent("Windows Firewall - Inbound Rules"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse firewall rules JSON", Name); }
            }

            return findings;
        }

        // ════════════════════════════════════════════════════════════════════════
        // REGISTRY  (port of WinRegistryCheck.cs — CheckRegistryViaWinRmAsync)
        // AST-REG-WIN-001..008, AST-REG-WIN-011..012
        // ════════════════════════════════════════════════════════════════════════

        private async Task<List<Finding>> CheckRegistryAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            // ── LSA + NTLM + UAC  (single round-trip with [PSCustomObject]) ──────
            // Using [PSCustomObject] instead of @{} avoids the function-definition
            // bug that caused exit code 1 with empty stdout in earlier versions.
            const string psReg = @"
$l = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$m = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$u = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
[PSCustomObject]@{
    LmCompatibilityLevel       = (Get-ItemProperty $l  -Name LmCompatibilityLevel       -ErrorAction SilentlyContinue).LmCompatibilityLevel
    NoLMHash                   = (Get-ItemProperty $l  -Name NoLMHash                   -ErrorAction SilentlyContinue).NoLMHash
    RestrictAnonymous          = (Get-ItemProperty $l  -Name RestrictAnonymous          -ErrorAction SilentlyContinue).RestrictAnonymous
    EveryoneIncludesAnonymous  = (Get-ItemProperty $l  -Name EveryoneIncludesAnonymous  -ErrorAction SilentlyContinue).EveryoneIncludesAnonymous
    NTLMMinClientSec           = (Get-ItemProperty $m  -Name NTLMMinClientSec           -ErrorAction SilentlyContinue).NTLMMinClientSec
    NTLMMinServerSec           = (Get-ItemProperty $m  -Name NTLMMinServerSec           -ErrorAction SilentlyContinue).NTLMMinServerSec
    EnableLUA                  = (Get-ItemProperty $u  -Name EnableLUA                  -ErrorAction SilentlyContinue).EnableLUA
    ConsentPromptBehaviorAdmin = (Get-ItemProperty $u  -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    PromptOnSecureDesktop      = (Get-ItemProperty $u  -Name PromptOnSecureDesktop      -ErrorAction SilentlyContinue).PromptOnSecureDesktop
    FilterAdministratorToken   = (Get-ItemProperty $u  -Name FilterAdministratorToken   -ErrorAction SilentlyContinue).FilterAdministratorToken
} | ConvertTo-Json";

            var regJson = await winRm.ExecutePowerShellAsync(psReg);
            if (!string.IsNullOrWhiteSpace(regJson) && regJson.Trim() != "null")
            {
                try
                {
                    var reg = JsonSerializer.Deserialize<JsonElement>(regJson);

                    // AST-REG-WIN-001 — LmCompatibilityLevel < 5
                    if (TryGetInt(reg, "LmCompatibilityLevel", out int lmLevel) && lmLevel < 5)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-REG-WIN-001",
                            title: "Insecure LM/NTLM authentication level",
                            severity: lmLevel < 3 ? "high" : "medium", confidence: "high",
                            recommendation:
                                "Set LmCompatibilityLevel to 5 (Send NTLMv2 only, refuse LM & NTLM):\n" +
                                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -Value 5\n" +
                                "Or via GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > " +
                                "Network security: LAN Manager authentication level → Send NTLMv2 only. Refuse LM & NTLM")
                            .WithDescription(
                                $"LmCompatibilityLevel={lmLevel} allows legacy LM/NTLMv1 authentication.\n" +
                                "• LM: Case-insensitive, split into 7-char chunks, crackable in seconds\n" +
                                "• NTLMv1: Vulnerable to pass-the-hash and downgrade attacks\n" +
                                "Level 5 required: NTLMv2 session security, refuses LM & NTLM.")
                            .WithEvidence(type: "registry", value: $"HKLM:\\...\\Lsa\\LmCompatibilityLevel = {lmLevel}")
                            .WithAffectedComponent("NTLM Authentication"));
                    }

                    // AST-REG-WIN-002 — NoLMHash = 0
                    if (TryGetInt(reg, "NoLMHash", out int noLm) && noLm == 0)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-REG-WIN-002",
                            title: "LM password hashes are being stored in SAM",
                            severity: "high", confidence: "high",
                            recommendation:
                                "Enable NoLMHash=1:\n" +
                                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name NoLMHash -Value 1")
                            .WithDescription(
                                "NoLMHash=0 — Windows stores LAN Manager (LM) password hashes in the SAM database. " +
                                "LM hashes are trivially crackable with rainbow tables due to DES weakness and case-insensitive storage.")
                            .WithEvidence(type: "registry", value: "HKLM:\\...\\Lsa\\NoLMHash = 0")
                            .WithAffectedComponent("SAM Database"));
                    }

                    // AST-REG-WIN-003 — RestrictAnonymous = 0
                    if (TryGetInt(reg, "RestrictAnonymous", out int restAnon) && restAnon == 0)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-REG-WIN-003",
                            title: "Anonymous access to SAM accounts/shares is not restricted",
                            severity: "medium", confidence: "high",
                            recommendation:
                                "Set RestrictAnonymous=1:\n" +
                                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RestrictAnonymous -Value 1")
                            .WithDescription(
                                "RestrictAnonymous=0 permits unauthenticated (null session) enumeration of SAM accounts, " +
                                "shares, and network resources. Enables BloodHound-style LDAP enumeration without credentials.")
                            .WithEvidence(type: "registry", value: "HKLM:\\...\\Lsa\\RestrictAnonymous = 0")
                            .WithAffectedComponent("Anonymous Access"));
                    }

                    // AST-REG-WIN-011 — EveryoneIncludesAnonymous = 1
                    if (TryGetInt(reg, "EveryoneIncludesAnonymous", out int evAnon) && evAnon == 1)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-REG-WIN-011",
                            title: "Everyone group includes Anonymous users (legacy insecure setting)",
                            severity: "medium", confidence: "high",
                            recommendation:
                                "Set EveryoneIncludesAnonymous=0:\n" +
                                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name EveryoneIncludesAnonymous -Value 0")
                            .WithDescription(
                                "EveryoneIncludesAnonymous=1 makes anonymous users members of the Everyone group. " +
                                "Resources with Everyone permissions are unintentionally accessible without authentication.")
                            .WithEvidence(type: "registry", value: "HKLM:\\...\\Lsa\\EveryoneIncludesAnonymous = 1")
                            .WithAffectedComponent("Access Control - Everyone Group"));
                    }

                    // AST-REG-WIN-004 — NTLMMinClientSec weak
                    if (TryGetInt(reg, "NTLMMinClientSec", out int ntlmClient))
                    {
                        bool needsNTLMv2 = (ntlmClient & 0x00080000) != 0;
                        bool needs128bit = (ntlmClient & 0x20000000) != 0;
                        if (!needsNTLMv2 || !needs128bit)
                        {
                            findings.Add(Finding.Create(
                                id: "AST-REG-WIN-004",
                                title: "NTLM client session security requirements are weak",
                                severity: "medium", confidence: "high",
                                recommendation:
                                    "Require NTLMv2 + 128-bit encryption for client sessions:\n" +
                                    "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name NTLMMinClientSec -Value 537395248")
                                .WithDescription(
                                    $"NTLMMinClientSec=0x{ntlmClient:X8} — client may negotiate NTLMv1 or weak encryption.\n" +
                                    $"NTLMv2 required: {needsNTLMv2} | 128-bit required: {needs128bit}\n" +
                                    "Recommend 0x20080000 to enforce both.")
                                .WithEvidence(type: "registry", value: $"NTLMMinClientSec = 0x{ntlmClient:X8}")
                                .WithAffectedComponent("NTLM Client Session Security"));
                        }
                    }

                    // AST-REG-WIN-005 — NTLMMinServerSec weak
                    if (TryGetInt(reg, "NTLMMinServerSec", out int ntlmServer))
                    {
                        bool needsNTLMv2 = (ntlmServer & 0x00080000) != 0;
                        bool needs128bit = (ntlmServer & 0x20000000) != 0;
                        if (!needsNTLMv2 || !needs128bit)
                        {
                            findings.Add(Finding.Create(
                                id: "AST-REG-WIN-005",
                                title: "NTLM server session security requirements are weak",
                                severity: "medium", confidence: "high",
                                recommendation:
                                    "Require NTLMv2 + 128-bit encryption for server sessions:\n" +
                                    "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name NTLMMinServerSec -Value 537395248")
                                .WithDescription(
                                    $"NTLMMinServerSec=0x{ntlmServer:X8} — server accepts weak NTLM sessions from clients.\n" +
                                    $"NTLMv2 required: {needsNTLMv2} | 128-bit required: {needs128bit}\n" +
                                    "Recommend 0x20080000 to enforce both.")
                                .WithEvidence(type: "registry", value: $"NTLMMinServerSec = 0x{ntlmServer:X8}")
                                .WithAffectedComponent("NTLM Server Session Security"));
                        }
                    }

                    // AST-REG-WIN-006 — UAC disabled
                    if (TryGetInt(reg, "EnableLUA", out int lua) && lua == 0)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-REG-WIN-006",
                            title: "User Account Control (UAC) is completely disabled",
                            severity: "high", confidence: "high",
                            recommendation:
                                "Enable UAC (requires reboot):\n" +
                                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1\n" +
                                "Restart-Computer")
                            .WithDescription(
                                "EnableLUA=0 — UAC completely disabled. All processes run with full admin token by default.\n" +
                                "• Malware runs as admin without prompts\n" +
                                "• Drive-by downloads gain full system access\n" +
                                "• No privilege separation between user and admin context\n" +
                                "Should NEVER be disabled on production systems.")
                            .WithEvidence(type: "registry", value: "HKLM:\\...\\Policies\\System\\EnableLUA = 0")
                            .WithAffectedComponent("Windows UAC"));
                    }

                    // AST-REG-WIN-007 — UAC prompt disabled
                    if (TryGetInt(reg, "ConsentPromptBehaviorAdmin", out int consent) && consent == 0)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-REG-WIN-007",
                            title: "UAC configured to elevate without prompting",
                            severity: "high", confidence: "high",
                            recommendation:
                                "Set ConsentPromptBehaviorAdmin to 2 (credentials) or 5 (consent):\n" +
                                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 2")
                            .WithDescription(
                                "ConsentPromptBehaviorAdmin=0 — admin elevation happens silently without user interaction. " +
                                "Malware can call elevation APIs and gain SYSTEM access without any visible prompt.")
                            .WithEvidence(type: "registry", value: "HKLM:\\...\\Policies\\System\\ConsentPromptBehaviorAdmin = 0")
                            .WithAffectedComponent("Windows UAC - Elevation Prompt"));
                    }

                    // AST-REG-WIN-008 — Secure desktop disabled
                    if (TryGetInt(reg, "PromptOnSecureDesktop", out int secDesk) && secDesk == 0)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-REG-WIN-008",
                            title: "UAC secure desktop is disabled",
                            severity: "medium", confidence: "high",
                            recommendation:
                                "Enable secure desktop:\n" +
                                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name PromptOnSecureDesktop -Value 1")
                            .WithDescription(
                                "PromptOnSecureDesktop=0 — UAC elevation prompts appear on the regular desktop, " +
                                "making them vulnerable to UI spoofing attacks that forge a fake consent dialog.")
                            .WithEvidence(type: "registry", value: "HKLM:\\...\\Policies\\System\\PromptOnSecureDesktop = 0")
                            .WithAffectedComponent("Windows UAC - Secure Desktop"));
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug(ex, "{CheckName}: Failed to parse registry JSON", Name);
                }
            }
            else
            {
                Log.Warning("{CheckName}: Registry PS command returned empty output", Name);
            }

            // ── LDAP Server Signing (NTDS Parameters) — AST-AD-WIN-001 ─────────────
            var ldapSign = await winRm.ExecutePowerShellAsync(
                "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' " +
                "-Name LDAPServerIntegrity -ErrorAction SilentlyContinue).LDAPServerIntegrity");

            if (!string.IsNullOrWhiteSpace(ldapSign) && int.TryParse(ldapSign.Trim(), out int ldapIntegrity))
            {
                // 0 = None (no signing), 1 = Negotiate Signing (weak), 2 = Require Signing (good)
                if (ldapIntegrity < 2)
                {
                    var level = ldapIntegrity == 0 ? "None" : "Negotiate (optional)";
                    findings.Add(Finding.Create(
                        id: "AST-AD-WIN-001",
                        title: "LDAP signing not required by domain controller",
                        severity: ldapIntegrity == 0 ? "high" : "medium", confidence: "high",
                        recommendation:
                            "Require LDAP signing on all domain controllers:\n" +
                            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f\n" +
                            "Or via GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options\n" +
                            "> Domain controller: LDAP server signing requirements → Require signing\n" +
                            "Also enable LDAPS (port 636) with valid certificates.")
                        .WithDescription(
                            $"LDAPServerIntegrity={ldapIntegrity} ({level}) — the DC does not require LDAP signing. " +
                            "Without signing, LDAP traffic is vulnerable to MITM: an attacker can intercept, modify, or replay " +
                            "directory queries and responses, tamper with password changes, and manipulate group membership queries.")
                        .WithEvidence(type: "registry", value: $"HKLM:\\...\\NTDS\\Parameters\\LDAPServerIntegrity = {ldapIntegrity} ({level})")
                        .WithReferences("https://msrc.microsoft.com/update-guide/vulnerability/ADV190023")
                        .WithAffectedComponent($"{winRm.Host}:389 (LDAP)"));
                }
            }

            // ── WDigest — separate key path (SecurityProviders\WDigest) ───────────
            var wdigestVal = await winRm.ExecutePowerShellAsync(
                "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' " +
                "-Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential");

            if (!string.IsNullOrWhiteSpace(wdigestVal) && wdigestVal.Trim() == "1")
            {
                findings.Add(Finding.Create(
                    id: "AST-REG-WIN-012",
                    title: "WDigest authentication stores credentials in plaintext (LSASS)",
                    severity: "high", confidence: "high",
                    recommendation:
                        "Disable WDigest immediately:\n" +
                        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -Value 0\n" +
                        "Force logoff/logon to clear cached plaintext credentials from LSASS.")
                    .WithDescription(
                        "UseLogonCredential=1 — Windows stores plaintext credentials in LSASS memory via WDigest.\n" +
                        "Any process with LSASS read access (Mimikatz, ProcDump, Task Manager) can extract cleartext passwords.\n" +
                        "No cracking required. Domain admin passwords cached after logon are instantly recoverable.\n" +
                        "Disabled by default since KB2871997 (2014) — this was explicitly re-enabled.")
                    .WithEvidence(type: "registry", value: "HKLM:\\...\\SecurityProviders\\WDigest\\UseLogonCredential = 1")
                    .WithReferences("https://attack.mitre.org/techniques/T1003/001/")
                    .WithAffectedComponent("WDigest Authentication Provider (LSASS)"));
            }

            return findings;
        }

        // ════════════════════════════════════════════════════════════════════════
        // SERVICES  (port of WinServicesCheck.cs — WinRM path)
        // AST-IIS-WIN-001..005, AST-SQL-WIN-001..003, AST-EXCH-WIN-001, AST-SVC-WIN-001/003
        // ════════════════════════════════════════════════════════════════════════

        private async Task<List<Finding>> CheckServicesAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();
            var iisFindings  = await CheckIisAsync(winRm);
            var sqlFindings  = await CheckSqlServerAsync(winRm);
            var exchFindings = await CheckExchangeAsync(winRm);
            findings.AddRange(iisFindings);
            findings.AddRange(sqlFindings);
            findings.AddRange(exchFindings);
            findings.AddRange(await CheckLocalSystemServicesAsync(winRm));

            // AST-SVC-WIN-003 — Critical services summary (info) when any critical service detected
            var detectedServices = new List<string>();
            if (iisFindings.Count > 0 || findings.Any(f => f.Id?.StartsWith("AST-IIS") == true)) detectedServices.Add("IIS");
            if (sqlFindings.Count > 0 || findings.Any(f => f.Id?.StartsWith("AST-SQL") == true)) detectedServices.Add("SQL Server");
            if (exchFindings.Count > 0 || findings.Any(f => f.Id?.StartsWith("AST-EXCH") == true)) detectedServices.Add("Exchange");
            if (detectedServices.Count > 0)
            {
                findings.Add(Finding.Create(
                    id: "AST-SVC-WIN-003",
                    title: $"Critical services detected on {winRm.Host}",
                    severity: "info", confidence: "high",
                    recommendation:
                        "For each detected service:\n" +
                        "• IIS: Disable WebDAV if not needed, enforce HTTPS, apply Windows patches\n" +
                        "• SQL Server: Use Windows Authentication, disable 'sa', apply CUs\n" +
                        "• Exchange: Apply latest CU+SU immediately (ProxyShell/ProxyLogon/ProxyNotShell)")
                    .WithDescription(
                        $"Critical services detected on {winRm.Host}: {string.Join(", ", detectedServices)}. " +
                        "These services are high-value targets requiring specific hardening, regular patching, and monitoring. " +
                        "Each has had critical vulnerabilities exploited in the wild by ransomware and APT groups.")
                    .WithEvidence(type: "service", value: $"Detected: {string.Join(", ", detectedServices)}", context: winRm.Host)
                    .WithAffectedComponent($"Critical Services: {string.Join(", ", detectedServices)}"));
            }

            return findings;
        }

        private async Task<List<Finding>> CheckIisAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var iisJson = await winRm.ExecutePowerShellAsync(
                "Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue | Select-Object Status | ConvertTo-Json");
            if (string.IsNullOrWhiteSpace(iisJson)) return findings;

            try
            {
                var svc = JsonSerializer.Deserialize<JsonElement>(iisJson);
                if (!svc.TryGetProperty("Status", out var st) || st.GetInt32() != 4)
                    return findings;
            }
            catch { return findings; }

            Log.Information("[{CheckName}] IIS detected via WinRM, auditing configuration", Name);

            // WebDAV
            var webdavJson = await winRm.ExecutePowerShellAsync(
                "Get-WindowsFeature Web-DAV-Publishing -ErrorAction SilentlyContinue | " +
                "Select-Object Installed | ConvertTo-Json");
            if (!string.IsNullOrWhiteSpace(webdavJson))
            {
                try
                {
                    var wf = JsonSerializer.Deserialize<JsonElement>(webdavJson);
                    if (wf.TryGetProperty("Installed", out var inst) && GetBoolOrInt(inst))
                    {
                        findings.Add(Finding.Create(
                            id: "AST-IIS-WIN-001", title: "IIS WebDAV Enabled",
                            severity: "medium", confidence: "high",
                            recommendation: "Disable WebDAV:\nDisable-WindowsOptionalFeature -Online -FeatureName IIS-WebDAV")
                            .WithDescription("WebDAV enabled on IIS — attackers can use it for unauthorized file upload or remote code execution if misconfigured.")
                            .WithEvidence(type: "service", value: "WebDAV module is loaded in IIS")
                            .WithAffectedComponent("IIS WebDAV"));
                    }
                }
                catch { /* skip */ }
            }

            // HTTPS bindings
            var bindingsJson = await winRm.ExecutePowerShellAsync(
                "Import-Module WebAdministration -ErrorAction SilentlyContinue; " +
                "Get-WebBinding -ErrorAction SilentlyContinue | Select-Object protocol,bindingInformation | ConvertTo-Json");
            if (!string.IsNullOrWhiteSpace(bindingsJson))
            {
                try
                {
                    var arr = ParseAsArray(bindingsJson);
                    bool hasHttps = arr.Any(b =>
                        b.TryGetProperty("protocol", out var proto) &&
                        proto.GetString()?.Equals("https", StringComparison.OrdinalIgnoreCase) == true);
                    if (!hasHttps)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-IIS-WIN-004", title: "IIS HTTPS not configured or no SSL certificate bound",
                            severity: "medium", confidence: "medium",
                            recommendation: "Configure an HTTPS binding with a valid TLS certificate on all IIS sites.")
                            .WithDescription("No HTTPS bindings detected on IIS — all HTTP traffic is transmitted in cleartext.")
                            .WithEvidence(type: "config", value: "No SSL certificate binding detected")
                            .WithAffectedComponent($"IIS on {winRm.Host}"));
                    }
                }
                catch { /* skip */ }
            }

            // Directory browsing
            var dirBrowse = await winRm.ExecutePowerShellAsync(
                "Import-Module WebAdministration -ErrorAction SilentlyContinue; " +
                "(Get-WebConfiguration system.webServer/directoryBrowse 'IIS:\\' -ErrorAction SilentlyContinue).enabled");
            if (!string.IsNullOrWhiteSpace(dirBrowse) && dirBrowse.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(Finding.Create(
                    id: "AST-IIS-WIN-005", title: "IIS Directory browsing enabled",
                    severity: "medium", confidence: "high",
                    recommendation: "Disable directory browsing:\nSet-WebConfigurationProperty -Filter system.webServer/directoryBrowse -Name enabled -Value false")
                    .WithDescription("Directory browsing enabled — visitors can enumerate all files and folders in web directories, leaking sensitive file paths and names.")
                    .WithEvidence(type: "config", value: "directoryBrowse enabled=\"true\" in applicationHost.config")
                    .WithAffectedComponent("IIS Directory Browsing"));
            }

            // Anonymous authentication
            var anonAuth = await winRm.ExecutePowerShellAsync(
                "Import-Module WebAdministration -ErrorAction SilentlyContinue; " +
                "(Get-WebConfiguration system.webServer/security/authentication/anonymousAuthentication 'IIS:\\' -ErrorAction SilentlyContinue).enabled");
            if (!string.IsNullOrWhiteSpace(anonAuth) && anonAuth.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(Finding.Create(
                    id: "AST-IIS-WIN-002", title: "IIS Anonymous Authentication enabled",
                    severity: "low", confidence: "medium",
                    recommendation: "Review anonymous authentication — disable for admin interfaces and internal apps:\n" +
                        "Set-WebConfigurationProperty -Filter system.webServer/security/authentication/anonymousAuthentication -Name enabled -Value false")
                    .WithDescription("Anonymous authentication enabled on IIS. Normal for public sites, but may expose sensitive endpoints without authentication.")
                    .WithEvidence(type: "config", value: "anonymousAuthentication enabled=\"true\" in applicationHost.config")
                    .WithAffectedComponent("IIS Authentication"));
            }

            // Default welcome page
            var defaultPage = await winRm.ExecutePowerShellAsync(
                "Test-Path 'C:\\inetpub\\wwwroot\\iisstart.htm' -ErrorAction SilentlyContinue");
            if (!string.IsNullOrWhiteSpace(defaultPage) && defaultPage.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(Finding.Create(
                    id: "AST-IIS-WIN-003", title: "IIS Default welcome page present",
                    severity: "low", confidence: "high",
                    recommendation: "Remove default IIS welcome page: Remove-Item 'C:\\inetpub\\wwwroot\\iisstart.htm'")
                    .WithDescription("Default IIS welcome page (iisstart.htm) is present. Confirms IIS version and that the server is running default configuration.")
                    .WithEvidence(type: "path", value: @"C:\inetpub\wwwroot\iisstart.htm")
                    .WithAffectedComponent("IIS Default Content"));
            }

            return findings;
        }

        private async Task<List<Finding>> CheckSqlServerAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var sqlJson = await winRm.ExecutePowerShellAsync(
                "Get-Service | Where-Object { $_.Name -like 'MSSQL*' } | " +
                "Select-Object Name,Status | ConvertTo-Json");
            if (string.IsNullOrWhiteSpace(sqlJson)) return findings;

            try
            {
                var svcs = ParseAsArray(sqlJson);
                var running = svcs.Where(s =>
                    s.TryGetProperty("Status", out var st) && st.GetInt32() == 4).ToList();
                if (running.Count == 0) return findings;

                var svcName = running[0].TryGetProperty("Name", out var n) ? n.GetString() ?? "MSSQL" : "MSSQL";
                Log.Information("[{CheckName}] SQL Server detected: {Svc}", Name, svcName);

                // Version check
                var sqlVer = await winRm.ExecutePowerShellAsync(
                    "$inst = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server' -ErrorAction SilentlyContinue).InstalledInstances; " +
                    "if ($inst) { (Get-ItemProperty \"HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\$($inst[0])\\Setup\" -ErrorAction SilentlyContinue).Version } else { '' }");

                if (!string.IsNullOrWhiteSpace(sqlVer))
                {
                    var ver = sqlVer.Trim();
                    if (int.TryParse(ver.Split('.')[0], out int major) && major < 13)
                    {
                        string vName = major switch { 12 => "2014", 11 => "2012", 10 => "2008/2008R2", 9 => "2005", _ => $"v{major}" };
                        findings.Add(Finding.Create(
                            id: "AST-SQL-WIN-001",
                            title: "SQL Server outdated version detected",
                            severity: "high", confidence: "high",
                            recommendation:
                                "Upgrade to SQL Server 2019 or 2022. Backup all databases first.\n" +
                                "Apply latest Cumulative Update (CU) after upgrade.")
                            .WithDescription(
                                $"SQL Server {vName} (v{ver}) no longer receives security patches. " +
                                "Known CVEs remain unpatched — actively exploited in ransomware and data theft campaigns.")
                            .WithEvidence(type: "service", value: $"Version: {ver} ({vName})", context: svcName)
                            .WithAffectedComponent($"SQL Server ({svcName})"));
                    }
                }

                // Auth mode — Mixed = 2
                var loginMode = await winRm.ExecutePowerShellAsync(
                    "$inst = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server' -ErrorAction SilentlyContinue).InstalledInstances; " +
                    "if ($inst) { (Get-Item (\"HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\" + " +
                    "(Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server' -ErrorAction SilentlyContinue | " +
                    "Where-Object { $_.Name -match 'MSSQL' -and $_.Name -match '\\.' } | Select-Object -First 1).PSChildName + " +
                    "'\\MSSQLServer') -ErrorAction SilentlyContinue).GetValue('LoginMode') } else { -1 }");

                if (!string.IsNullOrWhiteSpace(loginMode) && loginMode.Trim() == "2")
                {
                    findings.Add(Finding.Create(
                        id: "AST-SQL-WIN-002",
                        title: "SQL Server using Mixed Mode authentication",
                        severity: "medium", confidence: "high",
                        recommendation:
                            "Switch to Windows Authentication Only:\n" +
                            "SSMS → Server Properties → Security → Windows Authentication mode → restart SQL service")
                        .WithDescription(
                            "Mixed Mode allows SQL logins (username/password) in addition to Windows auth. " +
                            "SQL logins bypass AD password policies and auditing, increasing brute-force attack surface.")
                        .WithEvidence(type: "config", value: "LoginMode = 2 (Mixed Mode)", context: svcName)
                        .WithAffectedComponent($"SQL Server Authentication ({svcName})"));
                }
                // AST-SQL-WIN-003 — 'sa' account (check if Mixed Mode enabled = sa likely present)
                // We detect this when Mixed Mode is on: sa account exists and is likely enabled
                if (!string.IsNullOrWhiteSpace(loginMode) && loginMode.Trim() == "2")
                {
                    findings.Add(Finding.Create(
                        id: "AST-SQL-WIN-003",
                        title: "SQL Server 'sa' account may be enabled",
                        severity: "high", confidence: "medium",
                        recommendation:
                            "Disable or rename the 'sa' account:\n" +
                            "ALTER LOGIN [sa] DISABLE  -- or --  ALTER LOGIN [sa] WITH NAME = [SecureAdminAlias]\n" +
                            "Create individual DBA accounts with Windows Authentication instead.\n" +
                            "If sa must remain: set a strong, unique password and enable failed login auditing.")
                        .WithDescription(
                            "Mixed Mode authentication is enabled, meaning the 'sa' (sysadmin) SQL account exists. " +
                            "'sa' is a known default account with full SYSTEM-level SQL privileges, targeted by:\n" +
                            "• Brute-force tools (Hydra, Medusa, ncrack)\n" +
                            "• Exploitation frameworks (Metasploit, CrackMapExec)\n" +
                            "• Ransomware groups that pivot through SQL Server to the OS via xp_cmdshell")
                        .WithEvidence(type: "config", value: "LoginMode=2 (Mixed Mode) — 'sa' account exists", context: svcName)
                        .WithReferences(
                            "https://attack.mitre.org/techniques/T1078/001/",
                            "https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode")
                        .WithAffectedComponent($"SQL Server 'sa' Account ({svcName})"));
                }
            }
            catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse SQL Server findings", Name); }

            return findings;
        }

        private async Task<List<Finding>> CheckExchangeAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var exchJson = await winRm.ExecutePowerShellAsync(
                "Get-Service | Where-Object { $_.Name -like 'MSExchange*' } | " +
                "Select-Object Name,Status | ConvertTo-Json");
            if (string.IsNullOrWhiteSpace(exchJson)) return findings;

            try
            {
                var svcs = ParseAsArray(exchJson);
                var running = svcs.Where(s =>
                    s.TryGetProperty("Status", out var st) && st.GetInt32() == 4).ToList();
                if (running.Count == 0) return findings;

                Log.Warning("[{CheckName}] Exchange Server detected!", Name);

                findings.Add(Finding.Create(
                    id: "AST-EXCH-WIN-001",
                    title: "Exchange Server detected - Verify latest security patches applied",
                    severity: "high", confidence: "high",
                    recommendation:
                        "CRITICAL — Verify Exchange is fully patched:\n" +
                        "1. Check version: Get-Command Exsetup.exe | % { $_.FileVersionInfo }\n" +
                        "2. Apply latest Cumulative Update (CU) + Security Update (SU)\n" +
                        "3. Verify patches for ProxyLogon (CVE-2021-26855), ProxyShell (CVE-2021-34473), ProxyNotShell (CVE-2022-41040)")
                    .WithDescription(
                        $"Exchange Server detected ({running.Count} MSExchange* services running). " +
                        "Exchange has been the target of multiple critical zero-day vulnerabilities in recent years (ProxyLogon, ProxyShell, ProxyNotShell). " +
                        "An unpatched Exchange server provides full domain compromise path through SYSTEM-level code execution.")
                    .WithEvidence(type: "service", value: $"{running.Count} MSExchange* services running")
                    .WithReferences(
                        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855",
                        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473")
                    .WithAffectedComponent("Microsoft Exchange Server"));
            }
            catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse Exchange findings", Name); }

            return findings;
        }

        private async Task<List<Finding>> CheckLocalSystemServicesAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var skip = "@('wuauserv','WinDefend','MpsSvc','Dhcp','Dnscache','EventLog','LanmanServer'," +
                       "'Schedule','SENS','SystemEventsBroker','Themes','WpnService','spooler','lsass')";
            var sysJson = await winRm.ExecutePowerShellAsync(
                $"$skip = {skip}; " +
                "Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | " +
                "Where-Object { $_.StartName -eq 'LocalSystem' -and $_.State -eq 'Running' -and $_.Name -notin $skip } | " +
                "Select-Object Name,DisplayName | ConvertTo-Json -Depth 1");

            if (!string.IsNullOrWhiteSpace(sysJson) && sysJson.Trim() != "null")
            {
                try
                {
                    var svcs = ParseAsArray(sysJson);
                    if (svcs.Count > 5)
                    {
                        var names = string.Join(", ", svcs.Take(5)
                            .Select(s => s.TryGetProperty("Name", out var n) ? n.GetString() : "?"));

                        findings.Add(Finding.Create(
                            id: "AST-SVC-WIN-001",
                            title: $"Multiple non-essential services running as LocalSystem ({svcs.Count} detected)",
                            severity: "info", confidence: "medium",
                            recommendation:
                                "Review services running as LocalSystem. Apply principle of least privilege — " +
                                "use dedicated service accounts (Network Service, virtual accounts, or MSA) where possible.")
                            .WithDescription(
                                $"{svcs.Count} non-essential services are running as LocalSystem (full SYSTEM privileges). " +
                                "LocalSystem services are high-value lateral movement targets — compromising any one gives SYSTEM access. " +
                                $"Examples: {names}")
                            .WithEvidence(type: "service", value: $"{svcs.Count} LocalSystem services", context: $"Examples: {names}")
                            .WithAffectedComponent("Windows Services - LocalSystem Accounts"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse LocalSystem services", Name); }
            }

            return findings;
        }

        // ════════════════════════════════════════════════════════════════════════
        // AD POLICY  (port of AdPolicyCheck.cs — CheckAdPolicyAsync)
        // AST-AD-WIN-001 is in CheckRegistryAsync. AST-AD-WIN-002/003 are here.
        // ════════════════════════════════════════════════════════════════════════

        private async Task<List<Finding>> CheckAdPolicyAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            // ── AST-AD-WIN-002: Weak domain password policy ─────────────────────────
            var pwPolicy = await winRm.ExecutePowerShellAsync(
                "try { " +
                "  $p = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop; " +
                "  [PSCustomObject]@{ MinLen=$p.MinPasswordLength; MaxAge=[int]$p.MaxPasswordAge.TotalDays; Complexity=$p.ComplexityEnabled } | ConvertTo-Json " +
                "} catch { " +
                "  $out = net accounts /domain 2>$null | Out-String; " +
                "  $minLen = if ($out -match 'Minimum password length:\\s+(\\d+)') { $Matches[1] } else { '-1' }; " +
                "  $maxAge = if ($out -match 'Maximum password age \\(days\\):\\s+([\\d]+)') { $Matches[1] } else { '0' }; " +
                "  [PSCustomObject]@{ MinLen=[int]$minLen; MaxAge=[int]$maxAge; Complexity=$null } | ConvertTo-Json " +
                "}");

            if (!string.IsNullOrWhiteSpace(pwPolicy) && pwPolicy.Trim() != "null")
            {
                try
                {
                    var pp = JsonSerializer.Deserialize<JsonElement>(pwPolicy);
                    if (TryGetInt(pp, "MinLen", out int minLen) && minLen >= 0 && minLen < 12)
                    {
                        string severity = minLen < 6 ? "high" : "medium";
                        findings.Add(Finding.Create(
                            id: "AST-AD-WIN-002",
                            title: $"Weak domain password policy: minimum length is {minLen} characters",
                            severity: severity, confidence: "high",
                            recommendation:
                                "Increase minimum password length to at least 12 characters (14 recommended):\n" +
                                "Via GPO: Default Domain Policy > Computer Config > Windows Settings > Security Settings > " +
                                "Account Policies > Password Policy > Minimum password length → 12\n" +
                                "Also enable: Password must meet complexity requirements\n" +
                                "Consider Fine-Grained Password Policies (PSO) for privileged accounts (≥15 chars).")
                            .WithDescription(
                                $"Domain password policy requires only {minLen} characters minimum. " +
                                (minLen < 6 ? "Passwords this short can be cracked in seconds. " : "Short passwords are easy to brute-force. ") +
                                "Industry best practices require minimum 12-14 characters for general users, 15+ for privileged accounts. " +
                                "Short passwords are trivially cracked by dictionary attacks, credential stuffing, and rainbow tables.")
                            .WithEvidence(type: "config", value: $"MinPasswordLength = {minLen}")
                            .WithReferences("https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy")
                            .WithAffectedComponent("Active Directory Domain Password Policy"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse password policy", Name); }
            }

            // ── AST-AD-WIN-003: Domain trusts (informational) ───────────────────────
            var trustsOut = await winRm.ExecutePowerShellAsync(
                "try { " +
                "  $t = Get-ADTrust -Filter * -ErrorAction Stop | Select-Object Name,TrustType,TrustDirection; " +
                "  if ($t) { $t | ConvertTo-Json -Depth 2 } else { '[]' } " +
                "} catch { " +
                "  $nl = nltest /domain_trusts 2>$null | Out-String; " +
                "  $count = ([regex]::Matches($nl, 'Trusted Domain')).Count; " +
                "  if ($count -gt 0) { \"[{\\\"Count\\\":$count}]\" } else { '[]' } " +
                "}");

            if (!string.IsNullOrWhiteSpace(trustsOut) && trustsOut.Trim() != "[]" && trustsOut.Trim() != "null")
            {
                try
                {
                    var trusts = ParseAsArray(trustsOut);
                    if (trusts.Count > 0)
                    {
                        var trustNames = string.Join(", ", trusts.Take(5).Select(t =>
                            t.TryGetProperty("Name", out var n) ? n.GetString() ?? "?" : $"Trust#{trusts.IndexOf(t)+1}"));

                        findings.Add(Finding.Create(
                            id: "AST-AD-WIN-003",
                            title: $"Domain has {trusts.Count} trust relationship(s): {trustNames}",
                            severity: "info", confidence: "medium",
                            recommendation:
                                "Review all domain trusts in Active Directory Domains and Trusts (domain.msc):\n" +
                                "• Verify each trust is still required\n" +
                                "• Enable SID filtering on all external trusts\n" +
                                "• Prefer selective authentication over forest-wide\n" +
                                "• Remove unnecessary/stale trusts\n" +
                                "• Monitor for cross-domain suspicious activity (BloodHound, AD Recon)")
                            .WithDescription(
                                $"{trusts.Count} domain trust(s) detected: {trustNames}. " +
                                "Domain trusts extend the attack surface — a compromised trusted domain can be leveraged for lateral movement " +
                                "into this domain. SID history attacks and Kerberos delegation can cross trust boundaries.")
                            .WithEvidence(type: "ldap", value: $"{trusts.Count} trust(s): {trustNames}")
                            .WithReferences("https://attack.mitre.org/techniques/T1482/")
                            .WithAffectedComponent("Active Directory Domain Trusts"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse domain trusts", Name); }
            }

            return findings;
        }

        // ════════════════════════════════════════════════════════════════════════
        // PRIVILEGE ESCALATION  (port of PrivEscCheckWin.cs)
        // AST-PRIV-WIN-001..010
        // ════════════════════════════════════════════════════════════════════════

        private async Task<List<Finding>> CheckPrivEscAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            findings.AddRange(await CheckUnquotedPathsAsync(winRm));
            findings.AddRange(await CheckAlwaysInstallElevatedAsync(winRm));
            findings.AddRange(await CheckWritableServiceExeAsync(winRm));
            findings.AddRange(await CheckWritableServiceDirAsync(winRm));
            findings.AddRange(await CheckScheduledTasksWritableAsync(winRm));
            findings.AddRange(await CheckAutoRunWritableAsync(winRm));
            findings.AddRange(await CheckWritableSystemDirsAsync(winRm));
            findings.AddRange(await CheckWritablePathDirsAsync(winRm));
            findings.AddRange(await CheckStartupFolderAsync(winRm));
            findings.AddRange(await CheckSeImpersonateAsync(winRm));

            return findings;
        }

        private async Task<List<Finding>> CheckUnquotedPathsAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var json = await winRm.ExecutePowerShellAsync(@"
Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
Where-Object {
    $p = $_.PathName
    # Already quoted — not vulnerable
    if ($p -match '^""') { return $false }
    # Only privileged services matter
    if ($_.StartName -ne 'LocalSystem' -and $_.StartName -notmatch 'System') { return $false }
    # Extract only the executable portion (up to and including first .exe)
    # This separates the path from arguments like '-k LocalService'
    if ($p -match '^(.+?\.exe)') {
        $exe = $Matches[1]
        # Vulnerable if the exe path itself contains a space (not just its arguments)
        return $exe -match ' '
    }
    return $false
} |
Select-Object Name,PathName,StartName | ConvertTo-Json -Depth 1");

            if (!string.IsNullOrWhiteSpace(json) && json.Trim() != "null")
            {
                try
                {
                    var svcs = ParseAsArray(json);
                    foreach (var svc in svcs)
                    {
                        var name = svc.TryGetProperty("Name", out var n) ? n.GetString() ?? "?" : "?";
                        var path = svc.TryGetProperty("PathName", out var p) ? p.GetString() ?? "?" : "?";

                        findings.Add(Finding.Create(
                            id: "AST-PRIV-WIN-002",
                            title: $"Unquoted service path with spaces: {name}",
                            severity: "medium", confidence: "high",
                            recommendation:
                                $"Quote the service path:\n" +
                                $"sc config \"{name}\" binPath= \"\\\"<correct_path>\\\"\"")
                            .WithDescription(
                                $"Service '{name}' has an unquoted executable path containing spaces, running as SYSTEM. " +
                                "Windows attempts multiple path interpretations — if an attacker can write to any intermediate directory, " +
                                "they can plant a malicious executable that runs as SYSTEM on next service start.")
                            .WithEvidence(type: "service", value: $"Service: {name}", context: $"Path: {path}")
                            .WithReferences("https://attack.mitre.org/techniques/T1574/009/")
                            .WithAffectedComponent($"Service: {name}"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse unquoted paths JSON", Name); }
            }

            return findings;
        }

        private async Task<List<Finding>> CheckAlwaysInstallElevatedAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var hklm = await winRm.ExecutePowerShellAsync(
                "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' " +
                "-Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated");
            var hkcu = await winRm.ExecutePowerShellAsync(
                "(Get-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' " +
                "-Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated");

            if (hklm.Trim() == "1" && hkcu.Trim() == "1")
            {
                findings.Add(Finding.Create(
                    id: "AST-PRIV-WIN-005",
                    title: "AlwaysInstallElevated registry key set — any user can install MSI as SYSTEM",
                    severity: "critical", confidence: "high",
                    recommendation:
                        "Disable AlwaysInstallElevated in BOTH HKLM and HKCU:\n" +
                        "reg delete \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v AlwaysInstallElevated /f\n" +
                        "reg delete \"HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v AlwaysInstallElevated /f\n" +
                        "Or via GPO: Computer/User Configuration → Admin Templates → Windows Installer → Always install elevated → Disabled")
                    .WithDescription(
                        "AlwaysInstallElevated=1 in both HKLM and HKCU — ANY user can install MSI packages with SYSTEM privileges. " +
                        "Trivially exploitable: msfvenom -p windows/x64/shell_reverse_tcp -f msi → msiexec /i evil.msi. " +
                        "Metasploit has a dedicated module (exploit/windows/local/always_install_elevated).")
                    .WithEvidence(type: "config", value: "AlwaysInstallElevated=1 (HKLM + HKCU)")
                    .WithReferences(
                        "https://attack.mitre.org/techniques/T1548/002/",
                        "https://www.rapid7.com/db/modules/exploit/windows/local/always_install_elevated/")
                    .WithAffectedComponent("Windows Installer Policy"));
            }

            return findings;
        }

        private async Task<List<Finding>> CheckWritableServiceExeAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var json = await winRm.ExecutePowerShellAsync(@"
$res = @()
Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
Where-Object { $_.StartName -eq 'LocalSystem' -and $_.State -eq 'Running' -and $_.PathName } |
ForEach-Object {
    $raw  = $_.PathName.Trim([char]34)
    $exe  = if ($raw -match '^(.+?\.exe)') { $Matches[1] } else { $raw.Split(' ')[0] }
    $exe  = [System.Environment]::ExpandEnvironmentVariables($exe)
    if ((Test-Path $exe -ErrorAction SilentlyContinue)) {
        $acl = Get-Acl $exe -ErrorAction SilentlyContinue
        if ($acl) {
            $writable = $acl.Access | Where-Object {
                $_.FileSystemRights -match 'Write|FullControl|Modify' -and $_.FileSystemRights -notmatch 'ReadAndExecute|Read,' -and
                $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
            }
            if ($writable) { $res += [PSCustomObject]@{ Name=$_.Name; Path=$exe; Perms=($writable[0].IdentityReference.Value) } }
        }
    }
}
if ($res.Count -gt 0) { $res | ConvertTo-Json -Depth 2 } else { '[]' }");

            if (!string.IsNullOrWhiteSpace(json) && json.Trim() != "[]" && json.Trim() != "null")
            {
                try
                {
                    var svcs = ParseAsArray(json);
                    foreach (var svc in svcs)
                    {
                        var name = svc.TryGetProperty("Name", out var n) ? n.GetString() ?? "?" : "?";
                        var path = svc.TryGetProperty("Path", out var p) ? p.GetString() ?? "?" : "?";
                        var perms = svc.TryGetProperty("Perms", out var pe) ? pe.GetString() ?? "?" : "?";

                        findings.Add(Finding.Create(
                            id: "AST-PRIV-WIN-001",
                            title: $"Service executable writable by non-admins: {name}",
                            severity: "high", confidence: "high",
                            recommendation:
                                $"Restrict permissions on {path}:\n" +
                                $"icacls \"{path}\" /inheritance:r /grant:r \"Administrators:F\" \"SYSTEM:F\" \"Users:R\"")
                            .WithDescription(
                                $"Service '{name}' runs as SYSTEM and its executable is writable by {perms}. " +
                                "Replacing the binary executes arbitrary code as SYSTEM on next service start/restart. " +
                                "No credentials or exploitation needed — pure filesystem attack.")
                            .WithEvidence(type: "path", value: path, context: $"Service: {name}, ACL writable by: {perms}")
                            .WithReferences("https://attack.mitre.org/techniques/T1574/010/")
                            .WithAffectedComponent($"Service: {name}"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse writable service exe JSON", Name); }
            }

            return findings;
        }

        private async Task<List<Finding>> CheckWritableServiceDirAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var json = await winRm.ExecutePowerShellAsync(@"
$seen = @{}
$res  = @()
Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
Where-Object { $_.StartName -eq 'LocalSystem' -and $_.State -eq 'Running' -and $_.PathName } |
ForEach-Object {
    $raw = $_.PathName.Trim([char]34)
    $exe = if ($raw -match '^(.+?\.exe)') { $Matches[1] } else { $raw.Split(' ')[0] }
    $exe = [System.Environment]::ExpandEnvironmentVariables($exe)
    $dir = [System.IO.Path]::GetDirectoryName($exe)
    if ($dir -and !$seen[$dir] -and (Test-Path $dir -ErrorAction SilentlyContinue)) {
        $seen[$dir] = $true
        $acl = Get-Acl $dir -ErrorAction SilentlyContinue
        if ($acl) {
            $w = $acl.Access | Where-Object {
                $_.FileSystemRights -match 'Write|FullControl|Modify' -and $_.FileSystemRights -notmatch 'ReadAndExecute|Read,' -and
                $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
            }
            if ($w) { $res += [PSCustomObject]@{ Dir=$dir; Svc=$_.Name; Perms=$w[0].IdentityReference.Value } }
        }
    }
}
if ($res.Count -gt 0) { $res | ConvertTo-Json -Depth 2 } else { '[]' }");

            if (!string.IsNullOrWhiteSpace(json) && json.Trim() != "[]" && json.Trim() != "null")
            {
                try
                {
                    var dirs = ParseAsArray(json);
                    foreach (var d in dirs)
                    {
                        var dir   = d.TryGetProperty("Dir",   out var di) ? di.GetString() ?? "?" : "?";
                        var svc   = d.TryGetProperty("Svc",   out var sv) ? sv.GetString() ?? "?" : "?";
                        var perms = d.TryGetProperty("Perms", out var pe) ? pe.GetString() ?? "?" : "?";

                        findings.Add(Finding.Create(
                            id: "AST-PRIV-WIN-003",
                            title: $"Service directory writable (DLL hijacking risk): {System.IO.Path.GetFileName(dir)}",
                            severity: "high", confidence: "high",
                            recommendation:
                                $"Remove write access for non-admins:\n" +
                                $"icacls \"{dir}\" /inheritance:r /grant:r \"Administrators:F\" \"SYSTEM:F\" \"Users:RX\"")
                            .WithDescription(
                                $"Directory '{dir}' (used by SYSTEM service '{svc}') is writable by {perms}. " +
                                "Enables DLL hijacking: place a malicious DLL with an expected name in the directory — " +
                                "service loads it on next start and executes code as SYSTEM.")
                            .WithEvidence(type: "path", value: dir, context: $"Service: {svc}, ACL writable by: {perms}")
                            .WithReferences(
                                "https://attack.mitre.org/techniques/T1574/001/",
                                "https://attack.mitre.org/techniques/T1574/002/")
                            .WithAffectedComponent($"Service Directory: {dir}"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse writable service dir JSON", Name); }
            }

            return findings;
        }

        private async Task<List<Finding>> CheckScheduledTasksWritableAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var json = await winRm.ExecutePowerShellAsync(@"
$res = @()
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' } |
ForEach-Object {
    $t = $_
    $t.Actions | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskExecAction' } |
    ForEach-Object {
        $exe = [System.Environment]::ExpandEnvironmentVariables($_.Execute)
        if ($exe -and (Test-Path $exe -ErrorAction SilentlyContinue)) {
            $acl = Get-Acl $exe -ErrorAction SilentlyContinue
            if ($acl) {
                $w = $acl.Access | Where-Object {
                    $_.FileSystemRights -match 'Write|FullControl|Modify' -and $_.FileSystemRights -notmatch 'ReadAndExecute|Read,' -and
                    $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
                }
                if ($w) { $res += [PSCustomObject]@{ Task=$t.TaskName; Path=$exe; Perms=$w[0].IdentityReference.Value } }
            }
        }
    }
}
if ($res.Count -gt 0) { $res | Select-Object -First 10 | ConvertTo-Json -Depth 2 } else { '[]' }");

            if (!string.IsNullOrWhiteSpace(json) && json.Trim() != "[]" && json.Trim() != "null")
            {
                try
                {
                    var tasks = ParseAsArray(json);
                    foreach (var t in tasks)
                    {
                        var task  = t.TryGetProperty("Task",  out var ta) ? ta.GetString() ?? "?" : "?";
                        var path  = t.TryGetProperty("Path",  out var pa) ? pa.GetString() ?? "?" : "?";
                        var perms = t.TryGetProperty("Perms", out var pe) ? pe.GetString() ?? "?" : "?";

                        findings.Add(Finding.Create(
                            id: "AST-PRIV-WIN-004",
                            title: $"Scheduled task with writable executable: {task}",
                            severity: "high", confidence: "high",
                            recommendation:
                                $"Restrict permissions:\n" +
                                $"icacls \"{path}\" /inheritance:r /grant:r \"Administrators:F\" \"SYSTEM:F\" \"Users:R\"")
                            .WithDescription(
                                $"Scheduled task '{task}' executes '{path}' which is writable by {perms}. " +
                                "Replacing the executable allows code execution with the task's privileges at the scheduled time.")
                            .WithEvidence(type: "path", value: path, context: $"Task: {task}, ACL writable by: {perms}")
                            .WithReferences("https://attack.mitre.org/techniques/T1053/005/")
                            .WithAffectedComponent($"Scheduled Task: {task}"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse scheduled tasks JSON", Name); }
            }

            return findings;
        }

        private async Task<List<Finding>> CheckAutoRunWritableAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var json = await winRm.ExecutePowerShellAsync(@"
$keys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$res = @()
foreach ($k in $keys) {
    $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $val = $_.Value.ToString()
            $exe = if ($val -match '^(.+?\.exe)') { $Matches[1] } else { $val.Split(' ')[0].Trim([char]34) }
            $exe = [System.Environment]::ExpandEnvironmentVariables($exe)
            if (Test-Path $exe -ErrorAction SilentlyContinue) {
                $acl = Get-Acl $exe -ErrorAction SilentlyContinue
                if ($acl) {
                    $w = $acl.Access | Where-Object {
                        $_.FileSystemRights -match 'Write|FullControl|Modify' -and $_.FileSystemRights -notmatch 'ReadAndExecute|Read,' -and
                        $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
                    }
                    if ($w) { $res += [PSCustomObject]@{ Key=$k; Value=$_.Name; Path=$exe } }
                }
            }
        }
    }
}
if ($res.Count -gt 0) { $res | ConvertTo-Json -Depth 2 } else { '[]' }");

            if (!string.IsNullOrWhiteSpace(json) && json.Trim() != "[]" && json.Trim() != "null")
            {
                try
                {
                    var items = ParseAsArray(json);
                    if (items.Count > 0)
                    {
                        var list = string.Join(", ", items.Take(5).Select(i =>
                            i.TryGetProperty("Value", out var v) ? v.GetString() ?? "?" : "?"));

                        findings.Add(Finding.Create(
                            id: "AST-PRIV-WIN-008",
                            title: $"Writable AutoRun registry targets ({items.Count} found)",
                            severity: "high", confidence: "high",
                            recommendation:
                                "Restrict permissions on AutoRun executables:\n" +
                                "icacls \"<path>\" /remove:g \"Users:(W,M)\"")
                            .WithDescription(
                                $"{items.Count} AutoRun registry entries point to executables writable by low-privileged users. " +
                                "Replacing these achieves persistence — malicious code runs at next user login/system startup.\n" +
                                $"Affected entries: {list}")
                            .WithEvidence(type: "config", value: $"{items.Count} writable AutoRun targets", context: list)
                            .WithReferences("https://attack.mitre.org/techniques/T1547/001/")
                            .WithAffectedComponent("AutoRun Registry Keys"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse AutoRun JSON", Name); }
            }

            return findings;
        }

        private async Task<List<Finding>> CheckWritableSystemDirsAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var json = await winRm.ExecutePowerShellAsync(@"
$dirs = @(
    $env:SystemRoot,
    [System.Environment]::GetFolderPath('System'),
    [System.Environment]::GetFolderPath('ProgramFiles'),
    [System.Environment]::GetFolderPath('ProgramFilesX86'),
    (Join-Path $env:SystemRoot 'System32\config')
) | Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) }
$res = @()
foreach ($d in $dirs) {
    try {
        $acl = Get-Acl $d -ErrorAction SilentlyContinue
        if ($acl) {
            $w = $acl.Access | Where-Object {
                $_.FileSystemRights -match 'Write|FullControl|Modify' -and $_.FileSystemRights -notmatch 'ReadAndExecute|Read,' -and
                $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
            }
            if ($w) { $res += [PSCustomObject]@{ Dir=$d; Perms=$w[0].IdentityReference.Value } }
        }
    } catch {}
}
if ($res.Count -gt 0) { $res | ConvertTo-Json -Depth 2 } else { '[]' }");

            if (!string.IsNullOrWhiteSpace(json) && json.Trim() != "[]" && json.Trim() != "null")
            {
                try
                {
                    var dirs = ParseAsArray(json);
                    foreach (var d in dirs)
                    {
                        var dir   = d.TryGetProperty("Dir",   out var di) ? di.GetString() ?? "?" : "?";
                        var perms = d.TryGetProperty("Perms", out var pe) ? pe.GetString() ?? "?" : "?";

                        findings.Add(Finding.Create(
                            id: "AST-PRIV-WIN-006",
                            title: $"Weak ACLs on system directory: {System.IO.Path.GetFileName(dir)}",
                            severity: "high", confidence: "high",
                            recommendation:
                                $"Restrict permissions:\n" +
                                $"icacls \"{dir}\" /inheritance:r /grant:r \"Administrators:F\" \"SYSTEM:F\" \"Users:RX\"")
                            .WithDescription(
                                $"Critical system directory '{dir}' is writable by {perms}. " +
                                "Enables DLL hijacking, executable replacement, and configuration tampering — all leading to SYSTEM-level code execution.")
                            .WithEvidence(type: "path", value: dir, context: $"ACL writable by: {perms}")
                            .WithReferences("https://attack.mitre.org/techniques/T1574/")
                            .WithAffectedComponent($"System Directory: {dir}"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse writable system dirs JSON", Name); }
            }

            return findings;
        }

        private async Task<List<Finding>> CheckWritablePathDirsAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var json = await winRm.ExecutePowerShellAsync(@"
$res = @()
$env:PATH -split ';' | Where-Object { $_ -ne '' } | ForEach-Object {
    $dir = $_.Trim()
    if (Test-Path $dir -ErrorAction SilentlyContinue) {
        try {
            $acl = Get-Acl $dir -ErrorAction SilentlyContinue
            if ($acl) {
                $w = $acl.Access | Where-Object {
                    $_.FileSystemRights -match 'Write|FullControl|Modify' -and $_.FileSystemRights -notmatch 'ReadAndExecute|Read,' -and
                    $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
                }
                if ($w) { $res += $dir }
            }
        } catch {}
    }
}
if ($res.Count -gt 0) { $res | ConvertTo-Json } else { '[]' }");

            if (!string.IsNullOrWhiteSpace(json) && json.Trim() != "[]" && json.Trim() != "null")
            {
                try
                {
                    var paths = ParseAsArray(json);
                    if (paths.Count > 0)
                    {
                        var pathList = string.Join(", ", paths.Select(p => p.GetString() ?? "?"));
                        findings.Add(Finding.Create(
                            id: "AST-PRIV-WIN-007",
                            title: $"Writable directories in system PATH ({paths.Count} found)",
                            severity: "high", confidence: "medium",
                            recommendation:
                                "Remove write permissions for non-admin users from PATH directories:\n" +
                                "icacls \"<path>\" /remove \"Users\"")
                            .WithDescription(
                                $"{paths.Count} system PATH director(ies) are writable by low-privileged users. " +
                                "PATH hijacking: place a malicious binary named 'whoami.exe' or similar in a writable PATH dir — " +
                                "executed whenever anyone (including SYSTEM processes) runs that command.\n" +
                                $"Writable dirs: {pathList}")
                            .WithEvidence(type: "path", value: $"{paths.Count} writable PATH dirs", context: pathList)
                            .WithReferences("https://attack.mitre.org/techniques/T1574/007/")
                            .WithAffectedComponent("System PATH Directories"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse writable PATH JSON", Name); }
            }

            return findings;
        }

        private async Task<List<Finding>> CheckStartupFolderAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            var json = await winRm.ExecutePowerShellAsync(@"
$folders = @(
    [System.Environment]::GetFolderPath('CommonStartup'),
    [System.Environment]::GetFolderPath('Startup')
) | Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) }
$res = @()
foreach ($f in $folders) {
    $acl = Get-Acl $f -ErrorAction SilentlyContinue
    if ($acl) {
        $w = $acl.Access | Where-Object {
            $_.FileSystemRights -match 'Write|FullControl|Modify' -and
            $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
        }
        if ($w) { $res += [PSCustomObject]@{ Folder=$f; Perms=$w[0].IdentityReference.Value } }
    }
}
if ($res.Count -gt 0) { $res | ConvertTo-Json -Depth 2 } else { '[]' }");

            if (!string.IsNullOrWhiteSpace(json) && json.Trim() != "[]" && json.Trim() != "null")
            {
                try
                {
                    var folders = ParseAsArray(json);
                    foreach (var f in folders)
                    {
                        var folder = f.TryGetProperty("Folder", out var fo) ? fo.GetString() ?? "?" : "?";
                        var perms  = f.TryGetProperty("Perms",  out var pe) ? pe.GetString() ?? "?" : "?";

                        findings.Add(Finding.Create(
                            id: "AST-PRIV-WIN-009",
                            title: $"Writable Startup folder: {System.IO.Path.GetFileName(folder)}",
                            severity: "medium", confidence: "high",
                            recommendation:
                                $"Restrict Startup folder permissions:\n" +
                                $"icacls \"{folder}\" /remove:g \"Users:(W,M)\"")
                            .WithDescription(
                                $"Startup folder '{folder}' is writable by {perms}. " +
                                "Programs placed here execute automatically at user login — persistence with zero exploitation needed.")
                            .WithEvidence(type: "path", value: folder, context: $"ACL writable by: {perms}")
                            .WithReferences("https://attack.mitre.org/techniques/T1547/001/")
                            .WithAffectedComponent($"Startup Folder: {folder}"));
                    }
                }
                catch (Exception ex) { Log.Debug(ex, "{C}: Failed to parse startup folder JSON", Name); }
            }

            return findings;
        }

        private async Task<List<Finding>> CheckSeImpersonateAsync(WinRmConnectionManager winRm)
        {
            var findings = new List<Finding>();

            // Check the WinRM session user's privileges
            var privs = await winRm.ExecutePowerShellAsync(
                "[System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | " +
                "ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]).Value }; " +
                "whoami /priv 2>&1 | Select-String 'SeImpersonatePrivilege'");

            if (!string.IsNullOrWhiteSpace(privs) && privs.Contains("SeImpersonatePrivilege", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(Finding.Create(
                    id: "AST-PRIV-WIN-010",
                    title: "SeImpersonatePrivilege enabled — Potato attack risk (SYSTEM escalation)",
                    severity: "high", confidence: "high",
                    recommendation:
                        "Remove SeImpersonatePrivilege from non-essential accounts:\n" +
                        "secpol.msc → Local Policies → User Rights Assignment → Impersonate a client after authentication\n" +
                        "Apply Windows patches for PrintSpoofer and Potato family exploits.")
                    .WithDescription(
                        "The WinRM session user has SeImpersonatePrivilege. This privilege is exploitable via Potato attacks:\n" +
                        "• JuicyPotato / RoguePotato: DCOM/RPC exploitation → SYSTEM shell\n" +
                        "• PrintSpoofer: Print Spooler trick → SYSTEM\n" +
                        "• SweetPotato: Combined technique\n" +
                        "Common on IIS application pools (IIS AppPool\\*) and SQL Server service accounts.")
                    .WithEvidence(type: "config", value: "SeImpersonatePrivilege: Enabled")
                    .WithReferences(
                        "https://attack.mitre.org/techniques/T1134/001/",
                        "https://github.com/ohpe/juicy-potato",
                        "https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/")
                    .WithAffectedComponent("Windows Token Privileges"));
            }

            return findings;
        }

        // ════════════════════════════════════════════════════════════════════════
        // HELPERS
        // ════════════════════════════════════════════════════════════════════════

        /// <summary>
        /// PowerShell ConvertTo-Json serializes booleans as 0/1 integers.
        /// Returns true for JSON true OR integer != 0.
        /// </summary>
        private static bool GetBoolOrInt(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.True)  return true;
            if (element.ValueKind == JsonValueKind.False) return false;
            if (element.ValueKind == JsonValueKind.Number) return element.GetInt32() != 0;
            return false;
        }

        /// <summary>Reads integer from a named property of a JsonElement (handles String and Number kinds).</summary>
        private static bool TryGetInt(JsonElement element, string property, out int value)
        {
            value = 0;
            if (!element.TryGetProperty(property, out var prop)) return false;
            return TryGetInt(prop, out value);
        }

        /// <summary>Reads integer from a scalar JsonElement (handles Number and String kinds).</summary>
        private static bool TryGetInt(JsonElement prop, out int value)
        {
            value = 0;
            if (prop.ValueKind == JsonValueKind.Null) return false;
            if (prop.ValueKind == JsonValueKind.Number) { value = prop.GetInt32(); return true; }
            if (prop.ValueKind == JsonValueKind.String)
            {
                var s = prop.GetString();
                if (int.TryParse(s, out var parsed)) { value = parsed; return true; }
            }
            return false;
        }

        /// <summary>
        /// Deserializes JSON as a list of JsonElements.
        /// Handles single-object responses (PowerShell omits [] when result is 1 item)
        /// and "null" strings returned by PowerShell for empty collections.
        /// </summary>
        private static List<JsonElement> ParseAsArray(string json)
        {
            if (string.IsNullOrWhiteSpace(json) || json.Trim() == "null" || json.Trim() == "\"null\"")
                return new List<JsonElement>();
            try
            {
                var doc = JsonSerializer.Deserialize<JsonElement>(json);
                if (doc.ValueKind == JsonValueKind.Array)
                    return doc.EnumerateArray().ToList();
                if (doc.ValueKind == JsonValueKind.Object)
                    return new List<JsonElement> { doc };
            }
            catch (JsonException) { /* ignore malformed */ }
            return new List<JsonElement>();
        }
    }
}
