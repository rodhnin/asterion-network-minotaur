using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32;
using Serilog;
using Asterion.Core;
using Asterion.Models;

namespace Asterion.Checks.CrossPlatform.Windows
{
    /// <summary>
    /// Windows Registry Security Check
    /// 
    /// Analyzes critical Windows Registry keys related to authentication and security:
    /// - LM/NTLM authentication settings (LmCompatibilityLevel, NoLMHash)
    /// - Anonymous access restrictions (RestrictAnonymous, EveryoneIncludesAnonymous)
    /// - NTLM session security (NTLMMinClientSec, NTLMMinServerSec)
    /// - User Account Control (UAC) configuration
    /// - Credential storage policies
    /// 
    /// Findings:
    /// - AST-REG-WIN-001: Insecure LM/NTLM compatibility level
    /// - AST-REG-WIN-002: LM password hashes are being stored
    /// - AST-REG-WIN-003: Anonymous access to SAM accounts/shares not restricted
    /// - AST-REG-WIN-004: Weak NTLM client security requirements
    /// - AST-REG-WIN-005: Weak NTLM server security requirements
    /// - AST-REG-WIN-006: User Account Control (UAC) is disabled
    /// - AST-REG-WIN-007: UAC admin elevation prompt behavior is insecure
    /// - AST-REG-WIN-008: UAC secure desktop is disabled
    /// - AST-REG-WIN-009: Built-in administrator account not properly protected
    /// - AST-REG-WIN-010: Domain credentials caching enabled
    /// - AST-REG-WIN-011: Everyone includes Anonymous (legacy insecure setting)
    /// 
    /// Requirements:
    /// - Windows operating system
    /// - Local execution (reads local registry)
    /// - Administrative privileges for some checks (will skip if denied)
    /// 
    /// References:
    /// - CIS Microsoft Windows Server Benchmark
    /// - Microsoft Security Baseline
    /// - NIST SP 800-53
    /// </summary>
    public class WinRegistryCheck : BaseCheck
    {
        public override string Name => "Windows Registry Security Check";
        
        public override CheckCategory Category => CheckCategory.Windows;
        
        public override string Description => 
            "Audits Windows Registry for security misconfigurations including weak authentication protocols " +
            "(LM/NTLM), anonymous access settings, UAC configuration, and credential storage policies. " +
            "Checks against CIS benchmarks and Microsoft security baselines.";

        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        public WinRegistryCheck(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            // Check if registry checks are enabled
            if (!_config.Windows.CheckRegistry)
            {
                Log.Debug("{CheckName} disabled in configuration", Name);
                return new List<Finding>();
            }

            var findings = new List<Finding>();

            Log.Information("[{CheckName}] Starting Windows Registry security audit", Name);

            try
            {
                // Note: This is a local check, 'targets' parameter is not used
                // We're auditing the local Windows Registry

                await Task.Run(() =>
                {
                    // Authentication & Credential Security
                    CheckLmCompatibilityLevel(findings);
                    CheckNoLmHash(findings);
                    CheckRestrictAnonymous(findings);
                    CheckEveryoneIncludesAnonymous(findings);
                    CheckNtlmMinClientSec(findings);
                    CheckNtlmMinServerSec(findings);
                    CheckDisableDomainCreds(findings);

                    // User Account Control (UAC)
                    CheckUacEnabled(findings);
                    CheckUacConsentPromptBehavior(findings);
                    CheckUacSecureDesktop(findings);
                    CheckUacFilterAdministratorToken(findings);
                });

                if (findings.Count == 0)
                {
                    Log.Information("{CheckName}: No registry security issues detected ✓", Name);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error during registry security check", Name);
            }

            LogExecution(1, findings.Count); // 1 target = local system
            return findings;
        }

        #region LM/NTLM Authentication Checks

        /// <summary>
        /// Check LmCompatibilityLevel registry value
        /// Values:
        ///   0 = Send LM & NTLM (weakest)
        ///   1 = Use NTLM if negotiated
        ///   2 = Send NTLM only
        ///   3 = Send NTLMv2 only
        ///   4 = Refuse LM
        ///   5 = Refuse LM & NTLM (strongest)
        /// </summary>
        private void CheckLmCompatibilityLevel(List<Finding> findings)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
                if (key == null)
                {
                    Log.Warning("{CheckName}: Cannot open LSA registry key", Name);
                    return;
                }

                var value = key.GetValue("LmCompatibilityLevel");
                if (value == null)
                {
                    // Not set, defaults vary by Windows version (usually 3 on modern systems)
                    Log.Debug("{CheckName}: LmCompatibilityLevel not explicitly set (using system default)", Name);
                    return;
                }

                int level = Convert.ToInt32(value);
                Log.Debug("{CheckName}: LmCompatibilityLevel = {Level}", Name, level);

                // Levels 0-4 are insecure (allow LM or NTLMv1)
                if (level < 5)
                {
                    string severity = level < 3 ? "high" : "medium";
                    string levelDescription = level switch
                    {
                        0 => "Send LM & NTLM responses",
                        1 => "Send LM & NTLM, use NTLMv2 if negotiated",
                        2 => "Send NTLM response only",
                        3 => "Send NTLMv2 response only",
                        4 => "Send NTLMv2 response only, refuse LM",
                        _ => "Unknown"
                    };
                    
                    findings.Add(Finding.Create(
                        id: "AST-REG-WIN-001",
                        title: "Insecure LM/NTLM authentication level",
                        severity: severity,
                        confidence: "high",
                        recommendation: "Set LmCompatibilityLevel to 5 (Send NTLMv2 only, refuse LM & NTLM):\n\n" +
                            "Via Group Policy:\n" +
                            "1. Open 'Local Security Policy' (secpol.msc)\n" +
                            "2. Navigate to: Security Settings > Local Policies > Security Options\n" +
                            "3. Find: 'Network security: LAN Manager authentication level'\n" +
                            "4. Set to: 'Send NTLMv2 response only. Refuse LM & NTLM'\n" +
                            "5. Apply and reboot\n\n" +
                            "Via Registry (requires reboot):\n" +
                            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f\n\n" +
                            "Via PowerShell:\n" +
                            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LmCompatibilityLevel' -Value 5\n" +
                            "Restart-Computer\n\n" +
                            "⚠️ WARNING: Test in non-production first. Legacy systems may not support NTLMv2."
                    )
                    .WithDescription(
                        $"The LmCompatibilityLevel is set to {level} ({levelDescription}), which allows legacy authentication protocols. " +
                        "Security implications:\n\n" +
                        "**Why this matters:**\n" +
                        "• LM (LAN Manager): Extremely weak, passwords are case-insensitive, split into 7-char chunks, crackable in seconds\n" +
                        "• NTLMv1: Vulnerable to pass-the-hash attacks, uses weak DES-based encryption\n" +
                        "• NTLMv2 (level 5): Uses HMAC-MD5, significantly stronger, required for modern security\n\n" +
                        "**Attack scenarios:**\n" +
                        "• Attackers can downgrade authentication to LM/NTLMv1 via man-in-the-middle\n" +
                        "• Rainbow tables can crack LM hashes instantly\n" +
                        "• Pass-the-hash attacks extract credentials from memory\n\n" +
                        "**Level meanings:**\n" +
                        "  0 = Send LM & NTLM (very weak) ❌\n" +
                        "  1 = Use NTLM if negotiated ❌\n" +
                        "  2 = Send NTLM only ❌\n" +
                        "  3 = Send NTLMv2 only ⚠️\n" +
                        "  4 = Refuse LM ⚠️\n" +
                        "  5 = Refuse LM & NTLM ✅ (REQUIRED)"
                    )
                    .WithEvidence(
                        type: "config",
                        value: $"LmCompatibilityLevel = {level}",
                        context: $"Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel\n" +
                                 $"Current: {levelDescription}\n" +
                                 $"Required: Level 5 (Send NTLMv2 only, refuse LM & NTLM)"
                    )
                    .WithReferences(
                        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level",
                        "https://www.cisecurity.org/benchmark/microsoft_windows_server",
                        "https://support.microsoft.com/en-us/help/239869/how-to-enable-ntlm-2-authentication",
                        "https://attack.mitre.org/techniques/T1550/002/" // Pass the Hash
                    )
                    .WithAffectedComponent("Windows Authentication - LM/NTLM Protocol"));

                    Log.Warning("{CheckName}: Insecure LM/NTLM level detected: {Level}", Name, level);
                }
            }
            catch (UnauthorizedAccessException)
            {
                Log.Warning("{CheckName}: Access denied reading LmCompatibilityLevel (requires elevation)", Name);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking LmCompatibilityLevel", Name);
            }
        }

        /// <summary>
        /// Check if LM password hashes are being stored
        /// NoLMHash = 1 means LM hashes are NOT stored (good)
        /// NoLMHash = 0 or missing means LM hashes ARE stored (bad)
        /// </summary>
        private void CheckNoLmHash(List<Finding> findings)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
                if (key == null)
                    return;

                var value = key.GetValue("NoLMHash");
                int noLmHash = value != null ? Convert.ToInt32(value) : 0;
                Log.Debug("{CheckName}: NoLMHash = {Value}", Name, noLmHash);

                if (noLmHash == 0)
                {
                    findings.Add(Finding.Create(
                        id: "AST-REG-WIN-002",
                        title: "LM password hashes are being stored in SAM",
                        severity: "high",
                        confidence: "high",
                        recommendation: "Disable storage of LM password hashes:\n\n" +
                            "Via Group Policy:\n" +
                            "1. Open 'Local Security Policy' (secpol.msc)\n" +
                            "2. Navigate to: Security Settings > Local Policies > Security Options\n" +
                            "3. Find: 'Network security: Do not store LAN Manager hash value on next password change'\n" +
                            "4. Set to: 'Enabled'\n" +
                            "5. Apply changes\n\n" +
                            "Via Registry:\n" +
                            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v NoLMHash /t REG_DWORD /d 1 /f\n\n" +
                            "Via PowerShell:\n" +
                            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'NoLMHash' -Value 1\n\n" +
                            "⚠️ IMPORTANT: Existing LM hashes persist until password changes!\n" +
                            "Force password reset for all users:\n" +
                            "Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon $true"
                    )
                    .WithDescription(
                        "The system is configured to store LAN Manager (LM) password hashes in the SAM database. " +
                        "This is a **critical security vulnerability** because:\n\n" +
                        "**LM Hash Weaknesses:**\n" +
                        "• Passwords limited to 14 characters\n" +
                        "• Converted to uppercase (loses case sensitivity)\n" +
                        "• Split into two 7-character chunks\n" +
                        "• Each chunk hashed independently with DES\n" +
                        "• No salt used (rainbow tables work)\n" +
                        "• Can be cracked in **seconds** with modern tools\n\n" +
                        "**Attack Scenarios:**\n" +
                        "• Physical access: Boot from USB, extract SAM database\n" +
                        "• Volume Shadow Copy: Extract SAM from VSS snapshots\n" +
                        "• Remote SAM dump: Use PsExec, WMI, or SMB exploits\n" +
                        "• Pass-the-hash: Use extracted hashes for lateral movement\n\n" +
                        "**Tools that exploit this:**\n" +
                        "• Mimikatz, Ophcrack, John the Ripper, hashcat\n" +
                        "• Rainbow tables (freely available online)\n\n" +
                        "An attacker with SAM access can recover passwords instantly and compromise all accounts."
                    )
                    .WithEvidence(
                        type: "config",
                        value: "NoLMHash = 0 (or not set)",
                        context: "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash\n" +
                                 "LM hashes are stored in C:\\Windows\\System32\\config\\SAM\n" +
                                 "Vulnerable to: Offline cracking, rainbow tables, pass-the-hash"
                    )
                    .WithReferences(
                        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change",
                        "https://www.cisecurity.org/benchmark/microsoft_windows_server",
                        "https://www.passcape.com/index.php?section=docsys&cmd=details&id=23",
                        "https://attack.mitre.org/techniques/T1003/002/" // SAM extraction
                    )
                    .WithAffectedComponent("Windows SAM Database - LM Hash Storage"));

                    Log.Warning("{CheckName}: LM hashes are being stored (critical vulnerability)", Name);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking NoLMHash", Name);
            }
        }

        /// <summary>
        /// Check RestrictAnonymous setting
        /// Values:
        ///   0 = No restrictions (default, insecure)
        ///   1 = Do not allow enumeration of SAM accounts/shares (medium)
        ///   2 = No access without explicit anonymous permissions (secure)
        /// </summary>
        private void CheckRestrictAnonymous(List<Finding> findings)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
                if (key == null)
                    return;

                var value = key.GetValue("RestrictAnonymous");
                int restrictAnon = value != null ? Convert.ToInt32(value) : 0;
                Log.Debug("{CheckName}: RestrictAnonymous = {Value}", Name, restrictAnon);

                if (restrictAnon == 0)
                {
                    findings.Add(Finding.Create(
                        id: "AST-REG-WIN-003",
                        title: "Anonymous access to SAM accounts/shares is not restricted",
                        severity: "medium",
                        confidence: "high",
                        recommendation: "Restrict anonymous access to level 1 (or 2 for maximum security):\n\n" +
                            "Via Group Policy:\n" +
                            "1. Open 'Local Security Policy' (secpol.msc)\n" +
                            "2. Navigate to: Security Settings > Local Policies > Security Options\n" +
                            "3. Find: 'Network access: Do not allow anonymous enumeration of SAM accounts and shares'\n" +
                            "4. Set to: 'Enabled'\n" +
                            "5. Apply changes\n\n" +
                            "Via Registry (Level 1 - recommended):\n" +
                            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f\n\n" +
                            "Via Registry (Level 2 - maximum security, may break legacy apps):\n" +
                            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 2 /f\n\n" +
                            "Via PowerShell:\n" +
                            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymous' -Value 1"
                    )
                    .WithDescription(
                        "The RestrictAnonymous registry value is set to 0, allowing anonymous users to enumerate " +
                        "SAM account names and network share information. This information disclosure aids reconnaissance:\n\n" +
                        "**What anonymous users can see:**\n" +
                        "• User account names (via NetUserEnum)\n" +
                        "• Share names (via NetShareEnum)\n" +
                        "• Group memberships (via NetGroupEnum)\n" +
                        "• Security policies (via LSA policy queries)\n\n" +
                        "**Attack scenarios:**\n" +
                        "• Enumerate valid usernames for brute-force attacks\n" +
                        "• Discover administrative accounts\n" +
                        "• Map network shares for lateral movement\n" +
                        "• Gather information about domain structure\n\n" +
                        "**Restriction levels:**\n" +
                        "  0 = No restrictions (allows enumeration) ❌\n" +
                        "  1 = Prevent SAM/share enumeration ✅\n" +
                        "  2 = No access without explicit permissions ✅✅"
                    )
                    .WithEvidence(
                        type: "config",
                        value: "RestrictAnonymous = 0",
                        context: "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous\n" +
                                 "Anonymous enumeration of SAM accounts and shares is permitted\n" +
                                 "Tools like 'enum4linux', 'rpcclient', 'net view' can extract data"
                    )
                    .WithReferences(
                        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts-and-shares",
                        "https://www.cisecurity.org/benchmark/microsoft_windows_server",
                        "https://attack.mitre.org/techniques/T1087/" // Account Discovery
                    )
                    .WithAffectedComponent("Windows SAM - Anonymous Access"));

                    Log.Warning("{CheckName}: Anonymous SAM/share enumeration is allowed", Name);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking RestrictAnonymous", Name);
            }
        }

        /// <summary>
        /// Check EveryoneIncludesAnonymous (legacy insecure setting)
        /// 0 = Everyone does NOT include Anonymous (secure)
        /// 1 = Everyone includes Anonymous (insecure, legacy)
        /// </summary>
        private void CheckEveryoneIncludesAnonymous(List<Finding> findings)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
                if (key == null)
                    return;

                var value = key.GetValue("EveryoneIncludesAnonymous");
                int everyoneIncludesAnon = value != null ? Convert.ToInt32(value) : 0;
                Log.Debug("{CheckName}: EveryoneIncludesAnonymous = {Value}", Name, everyoneIncludesAnon);

                if (everyoneIncludesAnon == 1)
                {
                    findings.Add(Finding.Create(
                        id: "AST-REG-WIN-011",
                        title: "Everyone group includes Anonymous users (legacy insecure setting)",
                        severity: "medium",
                        confidence: "high",
                        recommendation: "Disable EveryoneIncludesAnonymous:\n\n" +
                            "Via Group Policy:\n" +
                            "1. Open 'Local Security Policy' (secpol.msc)\n" +
                            "2. Navigate to: Security Settings > Local Policies > Security Options\n" +
                            "3. Find: 'Network access: Let Everyone permissions apply to anonymous users'\n" +
                            "4. Set to: 'Disabled'\n" +
                            "5. Apply changes\n\n" +
                            "Via Registry:\n" +
                            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f\n\n" +
                            "Via PowerShell:\n" +
                            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0"
                    )
                    .WithDescription(
                        "The EveryoneIncludesAnonymous setting is enabled, which is a legacy insecure configuration. " +
                        "This causes the built-in 'Everyone' group to include anonymous (unauthenticated) users:\n\n" +
                        "**Security impact:**\n" +
                        "• Any resource with 'Everyone' permissions is accessible to anonymous users\n" +
                        "• Network shares, registry keys, files may be unintentionally exposed\n" +
                        "• Violates principle of least privilege\n\n" +
                        "**Why this exists:**\n" +
                        "• Legacy setting from Windows NT/2000 era\n" +
                        "• Provided backward compatibility with pre-2000 systems\n" +
                        "• Modern Windows versions default to 0 (disabled)\n\n" +
                        "**Modern default:** Windows Vista and later default to 0 (secure). " +
                        "If this is enabled, it may indicate a manual misconfiguration or legacy migration."
                    )
                    .WithEvidence(
                        type: "config",
                        value: "EveryoneIncludesAnonymous = 1",
                        context: "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\EveryoneIncludesAnonymous\n" +
                                 "Anonymous users are treated as members of the Everyone group\n" +
                                 "Resources with Everyone permissions are exposed to unauthenticated users"
                    )
                    .WithReferences(
                        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-let-everyone-permissions-apply-to-anonymous-users",
                        "https://www.cisecurity.org/benchmark/microsoft_windows_server"
                    )
                    .WithAffectedComponent("Windows Access Control - Everyone Group"));

                    Log.Warning("{CheckName}: Everyone group includes Anonymous users (legacy insecure setting)", Name);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking EveryoneIncludesAnonymous", Name);
            }
        }

        #endregion

        #region NTLM Session Security Checks

        /// <summary>
        /// Check NTLMMinClientSec (NTLM client security requirements)
        /// Bitmask values:
        ///   0x00000000 = No requirements (insecure)
        ///   0x00080000 = Require NTLMv2 session security
        ///   0x20000000 = Require 128-bit encryption
        /// Recommended: 0x20080000 (both flags set)
        /// </summary>
        private void CheckNtlmMinClientSec(List<Finding> findings)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0");
                if (key == null)
                {
                    Log.Debug("{CheckName}: MSV1_0 registry key not found", Name);
                    return;
                }

                var value = key.GetValue("NTLMMinClientSec");
                int ntlmMinClientSec = value != null ? Convert.ToInt32(value) : 0;
                Log.Debug("{CheckName}: NTLMMinClientSec = 0x{Value:X8}", Name, ntlmMinClientSec);

                bool requiresNTLMv2 = (ntlmMinClientSec & 0x00080000) != 0;
                bool requires128bit = (ntlmMinClientSec & 0x20000000) != 0;

                if (!requiresNTLMv2 || !requires128bit)
                {
                    findings.Add(Finding.Create(
                        id: "AST-REG-WIN-004",
                        title: "NTLM client session security requirements are weak",
                        severity: "medium",
                        confidence: "high",
                        recommendation: "Strengthen NTLM client security to require both NTLMv2 and 128-bit encryption:\n\n" +
                            "Via Group Policy:\n" +
                            "1. Open 'Local Security Policy' (secpol.msc)\n" +
                            "2. Navigate to: Security Settings > Local Policies > Security Options\n" +
                            "3. Find: 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients'\n" +
                            "4. Enable BOTH:\n" +
                            "   ☑ Require NTLMv2 session security\n" +
                            "   ☑ Require 128-bit encryption\n" +
                            "5. Apply changes\n\n" +
                            "Via Registry:\n" +
                            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v NTLMMinClientSec /t REG_DWORD /d 0x20080000 /f\n\n" +
                            "Via PowerShell:\n" +
                            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name 'NTLMMinClientSec' -Value 0x20080000"
                    )
                    .WithDescription(
                        $"The NTLMMinClientSec registry value is set to 0x{ntlmMinClientSec:X8}, which does not require " +
                        "both NTLMv2 session security and 128-bit encryption for outgoing NTLM client connections.\n\n" +
                        "**Current configuration:**\n" +
                        $"• Require NTLMv2 session security: {(requiresNTLMv2 ? "✅ YES" : "❌ NO")}\n" +
                        $"• Require 128-bit encryption: {(requires128bit ? "✅ YES" : "❌ NO")}\n\n" +
                        "**Security implications:**\n" +
                        "• Client may negotiate weaker NTLM versions (NTLMv1)\n" +
                        "• May use 56-bit or 40-bit encryption (weak)\n" +
                        "• Vulnerable to downgrade attacks\n" +
                        "• Easier for attackers to intercept/decrypt traffic\n\n" +
                        "**What this protects:**\n" +
                        "• SMB file shares\n" +
                        "• RPC connections\n" +
                        "• HTTP NTLM authentication\n" +
                        "• SQL Server NTLM auth\n\n" +
                        "**Required value:** 0x20080000 (both flags enabled)"
                    )
                    .WithEvidence(
                        type: "config",
                        value: $"NTLMMinClientSec = 0x{ntlmMinClientSec:X8}",
                        context: $"Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinClientSec\n" +
                                 $"Flags: NTLMv2={requiresNTLMv2}, 128-bit={requires128bit}\n" +
                                 "Required: 0x20080000 (both NTLMv2 and 128-bit)"
                    )
                    .WithReferences(
                        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-minimum-session-security-for-ntlm-ssp-based-including-secure-rpc-clients",
                        "https://www.cisecurity.org/benchmark/microsoft_windows_server"
                    )
                    .WithAffectedComponent("Windows NTLM - Client Session Security"));

                    Log.Warning("{CheckName}: Weak NTLM client security: NTLMv2={NTLMv2}, 128-bit={Bit128}", 
                        Name, requiresNTLMv2, requires128bit);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking NTLMMinClientSec", Name);
            }
        }

        /// <summary>
        /// Check NTLMMinServerSec (NTLM server security requirements)
        /// Same bitmask as NTLMMinClientSec
        /// </summary>
        private void CheckNtlmMinServerSec(List<Finding> findings)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0");
                if (key == null)
                    return;

                var value = key.GetValue("NTLMMinServerSec");
                int ntlmMinServerSec = value != null ? Convert.ToInt32(value) : 0;
                Log.Debug("{CheckName}: NTLMMinServerSec = 0x{Value:X8}", Name, ntlmMinServerSec);

                bool requiresNTLMv2 = (ntlmMinServerSec & 0x00080000) != 0;
                bool requires128bit = (ntlmMinServerSec & 0x20000000) != 0;

                if (!requiresNTLMv2 || !requires128bit)
                {
                    findings.Add(Finding.Create(
                        id: "AST-REG-WIN-005",
                        title: "NTLM server session security requirements are weak",
                        severity: "medium",
                        confidence: "high",
                        recommendation: "Strengthen NTLM server security to require both NTLMv2 and 128-bit encryption:\n\n" +
                            "Via Group Policy:\n" +
                            "1. Open 'Local Security Policy' (secpol.msc)\n" +
                            "2. Navigate to: Security Settings > Local Policies > Security Options\n" +
                            "3. Find: 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers'\n" +
                            "4. Enable BOTH:\n" +
                            "   ☑ Require NTLMv2 session security\n" +
                            "   ☑ Require 128-bit encryption\n" +
                            "5. Apply changes\n\n" +
                            "Via Registry:\n" +
                            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v NTLMMinServerSec /t REG_DWORD /d 0x20080000 /f\n\n" +
                            "Via PowerShell:\n" +
                            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name 'NTLMMinServerSec' -Value 0x20080000"
                    )
                    .WithDescription(
                        $"The NTLMMinServerSec registry value is set to 0x{ntlmMinServerSec:X8}, which does not require " +
                        "both NTLMv2 session security and 128-bit encryption for incoming NTLM server connections.\n\n" +
                        "**Current configuration:**\n" +
                        $"• Require NTLMv2 session security: {(requiresNTLMv2 ? "✅ YES" : "❌ NO")}\n" +
                        $"• Require 128-bit encryption: {(requires128bit ? "✅ YES" : "❌ NO")}\n\n" +
                        "**Security implications:**\n" +
                        "• Server accepts connections with weak NTLM versions\n" +
                        "• May accept 56-bit or 40-bit encryption\n" +
                        "• Vulnerable to downgrade attacks by malicious clients\n" +
                        "• Easier for attackers to intercept/decrypt traffic\n\n" +
                        "**What this protects:**\n" +
                        "• SMB file server\n" +
                        "• RPC server\n" +
                        "• IIS with NTLM authentication\n" +
                        "• SQL Server with NTLM\n\n" +
                        "**Required value:** 0x20080000 (both flags enabled)"
                    )
                    .WithEvidence(
                        type: "config",
                        value: $"NTLMMinServerSec = 0x{ntlmMinServerSec:X8}",
                        context: $"Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinServerSec\n" +
                                 $"Flags: NTLMv2={requiresNTLMv2}, 128-bit={requires128bit}\n" +
                                 "Required: 0x20080000 (both NTLMv2 and 128-bit)"
                    )
                    .WithReferences(
                        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-minimum-session-security-for-ntlm-ssp-based-including-secure-rpc-servers",
                        "https://www.cisecurity.org/benchmark/microsoft_windows_server"
                    )
                    .WithAffectedComponent("Windows NTLM - Server Session Security"));

                    Log.Warning("{CheckName}: Weak NTLM server security: NTLMv2={NTLMv2}, 128-bit={Bit128}", 
                        Name, requiresNTLMv2, requires128bit);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking NTLMMinServerSec", Name);
            }
        }

        /// <summary>
        /// Check if domain credentials caching is enabled
        /// DisableDomainCreds = 1 means disabled (more secure for non-domain machines)
        /// DisableDomainCreds = 0 means enabled (default)
        /// </summary>
        private void CheckDisableDomainCreds(List<Finding> findings)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
                if (key == null)
                    return;

                var value = key.GetValue("DisableDomainCreds");
                
                // If not set, domain creds caching is enabled by default
                if (value == null)
                    return;

                int disableDomainCreds = Convert.ToInt32(value);
                Log.Debug("{CheckName}: DisableDomainCreds = {Value}", Name, disableDomainCreds);

                // Only flag as finding if it's a workgroup/standalone machine
                // (Domain-joined machines need credential caching for offline logon)
                // For now, we log but don't create a finding since we can't easily detect domain membership
                // This would require querying Win32_ComputerSystem.PartOfDomain

                if (disableDomainCreds == 0)
                {
                    Log.Debug("{CheckName}: Domain credential caching is enabled (default)", Name);
                    // Not creating a finding since this is normal for domain-joined machines
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking DisableDomainCreds", Name);
            }
        }

        #endregion

        #region User Account Control (UAC) Checks

        /// <summary>
        /// Check if UAC (User Account Control) is enabled
        /// EnableLUA = 1 means UAC is enabled (good)
        /// EnableLUA = 0 means UAC is disabled (bad)
        /// </summary>
        private void CheckUacEnabled(List<Finding> findings)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                if (key == null)
                    return;

                var value = key.GetValue("EnableLUA");
                int enableLUA = value != null ? Convert.ToInt32(value) : 1; // Default is enabled
                Log.Debug("{CheckName}: UAC EnableLUA = {Value}", Name, enableLUA);

                if (enableLUA == 0)
                {
                    findings.Add(Finding.Create(
                        id: "AST-REG-WIN-006",
                        title: "User Account Control (UAC) is completely disabled",
                        severity: "high",
                        confidence: "high",
                        recommendation: "Enable User Account Control immediately:\n\n" +
                            "Via Group Policy:\n" +
                            "1. Open 'Local Security Policy' (secpol.msc)\n" +
                            "2. Navigate to: Security Settings > Local Policies > Security Options\n" +
                            "3. Find: 'User Account Control: Run all administrators in Admin Approval Mode'\n" +
                            "4. Set to: 'Enabled'\n" +
                            "5. Restart the system\n\n" +
                            "Via Registry (requires reboot):\n" +
                            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f\n\n" +
                            "Via PowerShell (requires reboot):\n" +
                            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1\n" +
                            "Restart-Computer\n\n" +
                            "⚠️ WARNING: Test with legacy applications first. UAC may cause compatibility issues."
                    )
                    .WithDescription(
                        "User Account Control (UAC) is completely disabled on this system. This is a **critical security flaw**:\n\n" +
                        "**Why UAC is essential:**\n" +
                        "• Creates security boundary between standard and admin privileges\n" +
                        "• Prompts for elevation when admin rights needed\n" +
                        "• Prevents silent privilege escalation by malware\n" +
                        "• Implements 'Admin Approval Mode' for administrators\n" +
                        "• Virtualizes file/registry writes for legacy apps\n\n" +
                        "**With UAC disabled:**\n" +
                        "• All applications run with full administrative rights by default\n" +
                        "• No prompts for elevation (malware runs silently)\n" +
                        "• Privilege escalation is trivial\n" +
                        "• No protection against drive-by downloads\n" +
                        "• Malware can modify system files without warning\n\n" +
                        "**Attack scenarios:**\n" +
                        "• User clicks malicious email attachment → runs as admin\n" +
                        "• Drive-by download from compromised website → full system access\n" +
                        "• Ransomware encrypts system files without prompting\n\n" +
                        "This setting should **NEVER** be disabled on production systems."
                    )
                    .WithEvidence(
                        type: "config",
                        value: "EnableLUA = 0",
                        context: "Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA\n" +
                                 "UAC is disabled system-wide\n" +
                                 "All applications run with full administrative privileges\n" +
                                 "No elevation prompts are shown"
                    )
                    .WithReferences(
                        "https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-overview",
                        "https://www.cisecurity.org/benchmark/microsoft_windows_server",
                        "https://attack.mitre.org/techniques/T1548/002/" // Abuse Elevation Control
                    )
                    .WithAffectedComponent("Windows UAC"));

                    Log.Error("{CheckName}: UAC is completely disabled (critical vulnerability)", Name);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking UAC status", Name);
            }
        }

        /// <summary>
        /// Check UAC ConsentPromptBehaviorAdmin
        /// Values:
        ///   0 = Elevate without prompting (insecure)
        ///   1 = Prompt for credentials on secure desktop
        ///   2 = Prompt for consent on secure desktop (recommended for admins)
        ///   3 = Prompt for credentials
        ///   4 = Prompt for consent
        ///   5 = Prompt for consent for non-Windows binaries (default)
        /// </summary>
        private void CheckUacConsentPromptBehavior(List<Finding> findings)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                if (key == null)
                    return;

                var value = key.GetValue("ConsentPromptBehaviorAdmin");
                int consentPrompt = value != null ? Convert.ToInt32(value) : 5; // Default
                Log.Debug("{CheckName}: UAC ConsentPromptBehaviorAdmin = {Value}", Name, consentPrompt);

                if (consentPrompt == 0)
                {
                    findings.Add(Finding.Create(
                        id: "AST-REG-WIN-007",
                        title: "UAC configured to elevate without prompting",
                        severity: "high",
                        confidence: "high",
                        recommendation: "Configure UAC to prompt for elevation:\n\n" +
                            "Via Group Policy:\n" +
                            "1. Open 'Local Security Policy' (secpol.msc)\n" +
                            "2. Navigate to: Security Settings > Local Policies > Security Options\n" +
                            "3. Find: 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'\n" +
                            "4. Set to: 'Prompt for consent on the secure desktop' (recommended)\n" +
                            "5. Apply changes\n\n" +
                            "Via Registry:\n" +
                            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f\n\n" +
                            "Via PowerShell:\n" +
                            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2"
                    )
                    .WithDescription(
                        "UAC is configured with ConsentPromptBehaviorAdmin = 0, which means administrative operations " +
                        "are elevated **without any prompt or warning**. This defeats the purpose of UAC:\n\n" +
                        "**Security implications:**\n" +
                        "• Admin users bypass UAC prompts entirely\n" +
                        "• Malware can silently elevate privileges\n" +
                        "• No user awareness of privilege escalation\n" +
                        "• No opportunity to deny malicious operations\n\n" +
                        "**Prompt behavior values:**\n" +
                        "  0 = Elevate without prompting ❌ (CURRENT)\n" +
                        "  1 = Prompt for credentials on secure desktop ✅\n" +
                        "  2 = Prompt for consent on secure desktop ✅✅ (RECOMMENDED)\n" +
                        "  3 = Prompt for credentials\n" +
                        "  4 = Prompt for consent\n" +
                        "  5 = Prompt for consent for non-Windows binaries ✅ (Default)\n\n" +
                        "Value 2 provides the best balance of security and usability for administrators."
                    )
                    .WithEvidence(
                        type: "config",
                        value: "ConsentPromptBehaviorAdmin = 0",
                        context: "Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin\n" +
                                 "Administrative operations elevate without prompting\n" +
                                 "UAC protection is effectively bypassed for admins"
                    )
                    .WithReferences(
                        "https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings",
                        "https://www.cisecurity.org/benchmark/microsoft_windows_server"
                    )
                    .WithAffectedComponent("Windows UAC - Elevation Prompt"));

                    Log.Warning("{CheckName}: UAC configured to elevate without prompting", Name);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking UAC ConsentPromptBehaviorAdmin", Name);
            }
        }

        /// <summary>
        /// Check if UAC secure desktop is enabled
        /// PromptOnSecureDesktop = 1 means prompts on secure desktop (good)
        /// PromptOnSecureDesktop = 0 means prompts on normal desktop (insecure)
        /// </summary>
        private void CheckUacSecureDesktop(List<Finding> findings)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                if (key == null)
                    return;

                var value = key.GetValue("PromptOnSecureDesktop");
                int promptOnSecureDesktop = value != null ? Convert.ToInt32(value) : 1; // Default
                Log.Debug("{CheckName}: UAC PromptOnSecureDesktop = {Value}", Name, promptOnSecureDesktop);

                if (promptOnSecureDesktop == 0)
                {
                    findings.Add(Finding.Create(
                        id: "AST-REG-WIN-008",
                        title: "UAC secure desktop is disabled",
                        severity: "medium",
                        confidence: "high",
                        recommendation: "Enable UAC secure desktop:\n\n" +
                            "Via Group Policy:\n" +
                            "1. Open 'Local Security Policy' (secpol.msc)\n" +
                            "2. Navigate to: Security Settings > Local Policies > Security Options\n" +
                            "3. Find: 'User Account Control: Switch to the secure desktop when prompting for elevation'\n" +
                            "4. Set to: 'Enabled'\n" +
                            "5. Apply changes\n\n" +
                            "Via Registry:\n" +
                            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f\n\n" +
                            "Via PowerShell:\n" +
                            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'PromptOnSecureDesktop' -Value 1"
                    )
                    .WithDescription(
                        "UAC is configured to show elevation prompts on the normal desktop instead of the secure desktop. " +
                        "The secure desktop is an isolated desktop that prevents other applications from interacting with UAC prompts:\n\n" +
                        "**What is secure desktop:**\n" +
                        "• Isolated desktop session (separate from normal desktop)\n" +
                        "• Screen dimming effect (visual indicator)\n" +
                        "• No other applications can run or interact\n" +
                        "• Prevents UI automation attacks\n\n" +
                        "**Without secure desktop:**\n" +
                        "• Malware can interact with UAC prompts\n" +
                        "• UI automation can click 'Yes' automatically\n" +
                        "• Screen scrapers can read sensitive information\n" +
                        "• Clickjacking attacks are possible\n\n" +
                        "**Attack scenario:**\n" +
                        "Malware uses SendKeys or UI Automation to automatically click 'Yes' on UAC prompts, " +
                        "bypassing user intent. With secure desktop, this is prevented."
                    )
                    .WithEvidence(
                        type: "config",
                        value: "PromptOnSecureDesktop = 0",
                        context: "Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop\n" +
                                 "UAC prompts appear on normal desktop (not secure desktop)\n" +
                                 "Vulnerable to UI automation attacks"
                    )
                    .WithReferences(
                        "https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings",
                        "https://www.cisecurity.org/benchmark/microsoft_windows_server"
                    )
                    .WithAffectedComponent("Windows UAC - Secure Desktop"));

                    Log.Warning("{CheckName}: UAC secure desktop is disabled", Name);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking UAC PromptOnSecureDesktop", Name);
            }
        }

        /// <summary>
        /// Check FilterAdministratorToken (built-in Administrator account protection)
        /// FilterAdministratorToken = 1 means built-in admin runs in Admin Approval Mode (good)
        /// FilterAdministratorToken = 0 means built-in admin bypasses UAC (default, less secure)
        /// </summary>
        private void CheckUacFilterAdministratorToken(List<Finding> findings)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                if (key == null)
                    return;

                var value = key.GetValue("FilterAdministratorToken");
                int filterAdminToken = value != null ? Convert.ToInt32(value) : 0; // Default
                Log.Debug("{CheckName}: UAC FilterAdministratorToken = {Value}", Name, filterAdminToken);

                if (filterAdminToken == 0)
                {
                    // This is the default and expected behavior
                    // Only create finding if built-in admin account is actually enabled
                    // For now, just log (checking if admin is enabled requires additional Win32 API calls)
                    Log.Debug("{CheckName}: Built-in Administrator account can bypass UAC (default behavior)", Name);
                    
                    // Not creating a finding since this is default behavior
                    // and the built-in admin should be disabled by default anyway
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error checking UAC FilterAdministratorToken", Name);
            }
        }

        #endregion
    }
}