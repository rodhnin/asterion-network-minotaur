using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Models;

namespace Asterion.Checks.CrossPlatform.Windows
{
    /// <summary>
    /// Windows Defender Firewall Security Audit
    /// 
    /// Comprehensive firewall security assessment including:
    /// - Firewall state for all profiles (Domain, Private, Public)
    /// - Default action policies (Block vs Allow)
    /// - Overly permissive rules (Allow from Any IP)
    /// - Critical ports exposed without IP restrictions
    /// - Firewall service status
    /// - Logging configuration
    /// - Stealth mode settings
    /// 
    /// Findings:
    /// - AST-FW-WIN-001: Firewall disabled or misconfigured
    /// - AST-FW-WIN-002: Overly permissive firewall rules
    /// - AST-FW-WIN-003: Firewall logging disabled
    /// - AST-FW-WIN-004: Firewall service not running
    /// 
    /// Requirements:
    /// - Windows platform
    /// - Administrator privileges (for full audit)
    /// - PowerShell available
    /// 
    /// Method: PowerShell cmdlets (Get-NetFirewallProfile, Get-NetFirewallRule, Get-Service)
    /// </summary>
    public class WinFirewallCheck : BaseCheck
    {
        public override string Name => "Windows Firewall Security Audit";
        
        public override CheckCategory Category => CheckCategory.Windows;
        
        public override string Description => 
            "Audits Windows Defender Firewall configuration including profile states, default policies, " +
            "rule permissions, logging settings, and service status. Identifies overly permissive rules " +
            "and critical ports exposed without IP restrictions.";

        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        // Critical ports that should be restricted
        private static readonly Dictionary<string, string> CriticalPorts = new()
        {
            { "135", "RPC (Remote Procedure Call)" },
            { "139", "NetBIOS Session Service" },
            { "445", "SMB (Server Message Block)" },
            { "1433", "Microsoft SQL Server" },
            { "1521", "Oracle Database" },
            { "3306", "MySQL Database" },
            { "3389", "Remote Desktop Protocol (RDP)" },
            { "5432", "PostgreSQL Database" },
            { "5985", "WinRM HTTP" },
            { "5986", "WinRM HTTPS" },
            { "8080", "HTTP Alternate" },
            { "8443", "HTTPS Alternate" }
        };

        public WinFirewallCheck(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            // Check if enabled in config
            if (!_config.Windows.CheckFirewall)
            {
                Log.Debug("{CheckName} disabled in configuration", Name);
                return new List<Finding>();
            }

            var findings = new List<Finding>();

            Log.Information("[{CheckName}] Starting Windows Defender Firewall security audit", Name);

            try
            {
                // Check if firewall service is running
                var serviceFindings = await CheckFirewallServiceAsync();
                findings.AddRange(serviceFindings);

                // Check firewall profiles (Domain, Private, Public)
                var profileFindings = await CheckFirewallProfilesAsync();
                findings.AddRange(profileFindings);

                // Check for dangerous rules
                var ruleFindings = await CheckDangerousRulesAsync();
                findings.AddRange(ruleFindings);

                // Check logging configuration
                var loggingFindings = await CheckFirewallLoggingAsync();
                findings.AddRange(loggingFindings);

                Log.Information("[{CheckName}] Audit completed: {Count} issue(s) found", Name, findings.Count);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Firewall audit failed", Name);
            }

            LogExecution(1, findings.Count); // 1 target = local system
            return findings;
        }

        /// <summary>
        /// Check if Windows Firewall service is running
        /// </summary>
        private async Task<List<Finding>> CheckFirewallServiceAsync()
        {
            var findings = new List<Finding>();

            try
            {
                var command = "Get-Service -Name 'mpssvc' | Select-Object Status, StartType | ConvertTo-Json";
                var output = await ExecutePowerShellAsync(command);

                if (string.IsNullOrEmpty(output))
                {
                    Log.Warning("{CheckName}: Unable to query firewall service status", Name);
                    return findings;
                }

                var service = JsonSerializer.Deserialize<FirewallService>(output, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                // ServiceControllerStatus.Running = 4
                if (service != null && service.Status != 4)
                {
                    findings.Add(Finding.Create(
                        id: "AST-FW-WIN-004",
                        title: "Windows Firewall service is not running",
                        severity: "critical",
                        confidence: "high",
                        recommendation: "Start the Windows Firewall service immediately:\n" +
                            "1. Open Services (services.msc)\n" +
                            "2. Locate 'Windows Defender Firewall' (mpssvc)\n" +
                            "3. Right-click → Start\n" +
                            "4. Set Startup type to 'Automatic'\n" +
                            "5. Via PowerShell: Start-Service -Name mpssvc\n" +
                            "6. Verify: Get-Service -Name mpssvc"
                    )
                    .WithDescription(
                        "CRITICAL: The Windows Defender Firewall service (mpssvc) is not running. " +
                        "This means the firewall is completely disabled and provides NO network protection, " +
                        "regardless of configuration settings. The system is fully exposed to:\n" +
                        "• Network-based attacks and exploits\n" +
                        "• Port scanning and enumeration\n" +
                        "• Lateral movement in compromised networks\n" +
                        "• Malware propagation\n\n" +
                        $"Current status: {service.Status}, Startup type: {service.StartType}"
                    )
                    .WithEvidence(
                        type: "service",
                        value: $"Windows Defender Firewall (mpssvc): {service.Status}",
                        context: $"StartType: {service.StartType}"
                    )
                    .WithReferences(
                        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/",
                        "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"
                    )
                    .WithAffectedComponent("Windows Defender Firewall Service"));

                    Log.Error("{CheckName}: Firewall service is not running!", Name);
                }
                // ServiceStartMode.Automatic = 2
                else if (service != null && service.StartType != 2)
                {
                    string startTypeStr = service.StartType switch
                    {
                        0 => "Boot",
                        1 => "System",
                        2 => "Automatic",
                        3 => "Manual",
                        4 => "Disabled",
                        _ => $"Unknown ({service.StartType})"
                    };
                    Log.Warning("{CheckName}: Firewall service startup type is {StartType} (should be Automatic)",
                        Name, startTypeStr);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Failed to check firewall service", Name);
            }

            return findings;
        }

        /// <summary>
        /// Check firewall state for all profiles (Domain, Private, Public)
        /// </summary>
        private async Task<List<Finding>> CheckFirewallProfilesAsync()
        {
            var findings = new List<Finding>();

            try
            {
                var command = "Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked, LogAllowed | ConvertTo-Json";
                var output = await ExecutePowerShellAsync(command);

                if (string.IsNullOrEmpty(output))
                {
                    Log.Warning("{CheckName}: Unable to query firewall profiles (may need admin privileges)", Name);
                    return findings;
                }

                var profiles = ParseFirewallProfiles(output);

                foreach (var profile in profiles)
                {
                    Log.Debug("{CheckName}: Profile {Profile} - Enabled: {Enabled}, DefaultInbound: {Inbound}, DefaultOutbound: {Outbound}",
                        Name, profile.Name, profile.Enabled == 1, profile.DefaultInboundAction, profile.DefaultOutboundAction);

                    // Check if firewall is disabled (Enabled: 1 = True, 0 = False)
                    if (profile.Enabled != 1)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-FW-WIN-001",
                            title: $"Windows Firewall disabled on {profile.Name} profile",
                            severity: "high",
                            confidence: "high",
                            recommendation: $"Enable Windows Firewall for {profile.Name} profile:\n" +
                                "1. Open Windows Defender Firewall with Advanced Security (WF.msc)\n" +
                                $"2. Select '{profile.Name} Profile' in the left pane\n" +
                                "3. Click 'Properties' in the right pane\n" +
                                "4. Set 'Firewall state' to 'On (recommended)'\n" +
                                "5. Set 'Inbound connections' to 'Block (default)'\n" +
                                "6. Set 'Outbound connections' to 'Allow (default)'\n" +
                                $"7. Via PowerShell: Set-NetFirewallProfile -Profile {profile.Name} -Enabled True -DefaultInboundAction Block"
                        )
                        .WithDescription(
                            $"The Windows Defender Firewall is disabled for the {profile.Name} network profile. " +
                            "This completely removes packet filtering protection and exposes the system to:\n" +
                            "• Network-based attacks without any filtering\n" +
                            "• Unrestricted inbound connections on all ports\n" +
                            "• Port scanning and service enumeration\n" +
                            "• Malware communication and lateral movement\n\n" +
                            $"Network profiles define firewall behavior based on connection type:\n" +
                            "• Domain: Connected to domain controller (enterprise)\n" +
                            "• Private: Trusted home/work networks\n" +
                            "• Public: Untrusted networks (coffee shops, airports)\n\n" +
                            $"The {profile.Name} profile should always have the firewall enabled."
                        )
                        .WithEvidence(
                            type: "config",
                            value: $"Profile: {profile.Name}, Enabled: False",
                            context: $"DefaultInbound: {profile.DefaultInboundAction}, DefaultOutbound: {profile.DefaultOutboundAction}"
                        )
                        .WithReferences(
                            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/",
                            "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"
                        )
                        .WithAffectedComponent($"Windows Firewall - {profile.Name} Profile"));

                        Log.Warning("{CheckName}: Firewall disabled on {Profile} profile", Name, profile.Name);
                    }
                    // Check for overly permissive default inbound action (1 = Allow in NET_FW_ACTION enum)
                    else if (profile.DefaultInboundAction == 1)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-FW-WIN-001",
                            title: $"Windows Firewall default inbound action is Allow on {profile.Name}",
                            severity: "high",
                            confidence: "high",
                            recommendation: $"Change default inbound action to Block for {profile.Name}:\n" +
                                "1. Open Windows Defender Firewall with Advanced Security\n" +
                                $"2. Right-click '{profile.Name} Profile' → Properties\n" +
                                "3. Set 'Inbound connections' to 'Block (default)'\n" +
                                "4. Review and create explicit Allow rules ONLY for required services\n" +
                                "5. Document business justification for each Allow rule\n" +
                                $"6. Via PowerShell: Set-NetFirewallProfile -Profile {profile.Name} -DefaultInboundAction Block"
                        )
                        .WithDescription(
                            $"The {profile.Name} profile has DefaultInboundAction set to 'Allow'. " +
                            "This is a complete inversion of firewall security principles:\n" +
                            "• Permits ALL incoming connections by default (deny-list approach)\n" +
                            "• Requires blocking each threat individually (reactive)\n" +
                            "• Exposes unknown/undocumented services automatically\n" +
                            "• Allows attackers to probe any port without restriction\n\n" +
                            "Secure firewall practice requires 'Block' as default inbound action:\n" +
                            "• Denies ALL incoming connections by default (allow-list approach)\n" +
                            "• Requires explicit Allow rules for legitimate services (proactive)\n" +
                            "• Provides defense-in-depth against unknown vulnerabilities\n" +
                            "• Minimizes attack surface automatically"
                        )
                        .WithEvidence(
                            type: "config",
                            value: $"Profile: {profile.Name}, DefaultInboundAction: Allow",
                            context: "Firewall is enabled but policy is reversed (allow-by-default)"
                        )
                        .WithReferences(
                            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/",
                            "https://www.nist.gov/publications/guidelines-firewalls-and-firewall-policy",
                            "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"
                        )
                        .WithAffectedComponent($"Windows Firewall - {profile.Name} Profile"));

                        Log.Warning("{CheckName}: Default inbound action is Allow on {Profile}", Name, profile.Name);
                    }
                    // Check for permissive outbound action (less critical but worth noting, 0 = Block in NET_FW_ACTION enum)
                    else if (profile.DefaultOutboundAction == 0)
                    {
                        // This is actually more restrictive, which is good for high-security environments
                        // But may break applications, so just log it
                        Log.Information("{CheckName}: {Profile} has restrictive outbound policy (Block by default)", 
                            Name, profile.Name);
                    }
                }

                if (profiles.Count == 0)
                {
                    Log.Warning("{CheckName}: No firewall profiles found in output", Name);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Failed to check firewall profiles", Name);
            }

            return findings;
        }

        /// <summary>
        /// Check for dangerous firewall rules (Allow from Any IP to critical ports)
        /// </summary>
        private async Task<List<Finding>> CheckDangerousRulesAsync()
        {
            var findings = new List<Finding>();

            try
            {
                // Get all enabled Allow rules for inbound traffic
                var command = "Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | " +
                            "Get-NetFirewallAddressFilter | " +
                            "Select-Object @{Name='RuleName';Expression={(Get-NetFirewallRule -AssociatedNetFirewallAddressFilter $_).DisplayName}}, " +
                            "@{Name='RemoteAddress';Expression={$_.RemoteAddress -join ','}}, " +
                            "@{Name='LocalPort';Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule (Get-NetFirewallRule -AssociatedNetFirewallAddressFilter $_)).LocalPort -join ','}} | " +
                            "ConvertTo-Json";

                var output = await ExecutePowerShellAsync(command);

                if (string.IsNullOrEmpty(output))
                {
                    Log.Debug("{CheckName}: No firewall rules data returned", Name);
                    return findings;
                }

                var rules = ParseFirewallRules(output);
                var dangerousRules = new List<DangerousRuleInfo>();

                foreach (var rule in rules)
                {
                    // Check for rules allowing from any IP to critical ports
                    if (IsAnyAddress(rule.RemoteAddress))
                    {
                        var criticalPort = GetCriticalPortInfo(rule.LocalPort);
                        if (criticalPort != null)
                        {
                            dangerousRules.Add(new DangerousRuleInfo
                            {
                                RuleName = rule.DisplayName,
                                Port = criticalPort.Value.Key,
                                Service = criticalPort.Value.Value
                            });
                        }
                    }
                }

                if (dangerousRules.Any())
                {
                    var ruleList = string.Join("\n• ", dangerousRules.Take(10).Select(r => $"{r.RuleName} (Port {r.Port}: {r.Service})"));
                    var summary = dangerousRules.Count > 10 
                        ? $"Showing 10 of {dangerousRules.Count} overly permissive rules" 
                        : $"Total: {dangerousRules.Count} overly permissive rules";

                    findings.Add(Finding.Create(
                        id: "AST-FW-WIN-002",
                        title: $"Windows Firewall has {dangerousRules.Count} overly permissive rules exposing critical ports",
                        severity: dangerousRules.Count >= 5 ? "high" : "medium",
                        confidence: "high",
                        recommendation: "Restrict firewall rules to specific IP ranges:\n" +
                            "1. Open Windows Defender Firewall with Advanced Security\n" +
                            "2. Navigate to 'Inbound Rules'\n" +
                            "3. For each overly permissive rule identified:\n" +
                            "   a. Right-click the rule → Properties\n" +
                            "   b. Go to 'Scope' tab\n" +
                            "   c. Under 'Remote IP address':\n" +
                            "      - Change from 'Any IP address' to 'These IP addresses'\n" +
                            "      - Add only authorized IP ranges (e.g., 10.0.0.0/8 for internal network)\n" +
                            "   d. Click OK to save\n" +
                            "4. Document business justification for each exception\n" +
                            "5. Consider using IPsec or VPN for remote access instead\n" +
                            "6. Disable unused rules"
                    )
                    .WithDescription(
                        $"Found {dangerousRules.Count} firewall rules that allow incoming connections from ANY IP address " +
                        "to critical services. This significantly increases attack surface by:\n" +
                        "• Exposing sensitive services to the entire internet\n" +
                        "• Enabling brute-force attacks on authentication\n" +
                        "• Allowing unauthenticated reconnaissance\n" +
                        "• Permitting lateral movement in compromised networks\n\n" +
                        "Critical services exposed:\n" +
                        $"• {ruleList}\n\n" +
                        "Best practice: Restrict remote access to specific trusted IP ranges only. " +
                        "For internet-facing services, use additional authentication layers (VPN, IPsec, reverse proxy with WAF)."
                    )
                    .WithEvidence(
                        type: "config",
                        value: ruleList,
                        context: summary
                    )
                    .WithReferences(
                        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/",
                        "https://www.cisecurity.org/benchmark/microsoft_windows_desktop",
                        "https://www.sans.org/white-papers"
                    )
                    .WithAffectedComponent("Windows Firewall - Inbound Rules"));

                    Log.Warning("{CheckName}: {Count} overly permissive rules found", Name, dangerousRules.Count);
                }
                else
                {
                    Log.Information("{CheckName}: No overly permissive rules exposing critical ports", Name);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Failed to check firewall rules", Name);
            }

            return findings;
        }

        /// <summary>
        /// Check firewall logging configuration
        /// </summary>
        private async Task<List<Finding>> CheckFirewallLoggingAsync()
        {
            var findings = new List<Finding>();

            try
            {
                var command = "Get-NetFirewallProfile | Select-Object Name, LogBlocked, LogAllowed, LogFileName, LogMaxSizeKilobytes | ConvertTo-Json";
                var output = await ExecutePowerShellAsync(command);

                if (string.IsNullOrEmpty(output))
                {
                    return findings;
                }

                var profiles = ParseFirewallProfiles(output);
                // LogBlocked values from PowerShell: 0=NotConfigured, 1=False (not logging), 2=True (logging)
                var profilesWithNoLogging = profiles.Where(p =>
                    p.LogBlocked == 1).ToList();

                if (profilesWithNoLogging.Any())
                {
                    var profileNames = string.Join(", ", profilesWithNoLogging.Select(p => p.Name));

                    findings.Add(Finding.Create(
                        id: "AST-FW-WIN-003",
                        title: $"Windows Firewall logging disabled on {profilesWithNoLogging.Count} profile(s)",
                        severity: "low",
                        confidence: "high",
                        recommendation: "Enable firewall logging for security monitoring:\n" +
                            "1. Open Windows Defender Firewall with Advanced Security\n" +
                            "2. For each profile (Domain, Private, Public):\n" +
                            "   a. Right-click → Properties\n" +
                            "   b. Click 'Customize' under Logging\n" +
                            "   c. Set 'Log dropped packets' to 'Yes'\n" +
                            "   d. Optionally: Set 'Log successful connections' to 'Yes'\n" +
                            "   e. Set appropriate size limit (default: 4096 KB)\n" +
                            "   f. Note log file path (default: %SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log)\n" +
                            "3. Via PowerShell for all profiles:\n" +
                            "   Set-NetFirewallProfile -All -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 16384\n" +
                            "4. Configure log rotation and archival\n" +
                            "5. Integrate logs with SIEM/monitoring solution"
                    )
                    .WithDescription(
                        $"Firewall logging is disabled for: {profileNames}. Without logging:\n" +
                        "• No audit trail of blocked connection attempts\n" +
                        "• Unable to detect port scanning or brute-force attacks\n" +
                        "• Difficult to troubleshoot firewall rule issues\n" +
                        "• No evidence for incident response or forensics\n" +
                        "• Cannot identify suspicious traffic patterns\n\n" +
                        "Enabling firewall logging provides:\n" +
                        "• Visibility into blocked connection attempts\n" +
                        "• Evidence of attack patterns and tactics\n" +
                        "• Data for security monitoring and alerting\n" +
                        "• Audit trail for compliance requirements\n\n" +
                        "Recommendation: Enable 'Log dropped packets' at minimum. " +
                        "For high-security environments, also enable 'Log successful connections'."
                    )
                    .WithEvidence(
                        type: "config",
                        value: $"Profiles without logging: {profileNames}",
                        context: "LogBlocked: False"
                    )
                    .WithReferences(
                        "https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/configure-the-windows-firewall-log",
                        "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"
                    )
                    .WithAffectedComponent("Windows Firewall - Logging Configuration"));

                    Log.Warning("{CheckName}: Firewall logging disabled on {Profiles}", Name, profileNames);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Failed to check firewall logging", Name);
            }

            return findings;
        }

        /// <summary>
        /// Execute PowerShell command and return output
        /// </summary>
        private async Task<string> ExecutePowerShellAsync(string command)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -Command \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null)
                {
                    Log.Warning("{CheckName}: Failed to start PowerShell process", Name);
                    return string.Empty;
                }

                var output = await process.StandardOutput.ReadToEndAsync();
                var error = await process.StandardError.ReadToEndAsync();

                await process.WaitForExitAsync();

                if (process.ExitCode != 0)
                {
                    Log.Warning("{CheckName}: PowerShell command failed with exit code {ExitCode}: {Error}", 
                        Name, process.ExitCode, error);
                    return string.Empty;
                }

                return output.Trim();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Failed to execute PowerShell command", Name);
                return string.Empty;
            }
        }

        /// <summary>
        /// Parse firewall profiles from PowerShell JSON output
        /// </summary>
        private List<FirewallProfile> ParseFirewallProfiles(string json)
        {
            try
            {
                var options = new JsonSerializerOptions 
                { 
                    PropertyNameCaseInsensitive = true 
                };

                json = json.Trim();

                // Handle array or single object
                if (json.StartsWith("["))
                {
                    return JsonSerializer.Deserialize<List<FirewallProfile>>(json, options) 
                        ?? new List<FirewallProfile>();
                }
                else if (json.StartsWith("{"))
                {
                    var profile = JsonSerializer.Deserialize<FirewallProfile>(json, options);
                    return profile != null ? new List<FirewallProfile> { profile } : new List<FirewallProfile>();
                }

                Log.Warning("{CheckName}: Unexpected JSON format for firewall profiles", Name);
                return new List<FirewallProfile>();
            }
            catch (JsonException ex)
            {
                Log.Warning(ex, "{CheckName}: Failed to parse firewall profiles JSON, attempting manual parse", Name);
                return ParseFirewallProfilesManual(json);
            }
        }

        /// <summary>
        /// Manual parsing fallback for firewall profiles
        /// </summary>
        private List<FirewallProfile> ParseFirewallProfilesManual(string json)
        {
            var profiles = new List<FirewallProfile>();

            try
            {
                // Simple regex-based extraction as fallback
                var items = json.Contains("},{") 
                    ? json.Split(new[] { "},{" }, StringSplitOptions.RemoveEmptyEntries)
                    : new[] { json };

                foreach (var item in items)
                {
                    var profile = new FirewallProfile();

                    var nameMatch = Regex.Match(item, @"""Name"":\s*""([^""]+)""");
                    if (nameMatch.Success) profile.Name = nameMatch.Groups[1].Value;

                    // Enabled is returned as numeric (0/1) by PowerShell
                    var enabledMatch = Regex.Match(item, @"""Enabled"":\s*(\d+)");
                    if (enabledMatch.Success) profile.Enabled = int.Parse(enabledMatch.Groups[1].Value);

                    // DefaultInboundAction is returned as numeric (0=Block, 1=Allow, 2=Max) by PowerShell
                    var inboundMatch = Regex.Match(item, @"""DefaultInboundAction"":\s*(\d+)");
                    if (inboundMatch.Success) profile.DefaultInboundAction = int.Parse(inboundMatch.Groups[1].Value);

                    // DefaultOutboundAction is returned as numeric (0=Block, 1=Allow, 2=Max) by PowerShell
                    var outboundMatch = Regex.Match(item, @"""DefaultOutboundAction"":\s*(\d+)");
                    if (outboundMatch.Success) profile.DefaultOutboundAction = int.Parse(outboundMatch.Groups[1].Value);

                    // LogBlocked is returned as numeric (0=NotConfigured, 1=False, 2=True) by PowerShell
                    var logBlockedMatch = Regex.Match(item, @"""LogBlocked"":\s*(\d+)");
                    if (logBlockedMatch.Success) profile.LogBlocked = int.Parse(logBlockedMatch.Groups[1].Value);

                    if (!string.IsNullOrEmpty(profile.Name))
                    {
                        profiles.Add(profile);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Manual parsing of firewall profiles failed", Name);
            }

            return profiles;
        }

        /// <summary>
        /// Parse firewall rules from PowerShell JSON output
        /// </summary>
        private List<FirewallRule> ParseFirewallRules(string json)
        {
            try
            {
                var options = new JsonSerializerOptions 
                { 
                    PropertyNameCaseInsensitive = true 
                };

                json = json.Trim();

                // Handle array or single object
                if (json.StartsWith("["))
                {
                    return JsonSerializer.Deserialize<List<FirewallRule>>(json, options) 
                        ?? new List<FirewallRule>();
                }
                else if (json.StartsWith("{"))
                {
                    var rule = JsonSerializer.Deserialize<FirewallRule>(json, options);
                    return rule != null ? new List<FirewallRule> { rule } : new List<FirewallRule>();
                }

                return new List<FirewallRule>();
            }
            catch (JsonException ex)
            {
                Log.Warning(ex, "{CheckName}: Failed to parse firewall rules JSON, attempting manual parse", Name);
                return ParseFirewallRulesManual(json);
            }
        }

        /// <summary>
        /// Manual parsing fallback for firewall rules
        /// </summary>
        private List<FirewallRule> ParseFirewallRulesManual(string json)
        {
            var rules = new List<FirewallRule>();

            try
            {
                var items = json.Contains("},{")
                    ? json.Split(new[] { "},{" }, StringSplitOptions.RemoveEmptyEntries)
                    : new[] { json };

                foreach (var item in items)
                {
                    var rule = new FirewallRule();

                    var nameMatch = Regex.Match(item, @"""RuleName"":\s*""([^""]+)""");
                    if (!nameMatch.Success) nameMatch = Regex.Match(item, @"""DisplayName"":\s*""([^""]+)""");
                    if (nameMatch.Success) rule.DisplayName = nameMatch.Groups[1].Value;

                    var remoteAddrMatch = Regex.Match(item, @"""RemoteAddress"":\s*""?([^"",}]+)""?");
                    if (remoteAddrMatch.Success) rule.RemoteAddress = remoteAddrMatch.Groups[1].Value.Trim();

                    var localPortMatch = Regex.Match(item, @"""LocalPort"":\s*""?([^"",}]+)""?");
                    if (localPortMatch.Success) rule.LocalPort = localPortMatch.Groups[1].Value.Trim();

                    if (!string.IsNullOrEmpty(rule.DisplayName))
                    {
                        rules.Add(rule);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Manual parsing of firewall rules failed", Name);
            }

            return rules;
        }

        /// <summary>
        /// Check if address is "Any" (0.0.0.0/0 or ::/0)
        /// </summary>
        private bool IsAnyAddress(string? address)
        {
            if (string.IsNullOrEmpty(address))
                return false;

            var normalized = address.Trim().ToLowerInvariant();
            return normalized == "any" || 
                   normalized == "0.0.0.0/0" || 
                   normalized == "::/0" ||
                   normalized.Contains("any");
        }

        /// <summary>
        /// Get critical port information if port is in critical list
        /// </summary>
        private KeyValuePair<string, string>? GetCriticalPortInfo(string? port)
        {
            if (string.IsNullOrEmpty(port) || port == "Any")
                return null;

            // Handle port ranges or comma-separated lists
            var ports = port.Split(new[] { ',', '-' }, StringSplitOptions.RemoveEmptyEntries)
                           .Select(p => p.Trim());

            foreach (var p in ports)
            {
                if (CriticalPorts.TryGetValue(p, out var service))
                {
                    return new KeyValuePair<string, string>(p, service);
                }
            }

            return null;
        }

        /// <summary>
        /// Firewall profile data structure
        /// </summary>
        private class FirewallProfile
        {
            public string Name { get; set; } = string.Empty;

            // PowerShell returns 0/1 as numbers, not true/false
            public int Enabled { get; set; }

            // NET_FW_ACTION: 0=Block, 1=Allow, 2=Max (PowerShell returns numeric enum values)
            [JsonPropertyName("DefaultInboundAction")]
            public int DefaultInboundAction { get; set; }

            [JsonPropertyName("DefaultOutboundAction")]
            public int DefaultOutboundAction { get; set; }

            // PowerShell returns numbers (0=NotConfigured, 1=False, 2=True)
            [JsonPropertyName("LogBlocked")]
            public int LogBlocked { get; set; }

            [JsonPropertyName("LogAllowed")]
            public int LogAllowed { get; set; }
        }

        /// <summary>
        /// Firewall rule data structure
        /// </summary>
        private class FirewallRule
        {
            [JsonPropertyName("RuleName")]
            public string DisplayName { get; set; } = string.Empty;

            public string? RemoteAddress { get; set; }
            public string? LocalPort { get; set; }
        }

        /// <summary>
        /// Firewall service data structure
        /// PowerShell returns Status as ServiceControllerStatus enum (Running = 4)
        /// and StartType as ServiceStartMode enum (Automatic = 2)
        /// </summary>
        private class FirewallService
        {
            // ServiceControllerStatus: Stopped=1, StartPending=2, StopPending=3, Running=4, ContinuePending=5, PausePending=6, Paused=7
            public int Status { get; set; }

            // ServiceStartMode: Boot=0, System=1, Automatic=2, Manual=3, Disabled=4
            public int StartType { get; set; }
        }

        /// <summary>
        /// Dangerous rule information for reporting
        /// </summary>
        private class DangerousRuleInfo
        {
            public string RuleName { get; set; } = string.Empty;
            public string Port { get; set; } = string.Empty;
            public string Service { get; set; } = string.Empty;
        }
    }
}