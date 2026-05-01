using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Models;

namespace Asterion.Checks.Linux
{
    /// <summary>
    /// Linux Firewall Security Check
    /// Analyzes host-based firewall configurations on Linux systems
    /// 
    /// Supported Firewalls:
    /// - iptables (legacy netfilter)
    /// - nftables (modern netfilter)
    /// - UFW (Uncomplicated Firewall - Ubuntu/Debian)
    /// - firewalld (RHEL/CentOS/Fedora)
    /// 
    /// Findings:
    /// - AST-FW-LNX-001: Firewall disabled or not running
    /// - AST-FW-LNX-002: Default policy ACCEPT (permissive)
    /// - AST-FW-LNX-003: Permissive rules allowing wide access
    /// - AST-FW-LNX-004: No active firewall rules configured
    /// 
    /// Execution Modes:
    /// - Local: Requires Linux OS and ideally root privileges
    /// - Remote: Uses SSH credentials if provided (requires sudo access)
    /// </summary>
    public class LinuxFirewallCheck : BaseCheck
    {
        public override string Name => "Linux Firewall Security Check";
        
        public override CheckCategory Category => CheckCategory.Linux;
        
        public override string Description => 
            "Audits Linux host-based firewall configurations (iptables, nftables, UFW, firewalld). " +
            "Detects disabled firewalls, permissive policies, and overly broad rules. " +
            "Supports both local and remote SSH-based auditing.";

        public override bool RequiresAuthentication => false; // Can run without auth, but limited
        public override bool RequiresAggressiveMode => false;

        public LinuxFirewallCheck(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var findings = new List<Finding>();

            // Check if this is a local check
            bool isLocal = targets.Contains("localhost") || 
                          targets.Contains("127.0.0.1") || 
                          targets.Any(t => t == Environment.MachineName);

            if (isLocal)
            {
                Log.Information("[{CheckName}] Performing local Linux firewall audit", Name);
                findings.AddRange(await CheckLocalFirewallAsync());
            }
            else if (!string.IsNullOrEmpty(options.SshCredentials))
            {
                // Remote checks via SSH
                Log.Information("[{CheckName}] Performing remote firewall checks via SSH", Name);
                foreach (var target in targets)
                {
                    findings.AddRange(await CheckRemoteFirewallViaSshAsync(target, options));
                }
            }
            else
            {
                Log.Debug("[{CheckName}] Skipped: Not local and no SSH credentials provided", Name);
            }

            LogExecution(targets.Count, findings.Count);
            return findings;
        }

        #region Local Firewall Checks

        /// <summary>
        /// Perform all local firewall checks
        /// </summary>
        private async Task<List<Finding>> CheckLocalFirewallAsync()
        {
            var findings = new List<Finding>();

            try
            {
                // Check if running as root
                bool isRoot = await IsRootAsync();
                if (!isRoot)
                {
                    Log.Warning("[{CheckName}] Not running as root - firewall check may be incomplete", Name);
                }

                // Check each firewall system
                findings.AddRange(await CheckIptablesAsync());
                findings.AddRange(await CheckNftablesAsync());
                findings.AddRange(await CheckUfwAsync());
                findings.AddRange(await CheckFirewalldAsync());

                // If no findings and no firewall detected, create a finding
                if (!findings.Any())
                {
                    Log.Information("[{CheckName}] No firewall issues detected", Name);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error during local firewall check", Name);
            }

            return findings;
        }

        #endregion

        #region iptables Checks

        private async Task<List<Finding>> CheckIptablesAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("[{CheckName}] Checking iptables configuration...", Name);

                // Check if iptables exists
                if (!await CommandExistsAsync("iptables"))
                {
                    Log.Debug("iptables not found on system");
                    return findings;
                }

                // Get iptables rules
                var (success, output) = await ExecuteCommandAsync("iptables", "-L -n -v");
                if (!success)
                {
                    Log.Debug("Failed to query iptables (may need root)");
                    return findings;
                }

                // Parse output
                var lines = output.Split('\n');
                
                // Check INPUT chain policy
                var inputChainLine = lines.FirstOrDefault(l => l.StartsWith("Chain INPUT"));
                if (inputChainLine != null)
                {
                    if (inputChainLine.Contains("policy ACCEPT"))
                    {
                        // Count number of rules in INPUT chain
                        int ruleCount = CountRulesInChain(lines, "INPUT");

                        if (ruleCount < 5) // Few rules and default ACCEPT = bad
                        {
                            findings.Add(Finding.Create(
                                id: "AST-FW-LNX-002",
                                title: "iptables default policy ACCEPT on INPUT chain",
                                severity: "high",
                                confidence: "high",
                                recommendation: "Change iptables default policy to DROP and explicitly allow required services:\n" +
                                    "1. Set default DROP policy: iptables -P INPUT DROP\n" +
                                    "2. Allow established connections: iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n" +
                                    "3. Allow localhost: iptables -A INPUT -i lo -j ACCEPT\n" +
                                    "4. Allow SSH (or required services): iptables -A INPUT -p tcp --dport 22 -j ACCEPT\n" +
                                    "5. Save rules: iptables-save > /etc/iptables/rules.v4\n" +
                                    "6. Consider using ufw or firewalld for easier management"
                            )
                            .WithDescription(
                                "The INPUT chain has a default policy of ACCEPT with few explicit rules. " +
                                "This means all incoming traffic is allowed by default unless explicitly blocked, which is a weak security posture. " +
                                "A deny-by-default approach (DROP policy) is recommended where only necessary traffic is explicitly allowed."
                            )
                            .WithEvidence(
                                type: "config",
                                value: inputChainLine.Trim(),
                                context: $"Rule count in INPUT chain: {ruleCount}"
                            )
                            .WithReferences(
                                "https://wiki.archlinux.org/title/Iptables",
                                "https://www.digitalocean.com/community/tutorials/iptables-essentials-common-firewall-rules-and-commands"
                            )
                            .WithAffectedComponent($"Host: {Environment.MachineName}, Firewall: iptables"));
                        }
                    }
                }

                // Check for overly permissive rules
                var permissiveRules = FindPermissiveRules(lines);
                if (permissiveRules.Any())
                {
                    findings.Add(Finding.Create(
                        id: "AST-FW-LNX-003",
                        title: "Permissive iptables rules allowing wide access",
                        severity: "medium",
                        confidence: "high",
                        recommendation: "Review and restrict iptables rules:\n" +
                            "1. Identify which services need internet access\n" +
                            "2. Replace 0.0.0.0/0 rules with specific IP ranges when possible\n" +
                            "3. Use '-s <trusted_ip>' to limit sources\n" +
                            "4. Consider using connection tracking (-m state --state NEW)\n" +
                            "5. Example: iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT"
                    )
                    .WithDescription(
                        $"Found {permissiveRules.Count} iptables rules that allow broad access from any source (0.0.0.0/0 or 'anywhere'). " +
                        "These rules may unnecessarily expose services to the entire internet. " +
                        "Best practice is to restrict source IPs to known trusted networks when possible."
                    )
                    .WithEvidence(
                        type: "config",
                        value: string.Join("\n", permissiveRules.Take(5)),
                        context: $"Total permissive rules: {permissiveRules.Count}"
                    )
                    .WithReferences(
                        "https://www.cyberciti.biz/tips/linux-iptables-examples.html"
                    )
                    .WithAffectedComponent($"Host: {Environment.MachineName}, Firewall: iptables"));
                }

                // Check if firewall is effectively disabled (no rules)
                int totalRules = lines.Count(l => !string.IsNullOrWhiteSpace(l) && 
                                                  !l.StartsWith("Chain") && 
                                                  !l.StartsWith("pkts") &&
                                                  !l.StartsWith("target"));
                
                if (totalRules < 3)
                {
                    findings.Add(Finding.Create(
                        id: "AST-FW-LNX-004",
                        title: "No active iptables firewall rules detected",
                        severity: "high",
                        confidence: "high",
                        recommendation: "Configure iptables firewall:\n" +
                            "1. Create basic firewall rules (see AST-FW-LNX-002 recommendation)\n" +
                            "2. Or install ufw: apt install ufw && ufw enable\n" +
                            "3. Or install firewalld: yum install firewalld && systemctl enable firewalld\n" +
                            "4. Ensure firewall persists across reboots"
                    )
                    .WithDescription(
                        "iptables is installed but no active rules were found. " +
                        "The system may have no host-based firewall protection, leaving all ports potentially accessible."
                    )
                    .WithEvidence(
                        type: "config",
                        value: "iptables -L output shows no meaningful rules",
                        context: "Empty or default iptables configuration"
                    )
                    .WithReferences(
                        "https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-using-iptables-on-ubuntu-14-04"
                    )
                    .WithAffectedComponent($"Host: {Environment.MachineName}, Firewall: iptables"));
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking iptables", Name);
            }

            return findings;
        }

        #endregion

        #region nftables Checks

        private async Task<List<Finding>> CheckNftablesAsync()
        {
            var findings = new List<Finding>();

            try
            {
                Log.Debug("[{CheckName}] Checking nftables configuration...", Name);

                if (!await CommandExistsAsync("nft"))
                {
                    Log.Debug("nftables not found on system");
                    return findings;
                }

                var (success, output) = await ExecuteCommandAsync("nft", "list ruleset");
                if (!success)
                {
                    Log.Debug("Failed to query nftables");
                    return findings;
                }

                // Check if nftables is active but has no rules
                if (string.IsNullOrWhiteSpace(output) || output.Trim().Length < 50)
                {
                    findings.Add(Finding.Create(
                        id: "AST-FW-LNX-004",
                        title: "nftables installed but no rules configured",
                        severity: "medium",
                        confidence: "high",
                        recommendation: "Configure nftables firewall:\n" +
                            "1. Create a basic nftables configuration file\n" +
                            "2. Example location: /etc/nftables.conf\n" +
                            "3. Start service: systemctl enable nftables && systemctl start nftables\n" +
                            "4. Or switch to iptables/ufw if preferred"
                    )
                    .WithDescription(
                        "nftables (the modern replacement for iptables) is installed but has no active rules. " +
                        "The system lacks host-based firewall protection. nftables provides better performance and " +
                        "syntax than legacy iptables, but requires configuration."
                    )
                    .WithEvidence(
                        type: "config",
                        value: "nft list ruleset returned empty",
                        context: "No nftables ruleset configured"
                    )
                    .WithReferences(
                        "https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes",
                        "https://wiki.archlinux.org/title/Nftables"
                    )
                    .WithAffectedComponent($"Host: {Environment.MachineName}, Firewall: nftables"));
                }
                else
                {
                    // Basic analysis of nftables output
                    if (output.Contains("accept") && output.Contains("0.0.0.0"))
                    {
                        Log.Information("[{CheckName}] nftables has permissive rules - detailed analysis not implemented", Name);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking nftables", Name);
            }

            return findings;
        }

        #endregion

        #region UFW Checks

        private async Task<List<Finding>> CheckUfwAsync()
        {
            var findings = new List<Finding>();

            try
            {
                if (!await CommandExistsAsync("ufw"))
                {
                    Log.Debug("UFW not found on system");
                    return findings;
                }

                Log.Debug("[{CheckName}] Checking UFW status...", Name);

                var (success, output) = await ExecuteCommandAsync("ufw", "status");
                if (!success)
                {
                    return findings;
                }

                if (output.Contains("Status: inactive"))
                {
                    findings.Add(Finding.Create(
                        id: "AST-FW-LNX-001",
                        title: "UFW firewall is disabled",
                        severity: "high",
                        confidence: "high",
                        recommendation: "Enable UFW firewall:\n" +
                            "1. Review and configure basic rules first\n" +
                            "2. Allow SSH to avoid lockout: ufw allow 22/tcp\n" +
                            "3. Enable firewall: ufw enable\n" +
                            "4. Check status: ufw status verbose\n" +
                            "5. Configure additional rules as needed"
                    )
                    .WithDescription(
                        "UFW (Uncomplicated Firewall) is installed but currently disabled. " +
                        "UFW provides a user-friendly interface to iptables/nftables. " +
                        "With the firewall disabled, the system has no active host-based firewall protection."
                    )
                    .WithEvidence(
                        type: "service",
                        value: "ufw status: inactive",
                        context: "UFW service is disabled"
                    )
                    .WithReferences(
                        "https://help.ubuntu.com/community/UFW",
                        "https://www.digitalocean.com/community/tutorials/how-to-setup-a-firewall-with-ufw-on-an-ubuntu-and-debian-cloud-server"
                    )
                    .WithAffectedComponent($"Host: {Environment.MachineName}, Firewall: UFW"));
                }
                else if (output.Contains("Status: active"))
                {
                    Log.Information("[{CheckName}] UFW is active", Name);
                    
                    // Check for default policies
                    if (output.Contains("Default: allow (incoming)"))
                    {
                        findings.Add(Finding.Create(
                            id: "AST-FW-LNX-002",
                            title: "UFW default policy allows incoming traffic",
                            severity: "medium",
                            confidence: "high",
                            recommendation: "Change UFW default policy to deny:\n" +
                                "1. Set default deny: ufw default deny incoming\n" +
                                "2. Set default allow outgoing: ufw default allow outgoing\n" +
                                "3. Explicitly allow required services (e.g., ufw allow 22/tcp)\n" +
                                "4. Reload: ufw reload"
                        )
                        .WithDescription(
                            "UFW is active but configured with a default policy to allow incoming traffic. " +
                            "This is less secure than deny-by-default. Best practice is to deny all incoming traffic " +
                            "by default and explicitly allow only required services."
                        )
                        .WithEvidence(
                            type: "config",
                            value: "Default: allow (incoming)",
                            context: "UFW status output"
                        )
                        .WithAffectedComponent($"Host: {Environment.MachineName}, Firewall: UFW"));
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking UFW", Name);
            }

            return findings;
        }

        #endregion

        #region firewalld Checks

        private async Task<List<Finding>> CheckFirewalldAsync()
        {
            var findings = new List<Finding>();

            try
            {
                if (!await CommandExistsAsync("firewall-cmd"))
                {
                    Log.Debug("firewalld not found on system");
                    return findings;
                }

                Log.Debug("[{CheckName}] Checking firewalld status...", Name);

                var (success, output) = await ExecuteCommandAsync("firewall-cmd", "--state");
                
                if (!success || output.Contains("not running"))
                {
                    findings.Add(Finding.Create(
                        id: "AST-FW-LNX-001",
                        title: "firewalld is not running",
                        severity: "high",
                        confidence: "high",
                        recommendation: "Enable firewalld:\n" +
                            "1. Start firewalld: systemctl start firewalld\n" +
                            "2. Enable on boot: systemctl enable firewalld\n" +
                            "3. Check status: firewall-cmd --state\n" +
                            "4. Configure zones and services as needed"
                    )
                    .WithDescription(
                        "firewalld (the default firewall management tool on RHEL/CentOS/Fedora) is installed but not running. " +
                        "firewalld provides zone-based firewall management with dynamic rule updates. " +
                        "With the service stopped, the system has no active host-based firewall."
                    )
                    .WithEvidence(
                        type: "service",
                        value: "firewall-cmd --state: not running",
                        context: "firewalld service is stopped"
                    )
                    .WithReferences(
                        "https://firewalld.org/documentation/",
                        "https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-using-firewalld-on-centos-8"
                    )
                    .WithAffectedComponent($"Host: {Environment.MachineName}, Firewall: firewalld"));
                }
                else if (output.Contains("running"))
                {
                    Log.Information("[{CheckName}] firewalld is active", Name);
                    
                    // Check default zone
                    var (zoneSuccess, zoneOutput) = await ExecuteCommandAsync("firewall-cmd", "--get-default-zone");
                    if (zoneSuccess && zoneOutput.Contains("public"))
                    {
                        // Check if public zone is too permissive
                        var (servicesSuccess, servicesOutput) = await ExecuteCommandAsync("firewall-cmd", "--zone=public --list-all");
                        if (servicesSuccess)
                        {
                            int serviceCount = servicesOutput.Split('\n')
                                .Count(l => l.Trim().StartsWith("services:"));
                            
                            if (serviceCount > 10)
                            {
                                Log.Information("[{CheckName}] firewalld public zone has many services enabled", Name);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking firewalld", Name);
            }

            return findings;
        }

        #endregion

        #region SSH Remote Checks

        private async Task<List<Finding>> CheckRemoteFirewallViaSshAsync(string target, ScanOptions options)
        {
            var findings = new List<Finding>();

            try
            {
                Log.Information("[{CheckName}] Checking firewall on {Target} via SSH", Name, target);

                // Parse SSH credentials using BaseCheck helper
                var (username, password, domain) = ParseCredentials(options.SshCredentials);
                
                if (username == null || password == null)
                {
                    Log.Warning("[{CheckName}] Invalid SSH credentials format", Name);
                    return findings;
                }

                // Use SSH.NET library to connect and run commands
                using var client = new Renci.SshNet.SshClient(target, username, password);
                client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(_config.Ssh.TimeoutSeconds);
                
                await Task.Run(() => client.Connect());

                if (!client.IsConnected)
                {
                    Log.Warning("[{CheckName}] Failed to connect to {Target} via SSH", Name, target);
                    return findings;
                }

                // Run iptables check
                var result = client.RunCommand("sudo iptables -L -n 2>/dev/null || echo 'PERMISSION_DENIED'");
                if (result.Result.Contains("PERMISSION_DENIED") || result.ExitStatus != 0)
                {
                    Log.Warning("[{CheckName}] Cannot check firewall on {Target} - insufficient privileges", Name, target);
                }
                else
                {
                    // Basic parsing
                    if (result.Result.Contains("policy ACCEPT") && result.Result.Split('\n').Length < 20)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-FW-LNX-002",
                            title: $"Permissive firewall detected on {target}",
                            severity: "medium",
                            confidence: "medium",
                            recommendation: "Review and harden firewall on remote host:\n" +
                                "1. Change default policy to DROP\n" +
                                "2. Explicitly allow required services\n" +
                                "3. See local check recommendations for detailed steps"
                        )
                        .WithDescription(
                            $"Remote host {target} appears to have permissive iptables rules or minimal firewall configuration. " +
                            "The default policy is ACCEPT with few explicit rules, which may expose services unnecessarily."
                        )
                        .WithEvidence(
                            type: "config",
                            value: "iptables policy ACCEPT with few rules (via SSH)",
                            context: $"Remote host: {target}"
                        )
                        .WithAffectedComponent($"Host: {target}"));
                    }
                }

                client.Disconnect();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking firewall via SSH on {Target}", Name, target);
            }

            return findings;
        }

        #endregion

        #region Helper Methods

        // Keep existing CountRulesInChain and FindPermissiveRules methods

        private int CountRulesInChain(string[] lines, string chainName)
        {
            bool inChain = false;
            int count = 0;

            foreach (var line in lines)
            {
                if (line.StartsWith($"Chain {chainName}"))
                {
                    inChain = true;
                    continue;
                }
                
                if (line.StartsWith("Chain ") && !line.StartsWith($"Chain {chainName}"))
                {
                    inChain = false;
                }

                if (inChain && !string.IsNullOrWhiteSpace(line) && 
                    !line.StartsWith("pkts") && !line.StartsWith("Chain"))
                {
                    count++;
                }
            }

            return count;
        }

        private List<string> FindPermissiveRules(string[] lines)
        {
            var permissive = new List<string>();

            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (line.StartsWith("Chain") || line.StartsWith("pkts") || line.StartsWith("target")) continue;

                // Look for 0.0.0.0/0 source or "anywhere"
                if (line.Contains("0.0.0.0/0") || line.Contains("anywhere"))
                {
                    // Exclude established connections (those are OK)
                    if (!line.Contains("ESTABLISHED") && !line.Contains("RELATED") && 
                        !line.Contains("state ESTABLISHED") && !line.Contains("ctstate ESTABLISHED"))
                    {
                        permissive.Add(line.Trim());
                    }
                }
            }

            return permissive;
        }

        #endregion
    }
}