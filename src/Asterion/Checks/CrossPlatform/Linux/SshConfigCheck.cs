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
    /// Linux SSH Daemon Configuration Security Check
    /// 
    /// Analyzes /etc/ssh/sshd_config for common security misconfigurations:
    /// - Root login permissions
    /// - Password authentication settings
    /// - Weak cryptographic algorithms (ciphers, MACs, key exchange)
    /// - Empty password permissions
    /// - X11 forwarding risks
    /// 
    /// Findings:
    /// - AST-SSH-LNX-001: Root login via SSH is permitted
    /// - AST-SSH-LNX-002: Weak SSH cipher/MAC algorithms enabled
    /// - AST-SSH-LNX-003: Password authentication without additional protection
    /// - AST-SSH-LNX-004: Empty passwords allowed (CRITICAL)
    /// - AST-SSH-LNX-005: X11 forwarding enabled
    /// 
    /// Requirements:
    /// - Linux operating system
    /// - Read access to /etc/ssh/sshd_config (may require root/sudo)
    /// </summary>
    public class SshConfigCheck : BaseCheck
    {
        private const string SshConfigPath = "/etc/ssh/sshd_config";

        public override string Name => "SSH Configuration Check";
        
        public override CheckCategory Category => CheckCategory.Linux;
        
        public override string Description => 
            "Audits SSH daemon configuration for security weaknesses including root login, " +
            "weak cryptographic algorithms, password authentication risks, and dangerous features. " +
            "Checks /etc/ssh/sshd_config against CIS Linux Benchmark recommendations.";

        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        // Weak/obsolete ciphers that should not be used
        private static readonly HashSet<string> WeakCiphers = new(StringComparer.OrdinalIgnoreCase)
        {
            "3des-cbc",          // Triple DES (obsolete, slow)
            "aes128-cbc",        // CBC mode (vulnerable to padding oracle)
            "aes192-cbc",
            "aes256-cbc",
            "des-cbc",           // DES (broken)
            "rijndael-cbc@lysator.liu.se",
            "arcfour",           // RC4 (broken)
            "arcfour128",
            "arcfour256",
            "cast128-cbc",
            "blowfish-cbc"
        };

        // Weak/obsolete MACs that should not be used
        private static readonly HashSet<string> WeakMacs = new(StringComparer.OrdinalIgnoreCase)
        {
            "hmac-md5",          // MD5 (broken)
            "hmac-md5-96",
            "hmac-sha1-96",      // Truncated SHA1
            "hmac-ripemd160",
            "umac-64@openssh.com" // 64-bit (too short)
        };

        // Weak key exchange algorithms
        private static readonly HashSet<string> WeakKex = new(StringComparer.OrdinalIgnoreCase)
        {
            "diffie-hellman-group1-sha1",         // 1024-bit DH (broken)
            "diffie-hellman-group14-sha1",        // SHA1 (weak)
            "diffie-hellman-group-exchange-sha1"  // SHA1 (weak)
        };

        public SshConfigCheck(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var findings = new List<Finding>();

            // Note: This is a local check, 'targets' parameter is not used
            // We're auditing the local SSH configuration

            Log.Information("[{CheckName}] Analyzing SSH daemon configuration", Name);

            try
            {
                if (!await FileExistsAsync(SshConfigPath))
                {
                    Log.Debug("{CheckName}: SSH config not found at {Path}", Name, SshConfigPath);
                    LogExecution(0, 0);
                    return findings;
                }

                var content = await ReadFileAsync(SshConfigPath);
                var lines = content.Split('\n');

                Log.Debug("{CheckName}: Parsing {Lines} lines from {Path}", Name, lines.Length, SshConfigPath);

                // Parse SSH config
                var config = ParseSshConfig(lines);

                // Check PermitRootLogin
                CheckRootLogin(config, findings);

                // Check PasswordAuthentication
                CheckPasswordAuthentication(config, findings);

                // Check PermitEmptyPasswords (CRITICAL)
                CheckEmptyPasswords(config, findings);

                // Check Ciphers
                CheckCiphers(config, findings);

                // Check MACs
                CheckMacs(config, findings);

                // Check KexAlgorithms
                CheckKexAlgorithms(config, findings);

                // Check X11Forwarding
                CheckX11Forwarding(config, findings);

                if (findings.Count == 0)
                {
                    Log.Information("{CheckName}: No SSH configuration issues detected ✓", Name);
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                Log.Warning("{CheckName}: Permission denied reading {Path}: {Message}", 
                    Name, SshConfigPath, ex.Message);
                Log.Information("Run as root or with sudo for complete SSH configuration checks");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: Error during SSH configuration check", Name);
            }

            LogExecution(1, findings.Count); // 1 target = local system
            return findings;
        }

        /// <summary>
        /// Check PermitRootLogin setting
        /// </summary>
        private void CheckRootLogin(Dictionary<string, string> config, List<Finding> findings)
        {
            if (config.TryGetValue("PermitRootLogin", out var permitRoot))
            {
                if (permitRoot.Equals("yes", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(Finding.Create(
                        id: "AST-SSH-LNX-001",
                        title: "Root login via SSH is permitted",
                        severity: "high",
                        confidence: "high",
                        recommendation: "Disable direct root login via SSH:\n" +
                            "1. Edit /etc/ssh/sshd_config\n" +
                            "2. Set: PermitRootLogin no\n" +
                            "   OR (better): PermitRootLogin prohibit-password (keys only)\n" +
                            "3. Restart SSH: sudo systemctl restart sshd\n" +
                            "4. Use 'su' or 'sudo' from regular user accounts for root access\n" +
                            "5. Test login with regular user BEFORE disconnecting current session"
                    )
                    .WithDescription(
                        "The SSH daemon is configured to allow direct root login (PermitRootLogin yes). " +
                        "This is a significant security risk because:\n" +
                        "• Attackers can target the root account directly with brute-force attacks\n" +
                        "• There's no audit trail of who accessed root (all logs show 'root')\n" +
                        "• Increases the attack surface for privilege escalation\n" +
                        "• Violates the principle of least privilege\n\n" +
                        "Even with key-based authentication, allowing direct root login is discouraged. " +
                        "Best practice is to login as a regular user and use 'sudo' for privileged operations."
                    )
                    .WithEvidence(
                        type: "config",
                        value: $"PermitRootLogin {permitRoot}",
                        context: $"File: {SshConfigPath}"
                    )
                    .WithReferences(
                        "https://linux.die.net/man/5/sshd_config",
                        "https://www.ssh.com/academy/ssh/sshd_config",
                        "https://www.cisecurity.org/benchmark/distribution_independent_linux"
                    )
                    .WithAffectedComponent("SSH Daemon (sshd)"));

                    Log.Warning("{CheckName}: Root login via SSH is permitted", Name);
                }
                else if (permitRoot.Equals("without-password", StringComparison.OrdinalIgnoreCase) ||
                        permitRoot.Equals("prohibit-password", StringComparison.OrdinalIgnoreCase))
                {
                    Log.Information("{CheckName}: Root login restricted to key-based auth (acceptable)", Name);
                }
                else if (permitRoot.Equals("forced-commands-only", StringComparison.OrdinalIgnoreCase))
                {
                    Log.Information("{CheckName}: Root login allowed only for forced commands (restricted)", Name);
                }
            }
            else
            {
                Log.Debug("{CheckName}: PermitRootLogin not explicitly set (using system default)", Name);
            }
        }

        /// <summary>
        /// Check password authentication settings
        /// </summary>
        private void CheckPasswordAuthentication(Dictionary<string, string> config, List<Finding> findings)
        {
            if (config.TryGetValue("PasswordAuthentication", out var passAuth))
            {
                if (passAuth.Equals("yes", StringComparison.OrdinalIgnoreCase))
                {
                    // Check if there are additional protections
                    bool hasChallengeResponse = config.TryGetValue("ChallengeResponseAuthentication", out var cra) &&
                                               cra.Equals("yes", StringComparison.OrdinalIgnoreCase);
                    
                    bool hasPubkeyAuth = config.TryGetValue("PubkeyAuthentication", out var pka) &&
                                        pka.Equals("yes", StringComparison.OrdinalIgnoreCase);

                    // Password auth without MFA is concerning
                    if (!hasChallengeResponse)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-SSH-LNX-003",
                            title: "Password authentication enabled without additional protection",
                            severity: "medium",
                            confidence: "high",
                            recommendation: "Harden SSH authentication:\n" +
                                "1. Edit /etc/ssh/sshd_config\n" +
                                "2. PREFERRED: Set 'PasswordAuthentication no' (use keys only)\n" +
                                "3. Set: PubkeyAuthentication yes\n" +
                                "4. ALTERNATIVE: Enable 2FA/MFA:\n" +
                                "   - Install google-authenticator-libpam for TOTP\n" +
                                "   - Or use ChallengeResponseAuthentication with PAM\n" +
                                "5. Restrict access: AllowUsers or AllowGroups\n" +
                                "6. Install fail2ban to block brute-force attempts\n" +
                                "7. Restart SSH: sudo systemctl restart sshd"
                        )
                        .WithDescription(
                            "SSH is configured to allow password authentication without multi-factor authentication (MFA) " +
                            "or challenge-response mechanisms. This configuration:\n" +
                            "• Makes the system vulnerable to brute-force password attacks\n" +
                            "• Allows attackers unlimited login attempts (without fail2ban)\n" +
                            "• Provides no protection if passwords are weak or compromised\n" +
                            "• Is less secure than public key authentication\n\n" +
                            "While password authentication isn't always critical (depends on environment), " +
                            "best practice is to use SSH keys or enforce MFA for remote access."
                        )
                        .WithEvidence(
                            type: "config",
                            value: $"PasswordAuthentication {passAuth}",
                            context: $"File: {SshConfigPath}, ChallengeResponseAuthentication: {(hasChallengeResponse ? "yes" : "no/unset")}"
                        )
                        .WithReferences(
                            "https://www.ssh.com/academy/ssh/public-key-authentication",
                            "https://github.com/google/google-authenticator-libpam",
                            "https://www.fail2ban.org/"
                        )
                        .WithAffectedComponent("SSH Daemon (sshd)"));

                        Log.Warning("{CheckName}: Password authentication enabled without MFA", Name);
                    }
                }
            }
        }

        /// <summary>
        /// Check PermitEmptyPasswords (CRITICAL if enabled)
        /// </summary>
        private void CheckEmptyPasswords(Dictionary<string, string> config, List<Finding> findings)
        {
            if (config.TryGetValue("PermitEmptyPasswords", out var emptyPass))
            {
                if (emptyPass.Equals("yes", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(Finding.Create(
                        id: "AST-SSH-LNX-004",
                        title: "Empty passwords allowed for SSH authentication",
                        severity: "critical",
                        confidence: "high",
                        recommendation: "IMMEDIATE ACTION REQUIRED:\n" +
                            "1. Edit /etc/ssh/sshd_config\n" +
                            "2. Set: PermitEmptyPasswords no\n" +
                            "3. Restart SSH: sudo systemctl restart sshd\n" +
                            "4. Audit all user accounts for empty passwords:\n" +
                            "   sudo awk -F: '($2 == \"\") {print}' /etc/shadow\n" +
                            "5. Lock accounts with empty passwords:\n" +
                            "   sudo passwd -l <username>\n" +
                            "6. Set strong passwords for all accounts:\n" +
                            "   sudo passwd <username>"
                    )
                    .WithDescription(
                        "CRITICAL VULNERABILITY: The SSH daemon is configured to allow accounts with empty passwords " +
                        "to authenticate (PermitEmptyPasswords yes). This completely bypasses authentication and allows:\n" +
                        "• Anyone to login to accounts without passwords\n" +
                        "• Unauthenticated remote access to the system\n" +
                        "• Trivial privilege escalation if root has no password\n" +
                        "• Complete system compromise without any credentials\n\n" +
                        "This is one of the most severe SSH misconfigurations and must be fixed immediately."
                    )
                    .WithEvidence(
                        type: "config",
                        value: $"PermitEmptyPasswords {emptyPass}",
                        context: $"File: {SshConfigPath}"
                    )
                    .WithReferences(
                        "https://linux.die.net/man/5/sshd_config"
                    )
                    .WithAffectedComponent("SSH Daemon (sshd)"));

                    Log.Error("{CheckName}: CRITICAL - Empty passwords allowed for SSH!", Name);
                }
            }
        }

        /// <summary>
        /// Check for weak ciphers
        /// </summary>
        private void CheckCiphers(Dictionary<string, string> config, List<Finding> findings)
        {
            if (config.TryGetValue("Ciphers", out var ciphers))
            {
                var weakFound = CheckWeakAlgorithms(ciphers, WeakCiphers, "cipher");
                if (weakFound.Any())
                {
                    findings.Add(Finding.Create(
                        id: "AST-SSH-LNX-002",
                        title: "Weak SSH cipher algorithms enabled",
                        severity: "medium",
                        confidence: "high",
                        recommendation: "Update SSH cipher configuration:\n" +
                            "1. Edit /etc/ssh/sshd_config\n" +
                            "2. Set secure ciphers only:\n" +
                            "   Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n" +
                            "3. Restart SSH: sudo systemctl restart sshd\n" +
                            "4. Test from client: ssh -vv user@host\n" +
                            "   (check negotiated cipher in verbose output)\n" +
                            "5. Ensure all SSH clients support modern ciphers"
                    )
                    .WithDescription(
                        "The SSH daemon is configured to allow weak or obsolete cipher algorithms. Detected weak ciphers:\n" +
                        $"• {string.Join("\n• ", weakFound)}\n\n" +
                        "These ciphers have known vulnerabilities:\n" +
                        "• CBC-mode ciphers: Vulnerable to padding oracle attacks\n" +
                        "• 3DES: Obsolete, slow, and vulnerable to Sweet32 attack\n" +
                        "• RC4 (arcfour): Completely broken, trivial to crack\n" +
                        "• Blowfish: 64-bit block size (vulnerable to birthday attacks)\n\n" +
                        "Modern secure alternatives include ChaCha20-Poly1305 and AES-GCM/CTR modes."
                    )
                    .WithEvidence(
                        type: "config",
                        value: $"Weak ciphers: {string.Join(", ", weakFound)}",
                        context: $"File: {SshConfigPath}\nFull cipher list: {ciphers}"
                    )
                    .WithReferences(
                        "https://www.ssh.com/academy",
                        "https://stribika.github.io/2015/01/04/secure-secure-shell.html",
                        "https://infosec.mozilla.org/guidelines/openssh",
                        "https://sweet32.info/"
                    )
                    .WithAffectedComponent("SSH Daemon (sshd)"));

                    Log.Warning("{CheckName}: Weak ciphers detected: {Ciphers}", Name, string.Join(", ", weakFound));
                }
            }
        }

        /// <summary>
        /// Check for weak MACs
        /// </summary>
        private void CheckMacs(Dictionary<string, string> config, List<Finding> findings)
        {
            if (config.TryGetValue("MACs", out var macs))
            {
                var weakFound = CheckWeakAlgorithms(macs, WeakMacs, "MAC");
                if (weakFound.Any())
                {
                    findings.Add(Finding.Create(
                        id: "AST-SSH-LNX-002",
                        title: "Weak SSH MAC algorithms enabled",
                        severity: "medium",
                        confidence: "high",
                        recommendation: "Update SSH MAC configuration:\n" +
                            "1. Edit /etc/ssh/sshd_config\n" +
                            "2. Set secure MACs only:\n" +
                            "   MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256\n" +
                            "3. Restart SSH: sudo systemctl restart sshd\n" +
                            "4. Verify configuration: sshd -T | grep macs"
                    )
                    .WithDescription(
                        "The SSH daemon is configured to allow weak Message Authentication Code (MAC) algorithms. " +
                        "Detected weak MACs:\n" +
                        $"• {string.Join("\n• ", weakFound)}\n\n" +
                        "These MACs have known issues:\n" +
                        "• MD5-based: Broken hash function (collision attacks)\n" +
                        "• Truncated MACs (96-bit): Increased collision probability\n" +
                        "• umac-64: 64-bit tag (too short for modern security)\n\n" +
                        "Modern secure alternatives use SHA2-256/512 with ETM (Encrypt-then-MAC) mode."
                    )
                    .WithEvidence(
                        type: "config",
                        value: $"Weak MACs: {string.Join(", ", weakFound)}",
                        context: $"File: {SshConfigPath}\nFull MAC list: {macs}"
                    )
                    .WithReferences(
                        "https://www.ssh.com/academy/ssh/mac",
                        "https://infosec.mozilla.org/guidelines/openssh"
                    )
                    .WithAffectedComponent("SSH Daemon (sshd)"));

                    Log.Warning("{CheckName}: Weak MACs detected: {Macs}", Name, string.Join(", ", weakFound));
                }
            }
        }

        /// <summary>
        /// Check for weak key exchange algorithms
        /// </summary>
        private void CheckKexAlgorithms(Dictionary<string, string> config, List<Finding> findings)
        {
            if (config.TryGetValue("KexAlgorithms", out var kex))
            {
                var weakFound = CheckWeakAlgorithms(kex, WeakKex, "key exchange");
                if (weakFound.Any())
                {
                    Log.Warning("{CheckName}: Weak key exchange algorithms detected: {Kex}", 
                        Name, string.Join(", ", weakFound));
                    
                    // I will add more findings here in the future
                    // For now just logging as these are less critical than ciphers/MACs
                }
            }
        }

        /// <summary>
        /// Check X11Forwarding (potential attack vector)
        /// </summary>
        private void CheckX11Forwarding(Dictionary<string, string> config, List<Finding> findings)
        {
            if (config.TryGetValue("X11Forwarding", out var x11fwd))
            {
                if (x11fwd.Equals("yes", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(Finding.Create(
                        id: "AST-SSH-LNX-005",
                        title: "X11 forwarding enabled in SSH",
                        severity: "low",
                        confidence: "high",
                        recommendation: "Disable X11 forwarding if not needed:\n" +
                            "1. Edit /etc/ssh/sshd_config\n" +
                            "2. Set: X11Forwarding no\n" +
                            "3. Restart SSH: sudo systemctl restart sshd\n" +
                            "4. If X11 forwarding IS required:\n" +
                            "   - Set: X11UseLocalhost yes (additional security)\n" +
                            "   - Restrict to specific users/groups\n" +
                            "   - Monitor X11 connections in logs"
                    )
                    .WithDescription(
                        "SSH is configured with X11 forwarding enabled, which can be used as an attack vector for:\n" +
                        "• Session hijacking (attackers can capture X11 connections)\n" +
                        "• Keylogging (intercepting keyboard input via X11)\n" +
                        "• Screenshot capture (viewing user's display)\n" +
                        "• Privilege escalation in some scenarios\n\n" +
                        "Unless X11 forwarding is specifically required for GUI applications over SSH, " +
                        "it should be disabled to reduce attack surface. Most servers do not need X11 forwarding."
                    )
                    .WithEvidence(
                        type: "config",
                        value: $"X11Forwarding {x11fwd}",
                        context: $"File: {SshConfigPath}"
                    )
                    .WithReferences(
                        "https://www.ssh.com/academy/"
                    )
                    .WithAffectedComponent("SSH Daemon (sshd)"));

                    Log.Information("{CheckName}: X11 forwarding is enabled", Name);
                }
            }
        }

        /// <summary>
        /// Parse SSH config into key-value pairs
        /// </summary>
        private Dictionary<string, string> ParseSshConfig(string[] lines)
        {
            var config = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var rawLine in lines)
            {
                var line = rawLine.Trim();

                // Skip empty lines and comments
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                {
                    continue;
                }

                // Parse key value (space or tab separated)
                // Using regex with timeout for security
                var parts = Regex.Split(line, @"\s+", RegexOptions.None, TimeSpan.FromSeconds(1));
                if (parts.Length >= 2)
                {
                    var key = parts[0];
                    var value = string.Join(" ", parts.Skip(1));
                    
                    // Note: This is a simplified parser
                    // I will consider using a dedicated SSH config library
                    // or calling 'sshd -T' to get the effective configuration to implement in the future
                    
                    // Store first occurrence (later Match blocks might override)
                    if (!config.ContainsKey(key))
                    {
                        config[key] = value;
                    }
                }
            }

            return config;
        }

        /// <summary>
        /// Check if a comma-separated list of algorithms contains weak ones
        /// </summary>
        private List<string> CheckWeakAlgorithms(string algorithmList, HashSet<string> weakSet, string type)
        {
            var found = new List<string>();
            var algorithms = algorithmList.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                                         .Select(a => a.Trim());

            foreach (var algo in algorithms)
            {
                if (weakSet.Contains(algo))
                {
                    found.Add(algo);
                    Log.Debug("{CheckName}: Weak {Type} algorithm detected: {Algorithm}", Name, type, algo);
                }
            }

            return found;
        }

        /// <summary>
        /// Override CanExecute to check platform compatibility
        /// </summary>
        public override bool CanExecute()
        {
            // Use base check first (validates Linux platform via Category)
            if (!base.CanExecute())
                return false;
            return true;
        }
    }
}