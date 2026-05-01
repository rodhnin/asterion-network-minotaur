using System;
using System.Collections.Generic;
using System.Linq;
using Serilog;
using Asterion.Models;

namespace Asterion.Core
{
    /// <summary>
    /// Attack Chain Analyzer — Static Finding Correlation Engine
    ///
    /// Identifies combinations of findings that form multi-step attack vectors.
    /// For example: SMBv1 + no signing + writable share = complete pass-the-hash + lateral movement chain.
    ///
    /// Produces AttackChain objects that are attached to the Report and rendered in HTML
    /// as a dedicated "Attack Chains" section, helping pentesters and defenders understand
    /// the combined risk of co-existing vulnerabilities.
    ///
    /// All chains are static rules — no network access required.
    /// Runs post-scan, before report generation.
    /// </summary>
    public static class AttackChainAnalyzer
    {
        /// <summary>
        /// Analyze a list of findings and return detected attack chains.
        /// </summary>
        public static List<AttackChain> Analyze(IReadOnlyList<Finding> findings)
        {
            var detectedChains = new List<AttackChain>();
            var ids = new HashSet<string>(findings.Select(f => f.Id));

            foreach (var rule in ChainRules)
            {
                // A chain triggers when ALL required finding codes are present
                if (rule.RequiredCodes.All(ids.Contains))
                {
                    // Optionally boost if any bonus codes are present
                    bool bonusPresent = rule.BonusCodes.Any(ids.Contains);
                    var chain = new AttackChain
                    {
                        Id          = rule.Id,
                        Title       = rule.Title,
                        Description = rule.Description,
                        Severity    = rule.Severity,
                        Mitre       = rule.Mitre,
                        Steps       = rule.Steps.ToList(),
                        FindingIds  = rule.RequiredCodes
                            .Concat(rule.BonusCodes.Where(ids.Contains))
                            .ToList(),
                        Remediation = rule.Remediation,
                        Enhanced    = bonusPresent
                    };
                    detectedChains.Add(chain);
                    Log.Warning("[AttackChain] Detected: {Id} — {Title}", chain.Id, chain.Title);
                }
            }

            Log.Information("[AttackChain] Analysis complete — {Count} attack chain(s) detected", detectedChains.Count);
            return detectedChains;
        }

        // =====================================================================
        // STATIC CHAIN RULES
        // =====================================================================
        // RequiredCodes: ALL must be present to trigger
        // BonusCodes: Additional codes that enhance the chain if present (optional)
        // =====================================================================

        private static readonly List<ChainRule> ChainRules = new()
        {
            // -----------------------------------------------------------------
            // CHAIN 1: Full NTLM Relay + Lateral Movement
            // Requires: SMB signing disabled + LLMNR/NBT-NS active
            // Enhanced by: SMBv1, null session, writable share
            // -----------------------------------------------------------------
            new ChainRule
            {
                Id       = "AST-CHAIN-001",
                Title    = "NTLM Relay → Lateral Movement chain",
                Severity = "critical",
                Mitre    = "T1557.001 (NTLM Relay) + T1021.002 (Lateral Movement via SMB)",
                RequiredCodes = new[] { "AST-SMB-002", "AST-NET-002" },
                BonusCodes    = new[] { "AST-SMB-003", "AST-SMB-001", "AST-SMB-005" },
                Description =
                    "LLMNR/NBT-NS poisoning is active AND SMB signing is not required. " +
                    "An attacker can capture NTLMv2 hashes by responding to broadcast queries, " +
                    "then relay them to other machines on the network to gain unauthorized access " +
                    "without cracking any password.",
                Steps = new[]
                {
                    "1. Start Responder: `responder -I eth0 -wrf` — poisons LLMNR/NBT-NS/mDNS",
                    "2. Capture NTLMv2 hashes when users access UNC paths (e.g., \\\\fileserver\\share)",
                    "3. Relay to any machine without SMB signing: `ntlmrelayx.py -t smb://<target> -smb2support`",
                    "4. Execute commands, dump SAM, or pivot to other systems",
                    "5. If SMBv1 present: use EternalBlue (MS17-010) for unauthenticated RCE"
                },
                Remediation =
                    "1. Enforce SMB signing (GPO: Microsoft network server: Digitally sign communications)\n" +
                    "2. Disable LLMNR and NetBIOS-NS (GPO: Turn off multicast name resolution)\n" +
                    "3. Disable SMBv1 if present\n" +
                    "4. Implement network segmentation to limit lateral movement"
            },

            // -----------------------------------------------------------------
            // CHAIN 2: Kerberoasting → Domain Privilege Escalation
            // Requires: Kerberoastable SPNs + weak password policy
            // Enhanced by: AS-REP roasting, RC4/NTLMv1 encryption
            // -----------------------------------------------------------------
            new ChainRule
            {
                Id       = "AST-CHAIN-002",
                Title    = "Kerberoasting → Domain Admin escalation",
                Severity = "critical",
                Mitre    = "T1558.003 (Kerberoasting) + T1078.002 (Domain Accounts)",
                RequiredCodes = new[] { "AST-KRB-003", "AST-AD-002" },
                BonusCodes    = new[] { "AST-KRB-001", "AST-AD-003", "AST-KRB-002" },
                Description =
                    "Service Principal Names (SPNs) are registered for accounts with Kerberos tickets " +
                    "requestable by any authenticated user, AND the domain has a weak password policy. " +
                    "An attacker with any domain credentials can request TGS tickets for service accounts " +
                    "and crack them offline to recover plaintext passwords.",
                Steps = new[]
                {
                    "1. Request TGS tickets: `GetUserSPNs.py -request -dc-ip <DC> DOMAIN/user:pass`",
                    "2. Save hashes: output in hashcat-compatible format",
                    "3. Crack offline: `hashcat -m 13100 spn_hashes.txt wordlist.txt`",
                    "4. If service account has Domain Admin rights: full domain compromise",
                    "5. (Bonus) If DONT_REQ_PREAUTH set: AS-REP roast without credentials first"
                },
                Remediation =
                    "1. Enforce strong password policy (16+ chars for service accounts)\n" +
                    "2. Use Group Managed Service Accounts (gMSA) — automatic 256-char passwords\n" +
                    "3. Audit and remove unnecessary SPNs\n" +
                    "4. Enable AES256 for Kerberos (disable RC4)\n" +
                    "5. Monitor for anomalous TGS requests (detect Kerberoasting)"
            },

            // -----------------------------------------------------------------
            // CHAIN 3: Anonymous LDAP + SYSVOL GPP → Credential Harvest
            // Requires: Anonymous LDAP bind + GPP cpassword
            // -----------------------------------------------------------------
            new ChainRule
            {
                Id       = "AST-CHAIN-003",
                Title    = "Unauthenticated AD enumeration → GPP credential harvest",
                Severity = "critical",
                Mitre    = "T1552.006 (GPP) + T1087.002 (Domain Account Discovery)",
                RequiredCodes = new[] { "AST-LDAP-001", "AST-SYSVOL-001" },
                BonusCodes    = new[] { "AST-SYSVOL-002", "AST-SYSVOL-003", "AST-LDAP-002" },
                Description =
                    "Anonymous LDAP bind allows unauthenticated AD enumeration (users, groups, policies), " +
                    "AND GPP cpassword credentials are present in SYSVOL. An unauthenticated attacker " +
                    "can enumerate the domain structure AND recover plaintext credentials from SYSVOL " +
                    "without any prior access.",
                Steps = new[]
                {
                    "1. Enumerate domain via anonymous LDAP: `ldapsearch -x -H ldap://<DC> -b DC=corp,DC=local`",
                    "2. List domain users, groups, OUs, GPOs without credentials",
                    "3. Enumerate SYSVOL for GPP files: `findstr /S /I cpassword \\\\<DC>\\SYSVOL\\*`",
                    "4. Decrypt cpassword: `gpp-decrypt <cpassword_value>` (or Get-GPPPassword)",
                    "5. Use recovered credentials for further access (RDP, SMB, WinRM)"
                },
                Remediation =
                    "1. Disable anonymous LDAP bind (set dsHeuristics bit 7 to 2)\n" +
                    "2. Apply MS14-025 patch and remove all GPP cpassword entries\n" +
                    "3. Enable LDAP signing and channel binding\n" +
                    "4. Restrict SYSVOL read access to authenticated users only"
            },

            // -----------------------------------------------------------------
            // CHAIN 4: WDigest + LSASS + Local Admin → Domain Credential Dump
            // Requires: WDigest enabled + weak NTLM auth (LM/NTLMv1)
            // Enhanced by: LSA protection disabled, UAC disabled
            // -----------------------------------------------------------------
            new ChainRule
            {
                Id       = "AST-CHAIN-004",
                Title    = "WDigest + weak NTLM → plaintext credential dump",
                Severity = "critical",
                Mitre    = "T1003.001 (LSASS Memory) + T1550.002 (Pass the Hash)",
                RequiredCodes = new[] { "AST-REG-WIN-012", "AST-REG-WIN-001" },
                BonusCodes    = new[] { "AST-REG-WIN-006", "AST-PRIV-WIN-001", "AST-PRIV-WIN-002" },
                Description =
                    "WDigest is enabled (storing plaintext credentials in LSASS) AND LmCompatibilityLevel " +
                    "is set to allow NTLMv1. Once any local admin access is obtained, LSASS can be dumped " +
                    "to recover plaintext domain credentials that can be used for immediate lateral movement.",
                Steps = new[]
                {
                    "1. Obtain local admin via any privesc vector (service exe write, unquoted path, etc.)",
                    "2. Dump LSASS: `procdump -ma lsass.exe lsass.dmp` or `task manager → Create Dump`",
                    "3. Extract credentials: `sekurlsa::logonpasswords` in Mimikatz — plaintext visible",
                    "4. Use NTLMv1 hash for pass-the-hash to other domain machines",
                    "5. Pivot to domain controllers using recovered domain admin credentials"
                },
                Remediation =
                    "1. Disable WDigest: Set UseLogonCredential = 0\n" +
                    "2. Set LmCompatibilityLevel = 5 (NTLMv2 only)\n" +
                    "3. Enable LSA Protected Process (RunAsPPL = 1)\n" +
                    "4. Enable Windows Credential Guard\n" +
                    "5. Use privileged access workstations (PAW) for admin tasks"
            },

            // -----------------------------------------------------------------
            // CHAIN 5: SSH Root Login + Weak Ciphers → Privileged Access
            // Requires: PermitRootLogin yes + weak SSH ciphers/MACs
            // -----------------------------------------------------------------
            new ChainRule
            {
                Id       = "AST-CHAIN-005",
                Title    = "SSH root login + weak ciphers → privileged interception",
                Severity = "high",
                Mitre    = "T1021.004 (SSH) + T1040 (Network Sniffing)",
                RequiredCodes = new[] { "AST-SSH-LNX-001", "AST-SSH-LNX-002" },
                BonusCodes    = new[] { "AST-SSH-LNX-004", "AST-FW-LNX-001" },
                Description =
                    "SSH allows direct root login AND uses weak cryptographic ciphers/MACs. " +
                    "An attacker intercepting SSH traffic (MitM) can decrypt the session and " +
                    "recover root credentials, gaining immediate privileged access to the system.",
                Steps = new[]
                {
                    "1. Position for MitM (ARP spoofing on LAN, or BGP hijack for remote)",
                    "2. Intercept SSH traffic encrypted with weak ciphers (CBC-mode vulnerabilities)",
                    "3. Decrypt/manipulate session using known CBC weaknesses",
                    "4. Capture root credentials from decrypted stream",
                    "5. Log in as root directly — no privilege escalation needed"
                },
                Remediation =
                    "1. Disable root SSH login: Set `PermitRootLogin no` in /etc/ssh/sshd_config\n" +
                    "2. Use only strong ciphers: `Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com`\n" +
                    "3. Use only strong MACs: `MACs hmac-sha2-512-etm@openssh.com`\n" +
                    "4. Require SSH key authentication, disable password auth\n" +
                    "5. Use fail2ban or similar to block brute force attempts"
            },

            // -----------------------------------------------------------------
            // CHAIN 6: Cleartext LDAP + NTLM relay → AD Credential Harvest
            // Requires: Cleartext LDAP + NTLM relay (no LDAP signing)
            // -----------------------------------------------------------------
            new ChainRule
            {
                Id       = "AST-CHAIN-006",
                Title    = "Cleartext LDAP + no signing → AD credential relay",
                Severity = "critical",
                Mitre    = "T1557.001 (NTLM Relay) + T1040 (Credential Sniffing)",
                RequiredCodes = new[] { "AST-LDAP-002", "AST-AD-001" },
                BonusCodes    = new[] { "AST-NET-002", "AST-SMB-002" },
                Description =
                    "LDAP traffic is sent in cleartext AND LDAP signing is not required. " +
                    "An attacker on the network can capture all LDAP bind credentials in plaintext " +
                    "or relay NTLM authentication to the domain controller to authenticate as any user.",
                Steps = new[]
                {
                    "1. Sniff LDAP traffic: `wireshark -f 'port 389'` — credentials visible in plaintext",
                    "2. OR relay via ntlmrelayx: `ntlmrelayx.py -t ldap://<DC> --escalate-user <user>`",
                    "3. With LDAP relay: add user to Domain Admins, dump password hashes, create backdoor",
                    "4. Combined with LLMNR poisoning: capture and relay in fully automated pipeline"
                },
                Remediation =
                    "1. Enable LDAP signing (Domain Controller: LDAP server signing requirements = Require)\n" +
                    "2. Enable LDAP channel binding\n" +
                    "3. Migrate all clients to LDAPS (port 636) with TLS\n" +
                    "4. Disable LLMNR and NetBIOS-NS to prevent poisoning attacks"
            },

            // -----------------------------------------------------------------
            // CHAIN 7: Service PrivEsc + WDigest → Full Domain Compromise
            // Requires: Writable service exe or unquoted path + WDigest enabled
            // -----------------------------------------------------------------
            new ChainRule
            {
                Id       = "AST-CHAIN-007",
                Title    = "Local PrivEsc → WDigest dump → Domain compromise",
                Severity = "critical",
                Mitre    = "T1574.009 (Path Hijacking) + T1003.001 (LSASS Dump)",
                RequiredCodes = new[] { "AST-PRIV-WIN-002", "AST-REG-WIN-012" },
                BonusCodes    = new[] { "AST-PRIV-WIN-001", "AST-PRIV-WIN-003", "AST-AD-002" },
                Description =
                    "Local privilege escalation vectors exist (unquoted service path / writable service exe) " +
                    "AND WDigest credential caching is enabled. A low-privileged attacker can escalate to " +
                    "SYSTEM, then dump LSASS to recover plaintext domain credentials, leading to full domain compromise.",
                Steps = new[]
                {
                    "1. Exploit unquoted service path: place malicious exe at the unquoted position",
                    "2. Wait for service restart or restart manually if privileges allow",
                    "3. Obtain SYSTEM shell",
                    "4. Dump LSASS with Mimikatz: `sekurlsa::logonpasswords` → recover plaintext domain creds",
                    "5. Use domain credentials to compromise additional machines / domain controller"
                },
                Remediation =
                    "1. Fix all unquoted service paths immediately\n" +
                    "2. Audit service executable permissions (no user-writable paths)\n" +
                    "3. Disable WDigest: UseLogonCredential = 0\n" +
                    "4. Enable LSA Protected Process (RunAsPPL = 1)\n" +
                    "5. Implement least privilege for all service accounts"
            },

            // -----------------------------------------------------------------
            // CHAIN 8: Default SNMP + Network Exposure → Infrastructure Takeover
            // Requires: SNMP default community + SNMP write access
            // -----------------------------------------------------------------
            new ChainRule
            {
                Id       = "AST-CHAIN-008",
                Title    = "SNMP default community + write access → infrastructure reconfiguration",
                Severity = "high",
                Mitre    = "T1602 (Data from Configuration Repository) + T1565.003 (Runtime Data Manipulation)",
                RequiredCodes = new[] { "AST-SNMP-001", "AST-SNMP-002" },
                BonusCodes    = new[] { "AST-SNMP-003", "AST-NET-002" },
                Description =
                    "SNMP uses default community strings (public/private) AND write access is enabled. " +
                    "An attacker can enumerate the full network topology, read running configurations, " +
                    "and modify device settings (routing tables, access lists, interface configs) " +
                    "to redirect or intercept traffic.",
                Steps = new[]
                {
                    "1. Enumerate with default strings: `snmpwalk -c public -v2c <target>`",
                    "2. Dump routing tables, ARP cache, interface configs, running processes",
                    "3. Write-access: `snmpset -c private <target> <OID> s 'value'`",
                    "4. Modify routing (e.g., redirect default gateway) to intercept traffic",
                    "5. Download full device config via SNMP: `snmp-brute.py` + tftp"
                },
                Remediation =
                    "1. Change all SNMP community strings to unique, complex values\n" +
                    "2. Disable SNMP write access (SNMPv2c RW) unless explicitly required\n" +
                    "3. Migrate to SNMPv3 with authentication and encryption\n" +
                    "4. Restrict SNMP access to dedicated management IPs via ACL\n" +
                    "5. Disable SNMP on devices where it is not needed"
            },
        };

        /// <summary>
        /// Internal chain rule definition
        /// </summary>
        private class ChainRule
        {
            public required string   Id             { get; init; }
            public required string   Title          { get; init; }
            public required string   Severity       { get; init; }
            public required string   Mitre          { get; init; }
            public required string[] RequiredCodes  { get; init; }
            public          string[] BonusCodes     { get; init; } = Array.Empty<string>();
            public required string   Description    { get; init; }
            public required string[] Steps          { get; init; }
            public required string   Remediation    { get; init; }
        }
    }
}
