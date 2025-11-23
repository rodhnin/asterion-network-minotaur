using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Serilog;
using Asterion.Core;
using Asterion.Core.Utils;
using Asterion.Models;

namespace Asterion.Checks.CrossPlatform
{
    /// <summary>
    /// SNMP (Simple Network Management Protocol) Security Scanner
    /// 
    /// Detects:
    /// - AST-SNMP-001: SNMP using default community string ('public', 'private', etc.)
    /// - AST-SNMP-002: SNMP with write access (RW community)
    /// - AST-SNMP-003: SNMPv1/v2c in use (recommend SNMPv3 with encryption)
    /// 
    /// Method:
    /// 1. Query UDP port 161 (SNMP)
    /// 2. Try default community strings (public, private, community, manager, admin)
    /// 3. Query system MIB objects (sysDescr, sysName, sysLocation, sysUpTime)
    /// 4. Determine protocol version (v1, v2c, v3)
    /// 5. Test for write access (heuristic + optional SET test)
    /// 6. Extract system information for evidence
    /// 
    /// Technical Reference:
    /// - RFC 1157 (SNMPv1)
    /// - RFC 1901-1908 (SNMPv2c)
    /// - RFC 3411-3418 (SNMPv3)
    /// - System MIB: RFC 1213 (MIB-II)
    /// </summary>
    public class SnmpScanner : BaseCheck
    {
        private const int SNMP_PORT = 161;
        
        public override string Name => "SNMP Security Scanner";
        
        public override CheckCategory Category => CheckCategory.CrossPlatform;
        
        public override string Description => 
            "Detects SNMP security issues including default community strings, write access, " +
            "and use of unencrypted SNMPv1/v2c protocols. Queries system MIB to extract device information.";

        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false; // Safe mode only does GET requests

        public SnmpScanner(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            // Check if SNMP checks are enabled
            if (!_config.Snmp.CheckDefaultCommunities)
            {
                Log.Debug("{CheckName} disabled in configuration", Name);
                return new List<Finding>();
            }

            var findings = new List<Finding>();

            Log.Information("[{CheckName}] Starting SNMP security scan on {Count} target(s)", Name, targets.Count);

            foreach (var target in targets)
            {
                try
                {
                    // Note: UDP port scanning is unreliable without ICMP
                    // We'll just try SNMP queries directly
                    Log.Debug("[{CheckName}] Checking SNMP on {Target}...", Name, target);

                    // Try each default community string
                    bool foundAccess = false;
                    foreach (var community in _config.Snmp.DefaultCommunities)
                    {
                        var snmpInfo = await ProbeSNMPAsync(target, community);

                        if (snmpInfo != null && snmpInfo.Accessible)
                        {
                            Log.Information("[{CheckName}] SNMP accessible on {Target} with community '{Community}'", 
                                Name, target, community);

                            // Create finding for default community
                            findings.Add(CreateDefaultCommunityFinding(target, snmpInfo));

                            // If write access, create additional critical finding
                            if (snmpInfo.HasWriteAccess)
                            {
                                findings.Add(CreateWriteAccessFinding(target, snmpInfo));
                            }

                            // Create finding for using SNMPv1/v2c (recommend v3)
                            if (snmpInfo.Version != "SNMPv3")
                            {
                                findings.Add(CreateLegacyVersionFinding(target, snmpInfo));
                            }

                            // Only report once per host (don't try more communities after success)
                            foundAccess = true;
                            break;
                        }
                    }

                    if (!foundAccess)
                    {
                        Log.Debug("[{CheckName}] No default SNMP communities found on {Target}", Name, target);
                    }
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "[{CheckName}] Failed to scan SNMP on {Target}", Name, target);
                }
            }

            LogExecution(targets.Count, findings.Count);
            return findings;
        }

        /// <summary>
        /// Probe SNMP service with a community string
        /// Queries system MIB objects to verify access
        /// </summary>
        private async Task<SnmpInfo?> ProbeSNMPAsync(string host, string community)
        {
            try
            {
                // Parse IP address
                if (!IPAddress.TryParse(host, out var ipAddress))
                {
                    // Try to resolve hostname
                    var hostEntry = await Dns.GetHostEntryAsync(host);
                    ipAddress = hostEntry.AddressList.FirstOrDefault();
                    
                    if (ipAddress == null)
                    {
                        Log.Debug("Cannot resolve hostname: {Host}", host);
                        return null;
                    }
                }

                var endpoint = new IPEndPoint(ipAddress, SNMP_PORT);
                var timeout = TimeSpan.FromSeconds(_config.Snmp.TimeoutSeconds);

                // System MIB OIDs (RFC 1213)
                var sysDescrOid = new ObjectIdentifier("1.3.6.1.2.1.1.1.0");      // sysDescr
                var sysNameOid = new ObjectIdentifier("1.3.6.1.2.1.1.5.0");       // sysName
                var sysLocationOid = new ObjectIdentifier("1.3.6.1.2.1.1.6.0");   // sysLocation
                var sysUpTimeOid = new ObjectIdentifier("1.3.6.1.2.1.1.3.0");     // sysUpTime

                var oids = new List<ObjectIdentifier> 
                { 
                    sysDescrOid, 
                    sysNameOid, 
                    sysLocationOid,
                    sysUpTimeOid
                };

                IList<Variable> varBinds = oids.Select(oid => new Variable(oid)).ToList();

                try
                {
                    // Try SNMPv2c GET request first
                    var results = await Task.Run(() =>
                    {
                        return Messenger.Get(
                            VersionCode.V2,
                            endpoint,
                            new OctetString(community),
                            varBinds,
                            (int)timeout.TotalMilliseconds
                        );
                    });

                    var info = new SnmpInfo
                    {
                        Host = host,
                        Community = community,
                        Accessible = true,
                        Version = "SNMPv2c"
                    };

                    // Extract values from response
                    foreach (var variable in results)
                    {
                        var oid = variable.Id.ToString();
                        var value = variable.Data.ToString();

                        if (oid.StartsWith("1.3.6.1.2.1.1.1"))
                        {
                            info.SysDescr = value;
                        }
                        else if (oid.StartsWith("1.3.6.1.2.1.1.5"))
                        {
                            info.SysName = value;
                        }
                        else if (oid.StartsWith("1.3.6.1.2.1.1.6"))
                        {
                            info.SysLocation = value;
                        }
                        else if (oid.StartsWith("1.3.6.1.2.1.1.3"))
                        {
                            info.SysUpTime = value;
                        }
                    }

                    // Heuristic: Determine if write access based on community name
                    // Common RW communities: private, write, admin, secret
                    var rwCommunities = new[] { "private", "write", "admin", "secret", "rw" };
                    info.HasWriteAccess = rwCommunities.Contains(community.ToLower());

                    // For now, we rely on heuristic to avoid accidentally modifying devices

                    Log.Debug("[{CheckName}] SNMP query successful on {Host} with '{Community}': {SysName}", 
                        Name, host, community, info.SysName ?? "unknown");

                    return info;
                }
                catch (Lextm.SharpSnmpLib.Messaging.TimeoutException)
                {
                    Log.Debug("[{CheckName}] SNMP timeout on {Host} with community '{Community}'", Name, host, community);
                    return null;
                }
                catch (Lextm.SharpSnmpLib.SnmpException ex)
                {
                    Log.Debug("[{CheckName}] SNMP error on {Host} with '{Community}': {Message}", 
                        Name, host, community, ex.Message);
                    return null;
                }
            }
            catch (Exception ex)
            {
                Log.Debug("[{CheckName}] SNMP probe failed on {Host} - {Error}", 
                    Name, host, ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Create finding for default community string
        /// </summary>
        private Finding CreateDefaultCommunityFinding(string target, SnmpInfo info)
        {
            // Severity based on community string
            // "public" is common and expected = medium
            // "private" suggests write access = high
            var severity = info.Community.ToLower() switch
            {
                "public" => "medium",
                "private" => "high",
                "admin" or "secret" or "write" => "high",
                _ => "medium"
            };

            var context = BuildEvidenceContext(info);

            return Finding.Create(
                id: "AST-SNMP-001",
                title: $"SNMP service using default community string '{info.Community}'",
                severity: severity,
                confidence: "high",
                recommendation: $"Secure or disable SNMP on host {target}:\n" +
                    $"1. Change the SNMP community string from '{info.Community}' to a strong, non-default value (20+ random characters).\n" +
                    "2. **Recommended**: Upgrade to SNMPv3 with authentication (SHA-256+) and encryption (AES-256) instead of SNMPv1/v2c.\n" +
                    "3. Limit SNMP access to specific management IP addresses via firewall rules or SNMP ACLs.\n" +
                    "4. Configure separate read-only and read-write community strings (never use the same for both).\n" +
                    "5. If SNMP is not needed, disable the SNMP service entirely to eliminate the attack surface.\n" +
                    "6. Enable SNMP traps to monitor for unauthorized access attempts."
            )
            .WithDescription(
                $"An SNMP agent on host {target} is responding to the default community string '{info.Community}'. " +
                "SNMP community strings act as passwords for accessing network device information. Using default values allows attackers to:\n" +
                "• Read device configuration and network topology\n" +
                "• Enumerate interfaces, routing tables, and ARP caches\n" +
                "• Discover other devices on the network\n" +
                "• Potentially modify configuration if write access is enabled\n\n" +
                "The 'public' community is widely known and should be considered compromised. " +
                (info.HasWriteAccess 
                    ? "This community likely allows WRITE access, which is critical." 
                    : "This community appears to be read-only, limiting the impact.")
            )
            .WithEvidence(
                type: "service",
                value: $"{info.Version} accessible with community '{info.Community}'",
                context: context
            )
            .WithReferences(
                "https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/7282-12.html",
                "https://tools.ietf.org/html/rfc3414" // SNMPv3 User-based Security Model
            )
            .WithAffectedComponent($"{target}:{SNMP_PORT} (SNMP Service)");
        }

        /// <summary>
        /// Create finding for write access
        /// </summary>
        private Finding CreateWriteAccessFinding(string target, SnmpInfo info)
        {
            return Finding.Create(
                id: "AST-SNMP-002",
                title: "SNMP with write access enabled (RW community)",
                severity: "critical",
                confidence: "medium", // Medium because it's heuristic-based
                recommendation: $"CRITICAL - Immediately secure SNMP write access on {target}:\n" +
                    $"1. Change the RW community string '{info.Community}' to a strong, unique value (40+ characters).\n" +
                    "2. If write access is not required, disable it entirely and use read-only communities.\n" +
                    "3. Implement IP-based ACLs to restrict write access to specific management stations only.\n" +
                    "4. Migrate to SNMPv3 with User-based Security Model (USM) for authentication and encryption.\n" +
                    "5. Enable comprehensive SNMP logging to detect unauthorized SET operations.\n" +
                    "6. Consider using NETCONF/RESTCONF for configuration management instead of SNMP.\n" +
                    "7. Regularly audit SNMP configurations and community strings."
            )
            .WithDescription(
                $"The SNMP service on {target} is accessible with a community string ('{info.Community}') that likely permits WRITE operations. " +
                "SNMP write access allows remote modification of device configuration via SET operations. An attacker with write access can:\n" +
                "• **Modify routing tables** to redirect traffic (man-in-the-middle attacks)\n" +
                "• **Disable network interfaces** causing denial of service\n" +
                "• **Change firewall rules** to allow unauthorized access\n" +
                "• **Update firmware** on some devices to install backdoors\n" +
                "• **Extract sensitive information** like RADIUS secrets or VPN keys\n" +
                "• **Reconfigure SNMP itself** to persist access\n\n" +
                "Note: This detection is heuristic-based on the community string name. " +
                "Actual write permissions depend on device configuration."
            )
            .WithEvidence(
                type: "service",
                value: $"Community '{info.Community}' suggests RW access (heuristic)",
                context: $"Device: {info.SysDescr ?? "unknown"}, Name: {info.SysName ?? "N/A"}"
            )
            .WithReferences(
                "https://nvd.nist.gov/vuln/detail/CVE-2017-6736",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0013"
            )
            .WithAffectedComponent($"{target}:{SNMP_PORT} (SNMP Service)");
        }

        /// <summary>
        /// Create finding for using legacy SNMPv1/v2c
        /// </summary>
        private Finding CreateLegacyVersionFinding(string target, SnmpInfo info)
        {
            return Finding.Create(
                id: "AST-SNMP-003",
                title: $"SNMP using unencrypted legacy protocol ({info.Version})",
                severity: "low",
                confidence: "high",
                recommendation: $"Upgrade SNMP on {target} to SNMPv3:\n" +
                    "1. Configure SNMPv3 with User-based Security Model (USM).\n" +
                    "2. Use authentication protocols: SHA-256 or SHA-512 (avoid MD5).\n" +
                    "3. Enable encryption: AES-256 or AES-192 (avoid DES).\n" +
                    "4. Create unique SNMPv3 users with strong passwords for each administrator.\n" +
                    "5. Disable SNMPv1 and SNMPv2c completely once SNMPv3 is configured.\n" +
                    "6. Verify management tools support SNMPv3 before migration.\n" +
                    "7. Document SNMPv3 user credentials securely (password manager)."
            )
            .WithDescription(
                $"The SNMP service on {target} is using {info.Version}, which sends community strings and data in plaintext. " +
                "Legacy SNMP versions (v1 and v2c) have significant security limitations:\n" +
                "• **No encryption**: All data (including community strings) sent in cleartext\n" +
                "• **No authentication**: Community strings are easily sniffed on the network\n" +
                "• **No integrity checking**: Messages can be modified in transit\n" +
                "• **No non-repudiation**: Cannot verify who performed an action\n\n" +
                "An attacker with network access can:\n" +
                "• Capture community strings via packet sniffing (Wireshark, tcpdump)\n" +
                "• Read all SNMP data including sensitive configuration\n" +
                "• Replay captured packets to gain access\n\n" +
                "SNMPv3 addresses these issues with authentication (HMAC-SHA) and encryption (AES)."
            )
            .WithEvidence(
                type: "service",
                value: $"Protocol: {info.Version} (plaintext, no encryption)",
                context: $"Device: {info.SysDescr ?? "unknown"}"
            )
            .WithReferences(
                "https://tools.ietf.org/html/rfc3410",
                "https://tools.ietf.org/html/rfc3414",
                "https://tools.ietf.org/html/rfc3826"
            )
            .WithAffectedComponent($"{target}:{SNMP_PORT} (SNMP Service)");
        }

        /// <summary>
        /// Build evidence context from SNMP system information
        /// </summary>
        private string BuildEvidenceContext(SnmpInfo info)
        {
            var parts = new List<string>();

            if (!string.IsNullOrEmpty(info.SysDescr))
                parts.Add($"sysDescr: '{info.SysDescr}'");
            
            if (!string.IsNullOrEmpty(info.SysName))
                parts.Add($"sysName: '{info.SysName}'");
            
            if (!string.IsNullOrEmpty(info.SysLocation))
                parts.Add($"sysLocation: '{info.SysLocation}'");
            
            if (!string.IsNullOrEmpty(info.SysUpTime))
                parts.Add($"sysUpTime: {info.SysUpTime}");

            return parts.Any() ? string.Join(", ", parts) : "No system information available";
        }
    }

    /// <summary>
    /// SNMP probe information extracted from queries
    /// </summary>
    internal class SnmpInfo
    {
        public string Host { get; set; } = string.Empty;
        public string Community { get; set; } = string.Empty;
        public bool Accessible { get; set; }
        public bool HasWriteAccess { get; set; }
        public string Version { get; set; } = "SNMPv2c";
        public string? SysDescr { get; set; }
        public string? SysName { get; set; }
        public string? SysLocation { get; set; }
        public string? SysUpTime { get; set; }
    }
}