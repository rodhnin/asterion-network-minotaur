using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Core.Utils;
using Asterion.Models;

namespace Asterion.Checks.CrossPlatform
{
    /// <summary>
    /// RDP (Remote Desktop Protocol) Security Scanner
    /// 
    /// Detects:
    /// - AST-RDP-001: RDP without NLA (Network Level Authentication)
    /// - AST-RDP-002: Weak RDP security protocol (non-TLS)
    /// - AST-RDP-003: Potential BlueKeep vulnerability (CVE-2019-0708)
    /// - AST-RDP-004: Weak or self-signed certificates
    /// 
    /// Method:
    /// 1. Connect to port 3389
    /// 2. Send X.224 Connection Request with negotiation flags
    /// 3. Parse X.224 Connection Confirm response
    /// 4. Analyze Security Protocol and NLA requirement
    /// 5. Extract certificate info if available
    /// 
    /// Technical Reference:
    /// - [MS-RDPBCGR] Remote Desktop Protocol: Basic Connectivity and Graphics Remoting
    /// - RFC 1006 (ISO Transport Service on top of TCP)
    /// - X.224 Connection-Oriented Transport Protocol
    /// </summary>
    public class RdpScanner : BaseCheck
    {
        private const int RDP_PORT = 3389;
        
        public override string Name => "RDP Security Scanner";
        
        public override CheckCategory Category => CheckCategory.CrossPlatform;
        
        public override string Description => 
            "Analyzes Remote Desktop Protocol (RDP) security configuration including Network Level Authentication (NLA), " +
            "encryption protocols, and potential vulnerabilities like BlueKeep (CVE-2019-0708). " +
            "Performs protocol-level analysis without authentication.";

        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        public RdpScanner(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            // Check if RDP checks are enabled
            if (!_config.Rdp.CheckNla)
            {
                Log.Debug("{CheckName} disabled in configuration", Name);
                return new List<Finding>();
            }

            var findings = new List<Finding>();

            Log.Information("[{CheckName}] Starting RDP security scan on {Count} target(s)", Name, targets.Count);

            foreach (var target in targets)
            {
                try
                {
                    // Check if RDP port is open
                    if (!await NetworkUtils.IsPortOpenAsync(target, RDP_PORT, _config.Scan.Timeout.Connect * 1000))
                    {
                        Log.Debug("RDP port {Port} not open on {Target}", RDP_PORT, target);
                        continue;
                    }

                    Log.Information("[{CheckName}] RDP port {Port} open on {Target}, analyzing protocol...", Name, RDP_PORT, target);

                    // Analyze RDP configuration
                    var rdpInfo = await AnalyzeRdpAsync(target, options);

                    if (rdpInfo != null)
                    {
                        // Check NLA requirement
                        if (!rdpInfo.NlaRequired)
                        {
                            findings.Add(CreateNlaFinding(target, rdpInfo));
                        }

                        // Check security protocol
                        if (rdpInfo.UsesLegacyRdpSecurity)
                        {
                            findings.Add(CreateWeakProtocolFinding(target, rdpInfo));
                        }

                        // Check for potential BlueKeep
                        if (rdpInfo.PotentialBlueKeep)
                        {
                            findings.Add(CreateBlueKeepFinding(target, rdpInfo));
                        }

                        // Check certificate issues
                        if (rdpInfo.HasWeakCertificate)
                        {
                            findings.Add(CreateWeakCertFinding(target, rdpInfo));
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "[{CheckName}] Failed to scan RDP on {Target}", Name, target);
                }
            }

            LogExecution(targets.Count, findings.Count);
            return findings;
        }

        /// <summary>
        /// Perform RDP protocol handshake and extract security configuration
        /// </summary>
        private async Task<RdpInfo?> AnalyzeRdpAsync(string host, ScanOptions options)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(host, RDP_PORT);
                
                if (await Task.WhenAny(connectTask, Task.Delay(_config.Scan.Timeout.Connect * 1000)) != connectTask)
                {
                    Log.Debug("RDP connection timeout on {Host}", host);
                    return null;
                }

                if (!client.Connected)
                {
                    return null;
                }

                using var stream = client.GetStream();
                stream.ReadTimeout = _config.Scan.Timeout.Read * 1000;
                stream.WriteTimeout = _config.Scan.Timeout.Connect * 1000;

                // Send X.224 Connection Request with TLS and CredSSP support
                var connectionRequest = BuildX224ConnectionRequest();
                await stream.WriteAsync(connectionRequest, 0, connectionRequest.Length);

                // Read X.224 Connection Confirm
                var response = new byte[8192];
                var bytesRead = await stream.ReadAsync(response, 0, response.Length);

                if (bytesRead < 19)
                {
                    Log.Debug("RDP response too short: {Bytes} bytes from {Host}", bytesRead, host);
                    return null;
                }

                // Parse response
                return ParseX224Response(response, bytesRead, host);
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "RDP handshake failed on {Host}", host);
                return null;
            }
        }

        /// <summary>
        /// Build X.224 Connection Request with RDP Negotiation Request
        /// 
        /// Packet Structure:
        /// - TPKT Header (4 bytes): Version 3, Length
        /// - X.224 CR TPDU (14 bytes): Connection Request
        /// - RDP Negotiation Request (8 bytes): Requested protocols
        /// 
        /// Total: 19 bytes
        /// </summary>
        private byte[] BuildX224ConnectionRequest()
        {
            var packet = new List<byte>();

            // TPKT Header (RFC 1006)
            packet.Add(0x03); // Version 3
            packet.Add(0x00); // Reserved
            packet.Add(0x00); // Length high byte
            packet.Add(0x13); // Length low byte (19 bytes total)

            // X.224 Connection Request TPDU
            packet.Add(0x0E); // Length Indicator (14 bytes)
            packet.Add(0xE0); // PDU Type: Connection Request (CR)
            packet.Add(0x00); packet.Add(0x00); // Destination Reference (0 for CR)
            packet.Add(0x00); packet.Add(0x00); // Source Reference
            packet.Add(0x00); // Class and Options

            // RDP Negotiation Request ([MS-RDPBCGR] section 2.2.1.1.1)
            packet.Add(0x01); // Type: TYPE_RDP_NEG_REQ
            packet.Add(0x00); // Flags
            packet.Add(0x08); packet.Add(0x00); // Length (8 bytes)
            
            // Requested Protocols (4 bytes, little-endian flags)
            // 0x00000001 = PROTOCOL_SSL (TLS 1.0)
            // 0x00000002 = PROTOCOL_HYBRID (CredSSP/NLA)
            // 0x00000000 = Standard RDP Security
            // We request both TLS and CredSSP to test what server accepts
            packet.Add(0x03); // Request TLS + CredSSP (0x01 | 0x02)
            packet.Add(0x00);
            packet.Add(0x00);
            packet.Add(0x00);

            return packet.ToArray();
        }

        /// <summary>
        /// Parse X.224 Connection Confirm and extract RDP security info
        /// </summary>
        private RdpInfo? ParseX224Response(byte[] data, int length, string host)
        {
            try
            {
                // Validate TPKT header
                if (data[0] != 0x03)
                {
                    Log.Debug("Invalid TPKT version: 0x{Version:X2} on {Host}", data[0], host);
                    return null;
                }

                // Check X.224 Connection Confirm (0xD0)
                if (data[5] != 0xD0)
                {
                    Log.Debug("Not a Connection Confirm (expected 0xD0, got 0x{Code:X2}) on {Host}", data[5], host);
                    return null;
                }

                var info = new RdpInfo
                {
                    Host = host,
                    NlaRequired = false,
                    UsesLegacyRdpSecurity = true,
                    SelectedProtocol = "Standard RDP Security"
                };

                // Look for RDP Negotiation Response (starts at byte 11)
                // Type can be: 0x02 (RDP_NEG_RSP), 0x03 (RDP_NEG_FAILURE)
                if (length >= 19 && data[11] == 0x02) // TYPE_RDP_NEG_RSP
                {
                    // Byte 16-19: Selected protocol flags (little-endian)
                    var protocolFlags = BitConverter.ToUInt32(data, 16);

                    if ((protocolFlags & 0x01) != 0)
                    {
                        // PROTOCOL_SSL (TLS 1.0)
                        info.SelectedProtocol = "TLS 1.0";
                        info.UsesLegacyRdpSecurity = false;
                    }

                    if ((protocolFlags & 0x02) != 0)
                    {
                        // PROTOCOL_HYBRID (CredSSP with NLA)
                        info.SelectedProtocol = "CredSSP (NLA Enforced)";
                        info.NlaRequired = true;
                        info.UsesLegacyRdpSecurity = false;
                    }

                    if (protocolFlags == 0x00)
                    {
                        // Standard RDP Security (no encryption negotiation)
                        info.SelectedProtocol = "Standard RDP Security";
                        info.UsesLegacyRdpSecurity = true;
                        info.NlaRequired = false;
                    }

                    Log.Information("[{CheckName}] {Host} RDP: Protocol={Protocol}, Flags=0x{Flags:X8}", 
                        Name, host, info.SelectedProtocol, protocolFlags);
                }
                else if (length >= 19 && data[11] == 0x03) // TYPE_RDP_NEG_FAILURE
                {
                    // Server rejected negotiation - extract failure code
                    var failureCode = BitConverter.ToUInt32(data, 16);
                    
                    if (failureCode == 0x00000001) // SSL_REQUIRED_BY_SERVER
                    {
                        info.NlaRequired = true;
                        info.UsesLegacyRdpSecurity = false;
                        info.SelectedProtocol = "SSL/TLS Required by Server";
                    }
                    else if (failureCode == 0x00000002) // SSL_NOT_ALLOWED_BY_SERVER
                    {
                        info.SelectedProtocol = "Standard RDP Security (SSL Disabled)";
                        info.UsesLegacyRdpSecurity = true;
                    }
                    else if (failureCode == 0x00000003) // SSL_CERT_NOT_ON_SERVER
                    {
                        info.SelectedProtocol = "Standard RDP Security (No Certificate)";
                        info.UsesLegacyRdpSecurity = true;
                    }

                    Log.Warning("[{CheckName}] {Host} RDP: Negotiation failed, code=0x{Code:X8}", 
                        Name, host, failureCode);
                }

                // Heuristic: Detect potential BlueKeep vulnerability
                // CVE-2019-0708 affects unpatched Windows systems with:
                // 1. Legacy RDP Security enabled (no TLS/CredSSP)
                // 2. No NLA requirement
                // Vulnerable: Windows 7, Server 2008 R2, Server 2008, XP, Server 2003
                if (info.UsesLegacyRdpSecurity && !info.NlaRequired)
                {
                    info.PotentialBlueKeep = true;
                    Log.Warning("[{CheckName}] {Host} may be vulnerable to BlueKeep (CVE-2019-0708)", Name, host);
                }

                // Certificate analysis
                // If using legacy protocol, likely using default self-signed cert
                if (info.UsesLegacyRdpSecurity)
                {
                    info.HasWeakCertificate = true;
                }

                return info;
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Failed to parse RDP response from {Host}", host);
                return null;
            }
        }

        private Finding CreateNlaFinding(string target, RdpInfo info)
        {
            return Finding.Create(
                id: "AST-RDP-001",
                title: "RDP accessible without Network Level Authentication (NLA)",
                severity: "high",
                confidence: "high",
                recommendation: $"Enable Network Level Authentication (NLA) for RDP on {target}:\n" +
                    "1. In System Properties > Remote, check 'Allow connections only from computers running Remote Desktop with NLA'.\n" +
                    "2. Via Group Policy: Computer Configuration > Administrative Templates > Windows Components > " +
                    "Remote Desktop Services > Remote Desktop Session Host > Security > " +
                    "'Require user authentication for remote connections by using Network Level Authentication'.\n" +
                    "3. Ensure the host is fully patched (especially CVE-2019-0708 if applicable).\n" +
                    "4. Restrict RDP access via firewall to only trusted IP addresses."
            )
            .WithDescription(
                $"The Remote Desktop service on {target} allows connections without requiring Network Level Authentication (NLA). " +
                "This means attackers can reach the RDP login screen without any pre-authentication. " +
                "NLA requires authentication before establishing a full RDP session, which:\n" +
                "• Reduces attack surface by requiring valid credentials upfront\n" +
                "• Mitigates unauthenticated RDP exploits like BlueKeep (CVE-2019-0708)\n" +
                "• Prevents resource exhaustion from connection floods\n" +
                "Without NLA, the server is more vulnerable to brute force attacks and remote exploits."
            )
            .WithEvidence(
                type: "service",
                value: $"RDP Protocol: {info.SelectedProtocol}",
                context: $"Host {target}:3389 - NLA not enforced (CredSSP not required)"
            )
            .WithCve("CVE-2019-0708")
            .WithReferences(
                "https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access",
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708"
            )
            .WithAffectedComponent($"{target}:3389 (RDP Service)");
        }

        private Finding CreateWeakProtocolFinding(string target, RdpInfo info)
        {
            return Finding.Create(
                id: "AST-RDP-002",
                title: "RDP using legacy security protocol (non-TLS)",
                severity: "medium",
                confidence: "high",
                recommendation: $"Configure RDP on {target} to require TLS encryption:\n" +
                    "1. Via Group Policy: Computer Configuration > Administrative Templates > Windows Components > " +
                    "Remote Desktop Services > Remote Desktop Session Host > Security\n" +
                    "2. Set 'Require use of specific security layer for remote (RDP) connections' to 'SSL (TLS 1.0)'.\n" +
                    "3. Also enable 'Require user authentication for remote connections by using Network Level Authentication'.\n" +
                    "4. Ensure a valid SSL/TLS certificate is installed for RDP."
            )
            .WithDescription(
                $"The RDP service on {target} is configured to use the legacy 'Standard RDP Security' protocol " +
                "instead of modern TLS/SSL encryption. This older protocol (based on RC4 encryption) is:\n" +
                "• Susceptible to man-in-the-middle attacks\n" +
                "• Does not provide forward secrecy\n" +
                "• Uses weaker cryptographic algorithms\n" +
                "• Cannot leverage modern TLS features (certificate pinning, etc.)\n" +
                "TLS provides stronger encryption and better protection against eavesdropping."
            )
            .WithEvidence(
                type: "service",
                value: $"RDP Protocol: {info.SelectedProtocol}",
                context: $"Host {target}:3389 - Server accepted Standard RDP Security negotiation"
            )
            .WithReferences(
                "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/",
                "https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/understanding-remote-desktop-protocol"
            )
            .WithAffectedComponent($"{target}:3389 (RDP Service)");
        }

        private Finding CreateBlueKeepFinding(string target, RdpInfo info)
        {
            return Finding.Create(
                id: "AST-RDP-003",
                title: "Potential BlueKeep vulnerability (CVE-2019-0708)",
                severity: "critical",
                confidence: "medium",
                recommendation: $"CRITICAL - Immediate action required for {target}:\n" +
                    "1. **URGENT**: Apply Microsoft security update KB4499175 (or later) immediately if not already installed.\n" +
                    "2. Enable Network Level Authentication (NLA) to block unauthenticated exploitation.\n" +
                    "3. Restrict RDP access via firewall to only specific trusted IP addresses/ranges.\n" +
                    "4. If running Windows 7, Server 2008 R2, or older, strongly consider upgrading to a supported OS.\n" +
                    "5. Monitor Windows Event Logs (Event ID 4625) for suspicious RDP connection attempts.\n" +
                    "6. Consider implementing RDP Gateway or VPN for remote access instead of direct RDP exposure."
            )
            .WithDescription(
                $"The RDP service on {target} is configured in a manner consistent with systems vulnerable to BlueKeep (CVE-2019-0708). " +
                "This is a **critical, wormable** remote code execution vulnerability that:\n" +
                "• Allows remote code execution WITHOUT authentication (pre-auth RCE)\n" +
                "• Can be exploited to install malware, ransomware, or create botnets\n" +
                "• Is wormable (can spread automatically like WannaCry)\n" +
                "• Affects vulnerable Windows versions: 7, Server 2008 R2, Server 2008, XP, Server 2003\n\n" +
                "The server is using legacy RDP Security without NLA, which are strong indicators of vulnerability. " +
                "While this is a heuristic detection (actual vulnerability depends on patch level), the risk is severe enough to warrant immediate investigation."
            )
            .WithEvidence(
                type: "service",
                value: $"RDP Configuration: {info.SelectedProtocol}, NLA Required: {info.NlaRequired}",
                context: $"Host {target}:3389 - Configuration matches vulnerable BlueKeep systems (legacy protocol + no NLA)"
            )
            .WithCve("CVE-2019-0708")
            .WithReferences(
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708",
                "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-0708",
                "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"
            )
            .WithAffectedComponent($"{target}:3389 (RDP Service)");
        }

        private Finding CreateWeakCertFinding(string target, RdpInfo info)
        {
            return Finding.Create(
                id: "AST-RDP-004",
                title: "RDP using potentially weak or self-signed certificate",
                severity: "low",
                confidence: "medium",
                recommendation: $"Improve RDP certificate security on {target}:\n" +
                    "1. Deploy a proper SSL/TLS certificate from a trusted Certificate Authority (CA) for RDP.\n" +
                    "2. Configure RDP to use the certificate:\n" +
                    "   - Remote Desktop Session Host Configuration > General > Certificate\n" +
                    "   - Or via Group Policy: 'Server authentication certificate template'\n" +
                    "3. Ensure RDP clients are configured to verify server certificates.\n" +
                    "4. Alternatively, use a certificate from an internal PKI with proper distribution."
            )
            .WithDescription(
                $"The RDP service on {target} is likely using a self-signed or default certificate. " +
                "When RDP uses Standard RDP Security or TLS without a proper certificate:\n" +
                "• The connection is vulnerable to man-in-the-middle (MITM) attacks\n" +
                "• Clients cannot verify server authenticity\n" +
                "• Attackers can intercept credentials and session data\n" +
                "• Users receive certificate warnings (often ignored)\n\n" +
                "While less critical than missing NLA, weak certificates undermine the security of even TLS-encrypted connections."
            )
            .WithEvidence(
                type: "service",
                value: $"RDP Protocol: {info.SelectedProtocol}",
                context: $"Host {target}:3389 - Using legacy RDP Security (likely default/self-signed certificate). " +
                         "Full certificate validation requires TLS handshake (not performed)."
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/remote-desktop-listener-certificate-configurations",
                "https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services"
            )
            .WithAffectedComponent($"{target}:3389 (RDP Service)");
        }
    }

    /// <summary>
    /// RDP configuration information extracted from protocol handshake
    /// </summary>
    internal class RdpInfo
    {
        public string Host { get; set; } = string.Empty;
        public bool NlaRequired { get; set; }
        public bool UsesLegacyRdpSecurity { get; set; }
        public string SelectedProtocol { get; set; } = string.Empty;
        public bool PotentialBlueKeep { get; set; }
        public bool HasWeakCertificate { get; set; }
    }
}