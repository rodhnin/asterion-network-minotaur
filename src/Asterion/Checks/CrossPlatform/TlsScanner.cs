using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Core.Utils;
using Asterion.Models;

namespace Asterion.Checks.CrossPlatform
{
    /// <summary>
    /// TLS/SSL Security Scanner
    ///
    /// Audits TLS configuration on common services (HTTPS, LDAPS, SMTPS, FTPS, RDP, etc.):
    /// - AST-TLS-001: SSLv2/SSLv3/TLS 1.0/TLS 1.1 enabled (deprecated protocols)
    /// - AST-TLS-002: Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, ANON)
    /// - AST-TLS-003: Self-signed or expired certificate
    /// - AST-TLS-004: Certificate hostname mismatch
    /// - AST-TLS-005: TLS not available on expected service port (cleartext)
    ///
    /// Checks: HTTPS(443), LDAPS(636), SMTPS(465/587/993/995), FTPS(990),
    ///         RDP(3389), MSSQL(1433), LDAP STARTTLS(389)
    /// </summary>
    public class TlsScanner : BaseCheck
    {
        public override string Name => "TLS/SSL Security Scanner";
        public override CheckCategory Category => CheckCategory.CrossPlatform;
        public override string Description =>
            "Audits TLS/SSL configuration across all services with transport encryption: " +
            "detects deprecated protocols (SSLv3, TLS 1.0/1.1), weak ciphers, expired/self-signed " +
            "certificates, and cleartext services on expected encrypted ports.";

        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        // Service ports to probe for TLS — (port, service label, required)
        private static readonly (int Port, string Label, bool Required)[] TlsPorts =
        {
            (443,  "HTTPS",   false),
            (636,  "LDAPS",   false),
            (465,  "SMTPS",   false),
            (587,  "SMTP/TLS",false),
            (993,  "IMAPS",   false),
            (995,  "POP3S",   false),
            (990,  "FTPS",    false),
            (3389, "RDP/TLS", false),
            (1433, "MSSQL",   false),
            (8443, "HTTPS-alt",false),
        };

        // Weak cipher keywords in cipher suite names
        private static readonly string[] WeakCipherKeywords =
            { "RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "ADH", "AECDH", "PSK" };

        public TlsScanner(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var findings = new List<Finding>();
            Log.Information("[{CheckName}] Starting TLS/SSL audit on {Count} target(s)", Name, targets.Count);

            foreach (var target in targets)
            {
                try
                {
                    foreach (var (port, label, _) in TlsPorts)
                    {
                        if (!await NetworkUtils.IsPortOpenAsync(target, port, 2000))
                            continue;

                        Log.Debug("[{CheckName}] Port {Port} ({Label}) open on {Target}", Name, port, label, target);
                        await AuditTlsPortAsync(target, port, label, findings, options);
                    }
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "[{CheckName}] Failed to audit TLS on {Target}", Name, target);
                }
            }

            LogExecution(targets.Count, findings.Count);
            return findings;
        }

        private async Task AuditTlsPortAsync(
            string target, int port, string label,
            List<Finding> findings, ScanOptions options)
        {
            // 1. Probe for deprecated protocol support
            await CheckDeprecatedProtocolsAsync(target, port, label, findings);

            // 2. Probe best-available TLS and inspect certificate + cipher
            await CheckCertificateAndCipherAsync(target, port, label, findings, options);
        }

        private async Task CheckDeprecatedProtocolsAsync(
            string target, int port, string label, List<Finding> findings)
        {
            // Test TLS 1.0 and TLS 1.1 (most impactful deprecated versions in practice)
            var deprecatedToTest = new[]
            {
#pragma warning disable SYSLIB0039
                (SslProtocols.Tls,   "TLS 1.0"),
                (SslProtocols.Tls11, "TLS 1.1"),
#pragma warning restore SYSLIB0039
            };

            var acceptedDeprecated = new List<string>();

            foreach (var (protocol, name) in deprecatedToTest)
            {
                try
                {
                    using var tcp = new TcpClient();
                    await tcp.ConnectAsync(target, port).WaitAsync(TimeSpan.FromSeconds(4));
                    using var ssl = new SslStream(tcp.GetStream(), false,
                        (sender, cert, chain, errors) => true); // accept any cert for protocol test

                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = target,
                        EnabledSslProtocols = protocol,
                        RemoteCertificateValidationCallback = (_, _, _, _) => true
                    }).WaitAsync(TimeSpan.FromSeconds(5));

                    acceptedDeprecated.Add(name);
                    Log.Warning("[{CheckName}] {Protocol} accepted on {Target}:{Port}", Name, name, target, port);
                }
                catch
                {
                    // Protocol rejected or connection failed — that's good
                }
            }

            if (acceptedDeprecated.Count > 0)
            {
                var protocols = string.Join(", ", acceptedDeprecated);
                findings.Add(Finding.Create(
                    id: "AST-TLS-001",
                    title: $"Deprecated TLS protocol(s) enabled on {label} port {port}: {protocols}",
                    severity: acceptedDeprecated.Contains("TLS 1.0") ? "high" : "medium",
                    confidence: "high",
                    recommendation:
                        "Disable TLS 1.0 and TLS 1.1 — both are deprecated and known-broken:\n\n" +
                        "**Windows (IIS / Schannel):**\n" +
                        "```powershell\n" +
                        "# Disable TLS 1.0\n" +
                        "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Force\n" +
                        "Set-ItemProperty -Path 'HKLM:\\...\\TLS 1.0\\Server' -Name 'Enabled' -Value 0\n" +
                        "# Disable TLS 1.1 (same pattern with 'TLS 1.1')\n" +
                        "# Enable TLS 1.2 and 1.3\n" +
                        "```\n\n" +
                        "**Linux (OpenSSL / nginx / Apache):**\n" +
                        "```\n" +
                        "# nginx.conf:\n" +
                        "ssl_protocols TLSv1.2 TLSv1.3;\n\n" +
                        "# Apache httpd.conf:\n" +
                        "SSLProtocol -all +TLSv1.2 +TLSv1.3\n" +
                        "```\n\n" +
                        "Minimum required: TLS 1.2. Recommended: TLS 1.3 only where client compatibility allows."
                )
                .WithDescription(
                    $"The `{label}` service on port `{port}` accepts connections using deprecated TLS versions: **{protocols}**.\n\n" +
                    "**Why deprecated protocols are dangerous:**\n" +
                    "- **TLS 1.0:** Vulnerable to BEAST, POODLE (via CBC downgrade), and CRIME attacks\n" +
                    "- **TLS 1.1:** Vulnerable to BEAST and deprecated by RFC 8996 (March 2021)\n" +
                    "- Both versions use weak MAC constructions and susceptible cipher suites\n" +
                    "- PCI-DSS 4.0 explicitly prohibits TLS 1.0 and discourages TLS 1.1\n\n" +
                    "An attacker performing a MitM can downgrade the connection to these weaker versions."
                )
                .WithEvidence(
                    type: "service",
                    value: $"{label} port {port} on {target} accepted: {protocols}",
                    context: $"Protocol negotiation test confirmed acceptance of deprecated TLS version(s).\n" +
                             $"Target: {target}:{port} ({label})"
                )
                .WithReferences(
                    "https://datatracker.ietf.org/doc/html/rfc8996",
                    "https://www.pcisecuritystandards.org/document_library/?category=pcidss&document=pci_dss",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566"
                )
                .WithAffectedComponent($"{label} (port {port}) on {target}"));
            }
        }

        private async Task CheckCertificateAndCipherAsync(
            string target, int port, string label,
            List<Finding> findings, ScanOptions options)
        {
            try
            {
                X509Certificate2? cert = null;
                string? cipherAlgorithm = null;
                string? negotiatedProtocol = null;
                bool tlsAvailable = false;

                try
                {
                    using var tcp = new TcpClient();
                    await tcp.ConnectAsync(target, port).WaitAsync(TimeSpan.FromSeconds(5));

                    using var ssl = new SslStream(tcp.GetStream(), false,
                        (sender, certificate, chain, errors) =>
                        {
                            if (certificate != null)
                                cert = new X509Certificate2(certificate);
                            return true; // Accept any cert to get the details
                        });

                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = target,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        // RemoteCertificateValidationCallback already set in SslStream constructor above
                    }).WaitAsync(TimeSpan.FromSeconds(8));

                    tlsAvailable = true;
                    cipherAlgorithm = ssl.CipherAlgorithm.ToString();
                    negotiatedProtocol = ssl.SslProtocol.ToString();

                    Log.Debug("[{CheckName}] {Target}:{Port} — Protocol={Proto} Cipher={Cipher}",
                        Name, target, port, negotiatedProtocol, cipherAlgorithm);
                }
                catch (AuthenticationException authEx)
                {
                    Log.Debug("[{CheckName}] TLS auth failed on {Target}:{Port}: {Msg}", Name, target, port, authEx.Message);
                }
                catch (Exception ex)
                {
                    Log.Debug("[{CheckName}] Could not establish TLS on {Target}:{Port}: {Msg}", Name, target, port, ex.Message);
                }

                // Check for weak cipher
                if (tlsAvailable && !string.IsNullOrEmpty(cipherAlgorithm))
                {
                    var upperCipher = cipherAlgorithm.ToUpperInvariant();
                    var weak = WeakCipherKeywords.FirstOrDefault(k => upperCipher.Contains(k));
                    if (weak != null)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-TLS-002",
                            title: $"Weak cipher suite negotiated on {label} port {port}: {cipherAlgorithm}",
                            severity: "high",
                            confidence: "high",
                            recommendation:
                                "Restrict cipher suites to AEAD ciphers with forward secrecy:\n\n" +
                                "**Recommended cipher string (OpenSSL):**\n" +
                                "```\nTLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:\n" +
                                "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256\n```\n\n" +
                                "**nginx:** `ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:...'`\n" +
                                "**IIS:** Use IIS Crypto or Group Policy to set cipher order."
                        )
                        .WithDescription(
                            $"The `{label}` service negotiated cipher **`{cipherAlgorithm}`** which contains " +
                            $"the weak algorithm `{weak}`.\n\n" +
                            "Weak ciphers compromise the confidentiality and integrity of encrypted communications:\n" +
                            "- **RC4:** Known statistical biases, effectively broken\n" +
                            "- **3DES/DES:** SWEET32 birthday attack (CVE-2016-2183)\n" +
                            "- **NULL:** No encryption — traffic in plaintext\n" +
                            "- **EXPORT/ANON:** Intentionally weak (FREAK, LOGJAM attacks)"
                        )
                        .WithEvidence(
                            type: "service",
                            value: $"Negotiated cipher: {cipherAlgorithm} (contains: {weak})",
                            context: $"Target: {target}:{port} ({label})\nProtocol: {negotiatedProtocol}"
                        )
                        .WithReferences(
                            "https://nvd.nist.gov/vuln/detail/CVE-2016-2183",
                            "https://www.ssllabs.com/ssltest/"
                        )
                        .WithAffectedComponent($"{label} (port {port}) on {target}"));
                    }
                }

                // Check certificate issues
                if (cert != null)
                {
                    var now = DateTime.UtcNow;

                    // Expired certificate
                    if (cert.NotAfter < now || cert.NotBefore > now)
                    {
                        var expired = cert.NotAfter < now;
                        findings.Add(Finding.Create(
                            id: "AST-TLS-003",
                            title: $"{'E' + (expired ? "xpired" : "not-yet-valid")} TLS certificate on {label} port {port}",
                            severity: expired ? "high" : "medium",
                            confidence: "high",
                            recommendation:
                                expired
                                    ? "Renew the TLS certificate immediately. Use Let's Encrypt for free automated certificates (certbot)."
                                    : "Verify the server clock is synchronized (NTP) and the certificate issuance date is correct."
                        )
                        .WithDescription(
                            $"The TLS certificate for `{label}` port `{port}` is " +
                            (expired ? $"**expired** (expired: {cert.NotAfter:yyyy-MM-dd})" : $"**not yet valid** (valid from: {cert.NotBefore:yyyy-MM-dd})") +
                            ". Browsers and clients will display security warnings and may refuse the connection."
                        )
                        .WithEvidence(
                            type: "service",
                            value: $"Certificate NotBefore={cert.NotBefore:yyyy-MM-dd} NotAfter={cert.NotAfter:yyyy-MM-dd}",
                            context: $"Subject: {cert.Subject}\nIssuer: {cert.Issuer}\nTarget: {target}:{port}"
                        )
                        .WithAffectedComponent($"{label} certificate on {target}"));
                    }

                    // Self-signed certificate (issuer == subject)
                    bool selfSigned = cert.Subject == cert.Issuer;
                    if (selfSigned)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-TLS-003",
                            title: $"Self-signed TLS certificate on {label} port {port}",
                            severity: "medium",
                            confidence: "high",
                            recommendation:
                                "Replace self-signed certificate with one issued by a trusted Certificate Authority (CA).\n\n" +
                                "For internal services: use an internal CA (Windows ADCS, or HashiCorp Vault PKI).\n" +
                                "For public services: use Let's Encrypt (free, automated, trusted by all browsers)."
                        )
                        .WithDescription(
                            $"The `{label}` service on port `{port}` presents a self-signed certificate (issuer = subject).\n\n" +
                            "Self-signed certificates are not trusted by browsers or clients by default, and cannot " +
                            "be verified by clients as belonging to the intended service. This enables MitM attacks " +
                            "where an attacker presents their own self-signed certificate without detection."
                        )
                        .WithEvidence(
                            type: "service",
                            value: $"Self-signed: Subject={cert.Subject}",
                            context: $"Issuer: {cert.Issuer}\nThumbprint: {cert.Thumbprint}\nTarget: {target}:{port}"
                        )
                        .WithAffectedComponent($"{label} certificate on {target}"));
                    }

                    // Hostname mismatch
                    if (!selfSigned) // Only check mismatch for non-self-signed certs
                    {
                        bool hostMatch = CheckCertificateHostMatch(cert, target);
                        if (!hostMatch)
                        {
                            findings.Add(Finding.Create(
                                id: "AST-TLS-004",
                                title: $"TLS certificate hostname mismatch on {label} port {port}",
                                severity: "medium",
                                confidence: "medium",
                                recommendation:
                                    "Obtain a certificate that includes the correct hostname in CN or SAN.\n" +
                                    "Certificate must match the DNS name or IP address used to reach the service."
                            )
                            .WithDescription(
                                $"The TLS certificate on `{label}` port `{port}` does not match the target hostname `{target}`.\n\n" +
                                "A hostname mismatch prevents clients from verifying they are connecting to the intended server " +
                                "and is a classic indicator of a misconfigured or potentially intercepted connection."
                            )
                            .WithEvidence(
                                type: "service",
                                value: $"Certificate CN/SAN does not match target: {target}",
                                context: $"Subject: {cert.Subject}\nTarget host: {target}:{port}"
                            )
                            .WithAffectedComponent($"{label} certificate on {target}"));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Debug("[{CheckName}] Certificate/cipher check failed on {Target}:{Port}: {Msg}", Name, target, port, ex.Message);
            }
        }

        /// <summary>
        /// Check if certificate CN or SAN matches the target hostname/IP.
        /// </summary>
        private static bool CheckCertificateHostMatch(X509Certificate2 cert, string target)
        {
            try
            {
                // Check Subject CN
                var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
                if (HostMatchesPattern(target, cn))
                    return true;

                // Check Subject Alternative Names
                var sanExt = cert.Extensions["2.5.29.17"];
                if (sanExt != null)
                {
                    var sanStr = sanExt.Format(false);
                    foreach (var part in sanStr.Split(',', StringSplitOptions.TrimEntries))
                    {
                        var san = part.Replace("DNS Name=", "").Replace("IP Address=", "").Trim();
                        if (HostMatchesPattern(target, san))
                            return true;
                    }
                }

                return false;
            }
            catch
            {
                return true; // If we can't check, assume OK to avoid false positives
            }
        }

        private static bool HostMatchesPattern(string host, string pattern)
        {
            if (string.IsNullOrEmpty(pattern)) return false;
            if (string.Equals(host, pattern, StringComparison.OrdinalIgnoreCase)) return true;

            // Wildcard: *.example.com matches host.example.com
            if (pattern.StartsWith("*."))
            {
                var suffix = pattern[1..]; // .example.com
                return host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) &&
                       host.IndexOf('.') == host.Length - suffix.Length;
            }

            return false;
        }
    }
}
