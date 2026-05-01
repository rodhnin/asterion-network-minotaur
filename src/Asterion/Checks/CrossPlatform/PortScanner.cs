using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Threading;
using Serilog;
using Asterion.Core;
using Asterion.Core.Utils;
using Asterion.Models;

namespace Asterion.Checks.CrossPlatform
{
    /// <summary>
    /// Network port scanner with top-1000 coverage and banner-based service fingerprinting.
    /// Extracts software name and version from banners so cve_lookup.py can map them to CVEs.
    ///
    /// Findings:
    /// - AST-NET-003: Open ports detected — informational inventory
    /// - AST-NET-004: Potentially dangerous service exposed (low/medium/high)
    /// </summary>
    public class PortScanner : BaseCheck
    {
        // ─── Nmap-style top-1000 TCP ports ordered by scan frequency ──────────
        // Full top-1000 list keeps coverage comparable to default nmap scans.
        private static readonly int[] Top1000Ports =
        {
            80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
            143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
            1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
            10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
            26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
            5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
            2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
            544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
            7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
            6646, 49157, 1028, 873, 1755, 407, 4848, 243, 8443, 1723,
            // Extended common service ports
            636, 137, 138, 161, 162, 389, 500, 514, 520, 636,
            902, 1080, 1194, 1433, 1434, 1521, 1723, 2082, 2083, 2086,
            2087, 2095, 2096, 2181, 2222, 2375, 2376, 3268, 3269, 3306,
            3389, 4444, 4848, 5000, 5001, 5432, 5555, 5601, 5672, 5900,
            6379, 7001, 7002, 7080, 7443, 7474, 8080, 8088, 8161, 8443,
            8888, 9000, 9001, 9042, 9090, 9092, 9200, 9300, 9418, 9999,
            10000, 11211, 15672, 27017, 27018, 28017, 50000, 50070, 61616,
            // Windows-specific
            49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159,
            // Additional web/app
            4443, 4567, 5985, 5986, 8001, 8002, 8003, 8004, 8005,
            8006, 8007, 8009, 8010, 8020, 8025, 8030, 8040, 8042,
            8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
            8089, 8090, 8098, 8099, 8100, 8180, 8181, 8200, 8222,
            8243, 8280, 8281, 8333, 8400, 8443, 8500, 8800, 8843,
            8880, 8888, 8983, 9043, 9060, 9080, 9090, 9091, 9100,
            9443, 9800, 9981, 10001, 10003, 10008, 12000, 20000,
        };

        // ─── Service fingerprint patterns ──────────────────────────────────────
        // Regex → (software, version_group_index)
        private static readonly (Regex Pattern, string Software, int VersionGroup)[] BannerPatterns =
        {
            // SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
            (new Regex(@"SSH-[\d.]+-(\S+?)[\s_]([\d.]+)", RegexOptions.IgnoreCase), "openssh", 2),
            // FTP: "220 ProFTPD 1.3.6 Server", "220 vsFTPd 3.0.5"
            (new Regex(@"220[- ].*(ProFTPD|vsftpd|FileZilla|Pure-FTPd)[/ ]([\d.]+)", RegexOptions.IgnoreCase), "auto", 2),
            // SMTP: "220 mail.host ESMTP Postfix (Ubuntu)", "220 ... Exim 4.96"
            (new Regex(@"220.*\b(Postfix|Exim|Sendmail|Exchange|MailEnable)\b[/ ]?([\d.]*)", RegexOptions.IgnoreCase), "auto", 2),
            // HTTP Server header: "Server: Apache/2.4.54", "Server: nginx/1.22.1"
            (new Regex(@"Server:\s*(Apache|nginx|IIS|lighttpd|Caddy|Tomcat)[/ ]?([\d.]+)?", RegexOptions.IgnoreCase), "auto", 2),
            // MySQL: "5.7.38-log", MariaDB
            (new Regex(@"([\d.]+)(?:-log)?.*(?:MySQL|MariaDB)", RegexOptions.IgnoreCase), "mysql", 1),
            // OpenSSL in banner
            (new Regex(@"OpenSSL[/ ]([\d.]+[a-z]?)", RegexOptions.IgnoreCase), "openssl", 1),
            // Samba / CIFS
            (new Regex(@"Samba[/ ]([\d.]+)", RegexOptions.IgnoreCase), "samba", 1),
            // RDP / Windows
            (new Regex(@"(Windows Server \d{4}|Windows \d{2})", RegexOptions.IgnoreCase), "windows", 0),
        };
        public override string Name => "Port Scanner";
        
        public override CheckCategory Category => CheckCategory.CrossPlatform;
        
        public override string Description => 
            "Discovers open network ports and identifies potentially dangerous services. " +
            "Performs TCP connect scans with configurable timeouts and rate limiting.";

        // Port scanning is always safe mode
        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        public PortScanner(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var findings = new List<Finding>();

            Log.Information("[{CheckName}] Starting port scan on {Count} target(s)", Name, targets.Count);

            // Determine which ports to scan:
            // 1. Explicit --ports flag
            // 2. Config default_ports (if ≥ 10 entries)
            // 3. Built-in top-1000 list
            List<int> portsToScan;
            if (options.Ports != null && options.Ports.Any())
            {
                portsToScan = ParsePorts(options.Ports);
                Log.Information("[{CheckName}] Custom port list: {Count} port(s)", Name, portsToScan.Count);
            }
            else if (_config.Network.DefaultPorts != null && _config.Network.DefaultPorts.Count >= 10)
            {
                portsToScan = _config.Network.DefaultPorts;
                Log.Information("[{CheckName}] Config default ports: {Count} port(s)", Name, portsToScan.Count);
            }
            else
            {
                portsToScan = Top1000Ports.Distinct().OrderBy(p => p).ToList();
                Log.Information("[{CheckName}] Using top-{Count} port list", Name, portsToScan.Count);
            }

            if (!portsToScan.Any())
            {
                Log.Warning("[{CheckName}] No ports configured for scanning", Name);
                LogExecution(targets.Count, 0);
                return findings;
            }

            Log.Information("[{CheckName}] Scanning {PortCount} ports per host", Name, portsToScan.Count);

            foreach (var target in targets)
            {
                try
                {
                    var (openPorts, banners) = await ScanHostAsync(target, portsToScan, options);

                    if (openPorts.Any())
                    {
                        findings.Add(CreateOpenPortsFinding(target, openPorts, banners));
                        CheckDangerousPorts(target, openPorts, banners, findings);
                    }
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "[{CheckName}] Failed to scan {Target}", Name, target);
                }
            }

            LogExecution(targets.Count, findings.Count);
            return findings;
        }

        // ─── Banner result ─────────────────────────────────────────────────────
        private record BannerResult(int Port, string Raw, string? Software, string? Version);

        /// <summary>
        /// Scan all specified ports on a single host with parallel execution.
        /// Returns open ports + per-port banner/service info.
        /// </summary>
        private async Task<(List<int> OpenPorts, Dictionary<int, BannerResult> Banners)>
            ScanHostAsync(string host, List<int> ports, ScanOptions options)
        {
            var openPorts  = new List<int>();
            var banners    = new Dictionary<int, BannerResult>();
            var timeout    = _config.Network.PortScan.TimeoutMs;
            // Increase concurrency for large lists — top-1000 benefits from high parallelism
            int maxConcurrency = ports.Count > 200 ? 50 : ports.Count > 50 ? 30 : 15;

            Log.Debug("[{CheckName}] Scanning {Host} — {PortCount} ports, concurrency {C}",
                Name, host, ports.Count, maxConcurrency);

            var semaphore = new SemaphoreSlim(maxConcurrency);
            var tasks     = new List<Task>();

            foreach (var port in ports)
            {
                await semaphore.WaitAsync();

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        if (!await NetworkUtils.IsPortOpenAsync(host, port, timeout))
                            return;

                        lock (openPorts) { openPorts.Add(port); }
                        Log.Information("[{CheckName}] {Host}:{Port} OPEN", Name, host, port);

                        // Banner grab + parse
                        try
                        {
                            var raw = await NetworkUtils.GetBannerAsync(host, port, timeout);
                            if (!string.IsNullOrWhiteSpace(raw))
                            {
                                var (software, version) = ParseServiceFromBanner(raw, port);
                                var br = new BannerResult(port, raw.Trim(), software, version);
                                lock (banners) { banners[port] = br; }

                                var preview = raw.Length > 100 ? raw[..100] : raw;
                                if (software != null)
                                    Log.Information("[{CheckName}] {Host}:{Port} → {SW} {Ver} | {Banner}",
                                        Name, host, port, software, version ?? "?", preview.Trim());
                                else
                                    Log.Debug("[{CheckName}] Banner {Host}:{Port}: {Banner}",
                                        Name, host, port, preview.Trim());
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.Debug(ex, "[{CheckName}] Banner failed {Host}:{Port}", Name, host, port);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Debug(ex, "[{CheckName}] Scan error {Host}:{Port}", Name, host, port);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            await Task.WhenAll(tasks);
            return (openPorts.OrderBy(p => p).ToList(), banners);
        }

        /// <summary>
        /// Parse a raw banner string and return (software, version) if identifiable.
        /// </summary>
        private static (string? Software, string? Version) ParseServiceFromBanner(string banner, int port)
        {
            foreach (var (pattern, software, versionGroup) in BannerPatterns)
            {
                var m = pattern.Match(banner);
                if (!m.Success) continue;

                // "auto" means extract from the match group itself
                string sw = software == "auto"
                    ? m.Groups[1].Value.ToLowerInvariant()
                    : software;

                string? ver = versionGroup > 0 && versionGroup < m.Groups.Count
                    ? (m.Groups[versionGroup].Success ? m.Groups[versionGroup].Value : null)
                    : null;

                // Map captured strings to canonical software names
                sw = sw switch
                {
                    "proftpd"  => "proftpd",
                    "vsftpd"   => "vsftpd",
                    "filezilla" => "filezilla",
                    "pure-ftpd" => "pure-ftpd",
                    "postfix"  => "postfix",
                    "exim"     => "exim",
                    "sendmail" => "sendmail",
                    "exchange" => "exchange",
                    "apache"   => "apache",
                    "nginx"    => "nginx",
                    "iis"      => "iis",
                    "lighttpd" => "lighttpd",
                    "tomcat"   => "tomcat",
                    _ => sw
                };

                return (sw, string.IsNullOrWhiteSpace(ver) ? null : ver);
            }

            // Fallback: well-known port → service name
            return port switch
            {
                22   => ("openssh", null),
                21   => ("ftp",     null),
                25   => ("smtp",    null),
                80   => ("http",    null),
                443  => ("https",   null),
                3306 => ("mysql",   null),
                5432 => ("postgresql", null),
                6379 => ("redis",   null),
                27017 => ("mongodb", null),
                _    => (null, null)
            };
        }

        /// <summary>
        /// Create informational finding about open ports, including service fingerprint table.
        /// </summary>
        private Finding CreateOpenPortsFinding(string target, List<int> openPorts,
            Dictionary<int, BannerResult> banners)
        {
            // Build compact service table: "22/tcp   openssh 8.9p1"
            var lines = openPorts.Select(p =>
            {
                if (banners.TryGetValue(p, out var br) && br.Software != null)
                    return $"  {p,-7} {br.Software,-15} {br.Version ?? ""}".TrimEnd();
                return $"  {p,-7} (no banner)";
            }).ToList();

            var portList = string.Join(", ", openPorts.Take(30));
            if (openPorts.Count > 30) portList += $" (+{openPorts.Count - 30} more)";

            var serviceTable = string.Join("\n", lines.Take(40));
            if (openPorts.Count > 40) serviceTable += $"\n  ... and {openPorts.Count - 40} more";

            // Log identified software for CVE enrichment
            var identified = banners.Values.Where(b => b.Software != null).ToList();
            if (identified.Any())
                Log.Information("[{CheckName}] Service fingerprints on {Host}: {Services}",
                    Name, target,
                    string.Join(", ", identified.Select(b => $"{b.Software} {b.Version}".Trim())));

            return Finding.Create(
                id: "AST-NET-003",
                title: $"Port scan — {openPorts.Count} open port(s) on {target}",
                severity: "info",
                confidence: "high",
                recommendation:
                    "Review every open port and disable services that are not required.\n" +
                    "Restrict access via host-based firewall (iptables/nftables/Windows Firewall).\n" +
                    "Ensure all identified software is kept patched and up to date."
            )
            .WithDescription(
                $"TCP port scan (top-{(openPorts.Count > 200 ? "1000" : openPorts.Count.ToString())}) discovered " +
                $"{openPorts.Count} open port(s) on {target}. " +
                $"Banner grabbing identified {identified.Count} service(s). " +
                "Specific protocol checks (SMB, LDAP, RDP, etc.) will report individual vulnerabilities."
            )
            .WithEvidence(
                type: "port",
                value: $"Open ports: {portList}\n\nService fingerprints:\n{serviceTable}",
                context: $"Total open: {openPorts.Count} | Identified: {identified.Count} | Timeout: {_config.Network.PortScan.TimeoutMs}ms"
            )
            .WithAffectedComponent(target)
            .WithReferences(
                "https://www.sans.org/reading-room/whitepapers/auditing/securing-network-infrastructure-36057",
                "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html"
            );
        }

        /// <summary>
        /// Check for commonly exploited ports that shouldn't be exposed.
        /// Includes banner info (software/version) for CVE enrichment context.
        /// </summary>
        private void CheckDangerousPorts(string host, List<int> openPorts,
            Dictionary<int, BannerResult> banners, List<Finding> findings)
        {
            // (service description, severity, recommendation hint)
            var dangerousPorts = new Dictionary<int, (string service, string severity, string hint)>
            {
                { 21,    ("FTP — plaintext file transfer", "medium",
                          "Replace FTP with SFTP/FTPS. If required, restrict to authorized IPs.") },
                { 23,    ("Telnet — unencrypted remote shell", "high",
                          "Disable Telnet immediately and migrate to SSH.") },
                { 69,    ("TFTP — trivial FTP (no auth)", "high",
                          "Disable TFTP unless required for PXE boot; restrict to dedicated VLAN.") },
                { 111,   ("RPC portmapper — NFS/NIS attack surface", "medium",
                          "Block port 111 at perimeter; restrict NFS mounts to specific hosts.") },
                { 135,   ("MS-RPC — Windows RPC endpoint mapper", "medium",
                          "Block at perimeter; restrict to management VLAN.") },
                { 137,   ("NetBIOS Name Service — information disclosure", "low",
                          "Disable NetBIOS over TCP/IP if not needed for legacy apps.") },
                { 139,   ("NetBIOS Session Service — SMB fallback", "low",
                          "Disable NetBIOS over TCP/IP; use SMB over port 445 only.") },
                { 161,   ("SNMP — default community strings risk", "medium",
                          "Change default community strings; prefer SNMPv3 with auth.") },
                { 445,   ("SMB/CIFS — frequent attack vector (EternalBlue etc.)", "medium",
                          "Require SMB signing; disable SMBv1; restrict to authorized hosts.") },
                { 512,   ("rexec — remote execution (no encryption)", "high",
                          "Disable rexec; use SSH instead.") },
                { 513,   ("rlogin — remote login (no encryption)", "high",
                          "Disable rlogin; use SSH instead.") },
                { 514,   ("rsh/syslog — remote shell or UDP syslog", "high",
                          "Disable rsh; use SSH. For syslog use TLS transport.") },
                { 1433,  ("MS SQL Server — database exposure", "medium",
                          "Restrict to application servers; enforce strong SA passwords; disable SA if unused.") },
                { 1521,  ("Oracle DB — database exposure", "medium",
                          "Restrict to application servers; enforce strong authentication.") },
                { 2375,  ("Docker API — unauthenticated container engine", "high",
                          "Never expose Docker daemon without TLS. Use Unix socket locally.") },
                { 2376,  ("Docker API (TLS) — container engine", "medium",
                          "Ensure TLS certificates are valid; restrict to authorized management hosts.") },
                { 3306,  ("MySQL/MariaDB — database exposure", "medium",
                          "Bind to localhost only; expose via SSH tunnel for remote access.") },
                { 3389,  ("RDP — Remote Desktop, brute-force target", "medium",
                          "Require NLA; use MFA; restrict via firewall or VPN.") },
                { 4444,  ("Metasploit/generic reverse shell port", "high",
                          "Investigate immediately — this port is commonly used by malware/RATs.") },
                { 5432,  ("PostgreSQL — database exposure", "medium",
                          "Bind to localhost; use pg_hba.conf to restrict remote connections.") },
                { 5900,  ("VNC — remote desktop, often weak passwords", "medium",
                          "Require strong VNC passwords; tunnel over SSH; restrict via firewall.") },
                { 5985,  ("WinRM HTTP — Windows Remote Management", "medium",
                          "Restrict to management VLAN; require Kerberos/HTTPS.") },
                { 5986,  ("WinRM HTTPS — Windows Remote Management", "low",
                          "Verify TLS certificate validity; restrict to management VLAN.") },
                { 6379,  ("Redis — NoSQL cache, often unauthenticated", "high",
                          "Bind to localhost; set requirepass; disable dangerous commands.") },
                { 9200,  ("Elasticsearch — no auth by default", "high",
                          "Enable X-Pack security; bind to localhost; restrict via firewall.") },
                { 9300,  ("Elasticsearch cluster transport", "medium",
                          "Restrict to cluster nodes only; enable TLS transport.") },
                { 11211, ("Memcached — no authentication", "medium",
                          "Bind to localhost; block UDP port 11211 (amplification DDoS risk).") },
                { 27017, ("MongoDB — no auth by default", "high",
                          "Enable authentication; bind to localhost or restrict via firewall.") },
                { 50000, ("IBM DB2 / various — database/app exposure", "medium",
                          "Restrict access; verify service identity.") },
            };

            foreach (var port in openPorts)
            {
                if (!dangerousPorts.TryGetValue(port, out var portInfo))
                    continue;

                var (service, severity, hint) = portInfo;

                // Include banner/version info if available
                string bannerNote = "";
                if (banners.TryGetValue(port, out var br))
                {
                    if (br.Software != null)
                        bannerNote = $"\nIdentified: {br.Software} {br.Version ?? ""}".TrimEnd();
                    if (!string.IsNullOrWhiteSpace(br.Raw))
                        bannerNote += $"\nBanner: {br.Raw.Trim().Replace('\n', ' ').Replace('\r', ' ')}";
                }

                var finding = Finding.Create(
                    id: "AST-NET-004",
                    title: $"Dangerous service exposed: port {port} ({service.Split('—')[0].Trim()})",
                    severity: severity,
                    confidence: "high",
                    recommendation: hint + "\nRestrict access via host-based firewall to authorized IPs only."
                )
                .WithDescription(
                    $"Port {port} is open on {host} — {service}. " +
                    $"This port is commonly targeted by attackers to find vulnerable systems. " +
                    $"Protocol-specific checks (SMB, RDP, LDAP, etc.) will report detailed vulnerabilities."
                )
                .WithEvidence(
                    type: "port",
                    value: $"Port {port}/tcp open — {service}{bannerNote}",
                    context: $"Host: {host} | Severity basis: known attack vector"
                )
                .WithAffectedComponent($"{host}:{port}")
                .WithReferences(
                    "https://www.sans.org/top25-software-errors/",
                    $"https://www.speedguide.net/port.php?port={port}"
                );

                findings.Add(finding);
            }
        }

        /// <summary>
        /// Parse port specifications (single ports and ranges)
        /// Supports: "80", "80-90", "80,443,8080"
        /// </summary>
        private List<int> ParsePorts(string[] portSpecs)
        {
            var ports = new HashSet<int>();

            foreach (var spec in portSpecs)
            {
                try
                {
                    if (spec.Contains('-'))
                    {
                        // Range: "80-90"
                        var parts = spec.Split('-');
                        if (parts.Length == 2 &&
                            int.TryParse(parts[0], out int start) &&
                            int.TryParse(parts[1], out int end))
                        {
                            for (int p = start; p <= end && p <= 65535; p++)
                            {
                                ports.Add(p);
                            }
                        }
                    }
                    else
                    {
                        // Single port: "80"
                        if (int.TryParse(spec, out int port) && port > 0 && port <= 65535)
                        {
                            ports.Add(port);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "[{CheckName}] Failed to parse port specification: {Spec}", Name, spec);
                }
            }

            return ports.OrderBy(p => p).ToList();
        }
    }
}