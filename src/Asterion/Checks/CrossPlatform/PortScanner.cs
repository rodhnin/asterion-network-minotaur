using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using Serilog;
using Asterion.Core;
using Asterion.Core.Utils;
using Asterion.Models;

namespace Asterion.Checks.CrossPlatform
{
    /// <summary>
    /// Basic network port scanner.
    /// Discovers open ports and identifies potentially dangerous services.
    /// 
    /// Findings:
    /// - AST-NET-003: Open ports detected (informational)
    /// - AST-NET-004: Potentially dangerous service exposed (low/medium/high)
    /// </summary>
    public class PortScanner : BaseCheck
    {
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

            // Determine which ports to scan
            var portsToScan = options.Ports != null && options.Ports.Any()
                ? ParsePorts(options.Ports)
                : _config.Network.DefaultPorts;

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
                    var openPorts = await ScanHostAsync(target, portsToScan, options);

                    if (openPorts.Any())
                    {
                        // Create informational finding about open ports
                        findings.Add(CreateOpenPortsFinding(target, openPorts));

                        // Check for particularly dangerous ports
                        await CheckDangerousPortsAsync(target, openPorts, findings);
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

        /// <summary>
        /// Scan all specified ports on a single host with parallel execution
        /// </summary>
        private async Task<List<int>> ScanHostAsync(string host, List<int> ports, ScanOptions options)
        {
            var openPorts = new List<int>();
            var timeout = _config.Network.PortScan.TimeoutMs;
            
            // Determine parallelism based on port count
            int maxConcurrency = ports.Count > 100 ? 20 : 10;
            
            Log.Debug("[{CheckName}] Scanning {Host} for {PortCount} ports (concurrency: {Concurrency})", 
                Name, host, ports.Count, maxConcurrency);
            
            var semaphore = new SemaphoreSlim(maxConcurrency);
            var tasks = new List<Task>();
            
            foreach (var port in ports)
            {
                await semaphore.WaitAsync();
                
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        if (await NetworkUtils.IsPortOpenAsync(host, port, timeout))
                        {
                            lock (openPorts)
                            {
                                openPorts.Add(port);
                            }
                            
                            Log.Information("[{CheckName}] {Host}:{Port} is OPEN", Name, host, port);
                            
                            // Try to grab banner for service identification
                            try
                            {
                                var banner = await NetworkUtils.GetBannerAsync(host, port, timeout);
                                if (!string.IsNullOrEmpty(banner))
                                {
                                    Log.Debug("Banner from {Host}:{Port} - {Banner}", host, port, banner.Trim());
                                    Log.Information("[{CheckName}] Banner from {Host}:{Port} - {Banner}",
                                        Name, host, port, banner.Substring(0, Math.Min(banner.Length, 100)));
                                }
                            }
                            catch (Exception ex)
                            {
                                Log.Debug(ex, "[{CheckName}] Failed to get banner from {Host}:{Port}", Name, host, port);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Debug(ex, "[{CheckName}] Error scanning {Host}:{Port}", Name, host, port);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }
            
            await Task.WhenAll(tasks);
            
            return openPorts.OrderBy(p => p).ToList();
        }

        /// <summary>
        /// Create informational finding about open ports
        /// </summary>
        private Finding CreateOpenPortsFinding(string target, List<int> openPorts)
        {
            var portList = string.Join(", ", openPorts.Take(20));
            if (openPorts.Count > 20)
            {
                portList += $" (and {openPorts.Count - 20} more)";
            }

            // Using Finding.Create() if it exists (builder pattern)
            // Otherwise use CreateFinding() helper from BaseCheck
            return Finding.Create(
                id: "AST-NET-003",
                title: $"Open ports detected on {target}",
                severity: "info",
                confidence: "high",
                recommendation: "Review open ports and close unnecessary services. " +
                                "Each open port increases the attack surface. " +
                                "Ensure firewall rules restrict access to authorized IPs only."
            )
            .WithDescription(
                $"Port scan discovered {openPorts.Count} open port(s) on target {target}. " +
                "Open ports indicate running services that may be vulnerable to attacks. " +
                "This is informational - specific service checks will identify actual vulnerabilities."
            )
            .WithEvidence(
                type: "port",
                value: $"Open ports: {portList}",
                context: $"Total: {openPorts.Count} ports, Timeout: {_config.Network.PortScan.TimeoutMs}ms"
            )
            .WithAffectedComponent($"{target}")
            .WithReferences(
                "https://www.sans.org/reading-room/whitepapers/auditing/securing-network-infrastructure-36057",
                "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html"
            );
        }

        /// <summary>
        /// Check for commonly exploited ports that shouldn't be exposed
        /// </summary>
        private async Task CheckDangerousPortsAsync(string host, List<int> openPorts, List<Finding> findings)
        {
            var dangerousPorts = new Dictionary<int, (string service, string severity)>
            {
                { 23, ("Telnet (unencrypted, obsolete)", "high") },
                { 135, ("RPC (Windows, often exploited)", "medium") },
                { 139, ("NetBIOS (information disclosure)", "low") },
                { 445, ("SMB (frequent attack vector)", "medium") },
                { 3389, ("RDP (brute force target)", "medium") },
                { 5900, ("VNC (often weak passwords)", "medium") },
                { 1433, ("MS SQL (database exposure)", "medium") },
                { 3306, ("MySQL (database exposure)", "medium") },
                { 5432, ("PostgreSQL (database exposure)", "medium") },
                { 27017, ("MongoDB (NoSQL exposure)", "medium") },
                { 6379, ("Redis (NoSQL exposure)", "medium") },
                { 9200, ("Elasticsearch (data exposure)", "medium") }
            };

            foreach (var port in openPorts)
            {
                if (dangerousPorts.TryGetValue(port, out var portInfo))
                {
                    var (service, severity) = portInfo;

                    var finding = Finding.Create(
                        id: "AST-NET-004",
                        title: $"Potentially dangerous service exposed: {service}",
                        severity: severity,
                        confidence: "high",
                        recommendation: $"Service on port {port} ({service}) is exposed. " +
                                        $"If not required, disable this service. " +
                                        $"If required, restrict access via firewall to authorized IPs only. " +
                                        $"Ensure the service is patched and securely configured."
                    )
                    .WithDescription(
                        $"Port {port} is open on {host}, running a service known to be a frequent attack target. " +
                        $"Attackers commonly scan for these ports to find vulnerable systems. " +
                        $"Additional service-specific checks will determine if there are actual vulnerabilities."
                    )
                    .WithEvidence(
                        type: "port",
                        value: $"Port {port} open ({service})",
                        context: $"Host: {host}"
                    )
                    .WithAffectedComponent($"{host}:{port}")
                    .WithReferences(
                        "https://www.sans.org/top25-software-errors/",
                        $"https://www.speedguide.net/port.php?port={port}"
                    );

                    findings.Add(finding);
                }
            }

            await Task.CompletedTask;
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