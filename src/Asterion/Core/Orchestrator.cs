using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using Serilog;
using Asterion.Checks;
using Asterion.Core.Output;
using Asterion.Core.Utils;
using Asterion.Models;
using System.Text.Json;

namespace Asterion.Core
{
    /// <summary>
    /// Orchestrates the execution of security checks
    /// Manages threading, rate limiting, and report generation
    /// </summary>
    public class Orchestrator
    {
        private readonly Config _config;
        private readonly List<ICheck> _checks;
        private readonly SemaphoreSlim _rateLimiter;
        private DateTime _lastRequestTime = DateTime.MinValue;

        public Orchestrator(Config config)
        {
            _config = config;
            _checks = new List<ICheck>();
            _rateLimiter = new SemaphoreSlim(1, 1);
            
            RegisterChecks();
        }
        
        /// <summary>
        /// Get effective rate limit, respecting CLI overrides and scan mode.
        /// Priority: 1) CLI --rate (no validation needed), 2) mode-based config
        /// Note: Consent validation happens in ExecuteScanAsync, not here
        /// </summary>
        private double GetEffectiveRateLimit(ScanOptions options)
        {
            // PRIORIDAD 1: CLI override (--rate parameter)
            if (options.RateLimit > 0)
            {
                Log.Information("Rate limit: {Rate} req/s (CLI override)", options.RateLimit);
                return options.RateLimit;
            }
            
            // PRIORIDAD 2: Mode-based default
            double configRate = options.Mode.ToLower() == "aggressive"
                ? _config.Scan.RateLimit.AggressiveMode  // 10.0 req/s
                : _config.Scan.RateLimit.SafeMode;       // 5.0 req/s
            
            Log.Information("Rate limit: {Rate} req/s (default for mode: {Mode})", 
                configRate, options.Mode);
            return configRate;
        }
        
        /// <summary>
        /// Register checks based on platform and configuration
        /// </summary>
        private void RegisterChecks()
        {
            bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            bool isLinux   = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

            Log.Information("Registering checks for platform: {Platform}",
                isWindows ? "Windows" : isLinux ? "Linux" : "Unknown");

            // ============================================================================
            // CROSS-PLATFORM CHECKS (always registered)
            // ============================================================================
            Log.Debug("Registering cross-platform checks");
            _checks.Add(new Checks.CrossPlatform.PortScanner(_config));
            _checks.Add(new Checks.CrossPlatform.SmbScanner(_config));
            _checks.Add(new Checks.CrossPlatform.RdpScanner(_config));
            _checks.Add(new Checks.CrossPlatform.LdapScanner(_config));
            _checks.Add(new Checks.CrossPlatform.KerberosScanner(_config));
            _checks.Add(new Checks.CrossPlatform.SnmpScanner(_config));
            _checks.Add(new Checks.CrossPlatform.DnsScanner(_config));
            _checks.Add(new Checks.CrossPlatform.FtpScanner(_config));

            // ============================================================================
            // WINDOWS-SPECIFIC CHECKS (compiled only on Windows)
            // ============================================================================
#if WINDOWS
            {
                Log.Debug("Registering Windows-specific checks");
                if (_config.Windows.CheckFirewall)
                    _checks.Add(new Checks.CrossPlatform.Windows.WinFirewallCheck(_config));
                if (_config.Windows.CheckRegistry)
                    _checks.Add(new Checks.CrossPlatform.Windows.WinRegistryCheck(_config));
                if (_config.Windows.CheckAdPolicies)
                    _checks.Add(new Checks.CrossPlatform.Windows.AdPolicyCheck(_config));
                if (_config.Windows.CheckServices)
                    _checks.Add(new Checks.CrossPlatform.Windows.WinServicesCheck(_config));
                _checks.Add(new Checks.CrossPlatform.Windows.PrivEscCheckWin(_config));
            }
#endif

            // ============================================================================
            // LINUX-SPECIFIC CHECKS (always registered, but only executed if target is Linux)
            // ============================================================================
            if (isLinux)
            {
                Log.Debug("Registering Linux-specific checks");
                if (_config.Linux.CheckFirewall)
                    _checks.Add(new Checks.Linux.LinuxFirewallCheck(_config));
                if (_config.Linux.CheckSambaConfig)
                    _checks.Add(new Checks.Linux.SambaNfsCheck(_config));
                if (_config.Linux.CheckSshConfig)
                    _checks.Add(new Checks.Linux.SshConfigCheck(_config));
                if (_config.Linux.CheckSuidBinaries)
                    _checks.Add(new Checks.Linux.PrivEscCheckLinux(_config));
            }

            Log.Information("Registered {Count} checks", _checks.Count);
        }

        /// <summary>
        /// Execute a complete security scan with Ctrl+C support
        /// </summary>
        public async Task<ScanResult> ExecuteScanAsync(ScanOptions options)
        {
            var stopwatch = Stopwatch.StartNew();
            var findings = new List<Finding>();
            int requestsSent = 0;

            using var cts = new CancellationTokenSource();
            var cancellationToken = cts.Token;

            // Register Ctrl+C handler
            Console.CancelKeyPress += (sender, e) =>
            {
                // Prevent immediate termination
                e.Cancel = true;
                
                // Signal cancellation
                Log.Warning("Scan interrupted by user (Ctrl+C)");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n⚠ Scan interrupted - saving partial results...");
                Console.ResetColor();
                
                cts.Cancel();
            };

            ScanResult result;

            try
            {
                Log.Information("Starting scan execution");
                Log.Information("Target: {Target}, Mode: {Mode}", options.Target, options.Mode);

                // VALIDATION: Aggressive mode requires verified consent
                if (options.Mode.ToLower() == "aggressive")
                {
                    Log.Information("Aggressive mode detected - checking for verified consent token in database");
                    
                    var database = new Database(_config);
                    var verifiedToken = await database.GetVerifiedConsentTokenAsync(options.Target);
                    
                    if (string.IsNullOrEmpty(verifiedToken))
                    {
                        Log.Error("No verified consent token found for domain: {Domain}", options.Target);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n✗ ERROR: Aggressive mode requires consent verification");
                        Console.ResetColor();
                        Console.WriteLine($"\nNo verified consent found for: {options.Target}");
                        Console.WriteLine("\nSteps to enable aggressive mode:");
                        Console.WriteLine("  1. Generate token:  ast consent generate --domain <domain>");
                        Console.WriteLine("  2. Verify token:    ast consent verify --method <http|dns|ssh> --domain <domain> --token <token>");
                        Console.WriteLine("  3. Run scan:        ast scan --target <target> --mode aggressive");
                        
                        throw new InvalidOperationException($"No verified consent token found for domain: {options.Target}");
                    }
                    
                    Log.Information("✓ Verified consent token found for {Domain}: {Token}", options.Target, verifiedToken);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"✓ Consent verified for domain: {options.Target}");
                    Console.ResetColor();
                }

                // Configure rate limiter (CLI override takes precedence)
                double rateLimit = GetEffectiveRateLimit(options);

                // Parse target(s)
                var targets = CidrParser.ParseTargets(options.Target);
                Log.Information("Discovered {Count} target(s) to scan", targets.Count);

                // ============================================================================
                // VALIDATION: Check if targets list is empty
                // ============================================================================
                if (targets.Count == 0)
                {
                    Log.Warning("No targets to scan (empty target list)");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("\n⚠ No targets to scan. Operation cancelled or invalid target.");
                    Console.ResetColor();
                    
                    throw new InvalidOperationException("No targets to scan");
                }

                // ============================================================================
                // Detect platform and warn about --auth limitations on Linux
                // ============================================================================
                if (!string.IsNullOrEmpty(options.AuthCredentials) && string.IsNullOrEmpty(options.SshCredentials))
                {
                    var firstTarget = targets.FirstOrDefault();
                    if (!string.IsNullOrEmpty(firstTarget) && !IsLocalTarget(firstTarget))
                    {
                        var isLinux = await DetectLinuxTargetAsync(firstTarget);
                        if (isLinux)
                        {
                            Log.Warning("Linux target detected with --auth credentials");
                            Log.Warning("--auth works for network-level checks but cannot perform Linux system auditing");
                            
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine($"\n⚠ WARNING: --auth provided for Linux target: {firstTarget}");
                            Console.ResetColor();
                            Console.WriteLine("  --auth works for network-level checks (SMB, RDP, LDAP, FTP, etc.)");
                            Console.WriteLine("  but CANNOT perform Linux system-level auditing.");
                            Console.WriteLine();
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine("  ℹ For comprehensive Linux security auditing:");
                            Console.WriteLine("    • Use --ssh <user:password> (SSH authentication)");
                            Console.WriteLine($"      ast scan --target {firstTarget} --ssh \"user:password\"");
                            Console.WriteLine();
                            Console.WriteLine("    SSH provides access to:");
                            Console.WriteLine("      - Firewall configuration (iptables/ufw)");
                            Console.WriteLine("      - SSH daemon hardening (sshd_config)");
                            Console.WriteLine("      - Samba/NFS share permissions");
                            Console.WriteLine("      - SUID binaries and privilege escalation vectors");
                            Console.WriteLine("      - Critical file permissions (/etc/shadow, sudoers)");
                            Console.ResetColor();
                            Console.WriteLine();
                            Console.WriteLine("  Continuing with CrossPlatform network checks only...");
                            Console.WriteLine();
                            
                            await Task.Delay(2500);
                        }
                    }
                }

                // ============================================================================
                // SCAN MODE DETECTION
                // ============================================================================
                bool hasLocalTarget = targets.Any(IsLocalTarget);
                bool hasRemoteTarget = targets.Any(t => !IsLocalTarget(t));
                bool hasSshCredentials = !string.IsNullOrEmpty(options.SshCredentials);

                string scanMode;
                string? remotePlatform = null;
                SshConnectionManager? sshManager = null;

                if (hasLocalTarget && !hasRemoteTarget)
                {
                    scanMode = "local";
                    Log.Information("Local scan detected: analyzing localhost");
                }
                else if (hasRemoteTarget && !hasSshCredentials)
                {
                    scanMode = "remote";
                    Log.Information("Remote scan detected: analyzing {Count} remote target(s)", targets.Count);
                }
                else if (hasRemoteTarget && hasSshCredentials)
                {
                    scanMode = "remote-ssh";
                    Log.Information("SSH credentials provided, attempting remote authenticated access");

                    var sshTarget = targets.First(t => !IsLocalTarget(t));
                    var (username, password) = ParseSshCredentials(options.SshCredentials!);

                    sshManager = new SshConnectionManager(sshTarget, username, password);
                    bool sshConnected = await sshManager.ConnectAsync();

                    if (!sshConnected)
                    {
                        Log.Error("SSH connection failed to {Target}, falling back to remote scan mode", sshTarget);
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"\n⚠ WARNING: SSH connection failed to {sshTarget}");
                        Console.WriteLine("Continuing with CrossPlatform checks only (no local system auditing)\n");
                        Console.ResetColor();

                        scanMode = "remote";
                        sshManager?.Dispose();
                        sshManager = null;
                    }
                    else
                    {
                        remotePlatform = await sshManager.DetectPlatformAsync();

                        if (remotePlatform == "Linux")
                        {
                            scanMode = "remote-ssh-linux";
                            Log.Information("SSH Linux scan mode activated for {Target}", sshTarget);
                            
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"\n✓ SSH connection established to Linux target: {sshTarget}");
                            Console.ResetColor();
                            Console.WriteLine("  → CrossPlatform checks: Network services (SMB, RDP, LDAP, etc.)");
                            Console.WriteLine("  → Linux checks: Firewall, SSH config, Samba/NFS, privilege escalation");
                            Console.WriteLine();
                        }
                        else if (remotePlatform == "Windows")
                        {
                            Log.Warning("SSH target is Windows - SSH-based checks are LIMITED on Windows");
                            Log.Warning("For comprehensive Windows auditing, use --auth with WinRM/RPC instead");
                            
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine($"\n⚠ WARNING: SSH connection to Windows target: {sshTarget}");
                            Console.ResetColor();
                            Console.WriteLine("  SSH-based local system checks are NOT supported on Windows.");
                            Console.WriteLine();
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine("  ℹ For comprehensive Windows auditing:");
                            Console.WriteLine("    • Use --auth <DOMAIN\\user:password> (WinRM/WMI authentication)");
                            Console.WriteLine("    • Or run Asterion locally on the Windows target");
                            Console.ResetColor();
                            Console.WriteLine();
                            Console.WriteLine("  Continuing with CrossPlatform network checks only...");
                            Console.WriteLine();

                            scanMode = "remote";
                            sshManager?.Dispose();
                            sshManager = null;
                        }
                        else
                        {
                            Log.Warning("SSH target platform is {Platform} - local checks may not be available", remotePlatform);
                            
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine($"\n⚠ WARNING: SSH target platform: {remotePlatform}");
                            Console.ResetColor();
                            Console.WriteLine("  SSH-based local checks only support Linux targets.");
                            Console.WriteLine("  Continuing with CrossPlatform network checks only...");
                            Console.WriteLine();

                            scanMode = "remote";
                            sshManager?.Dispose();
                            sshManager = null;
                        }
                    }
                }
                else
                {
                    scanMode = "mixed";
                    Log.Information("Mixed scan: {Local} local + {Remote} remote targets",
                        targets.Count(IsLocalTarget),
                        targets.Count(t => !IsLocalTarget(t)));
                }

                // ============================================================================
                // FILTER CHECKS & EXECUTE WITH CANCELLATION SUPPORT
                // ============================================================================
                var checksToRun = FilterChecksForScan(_checks, scanMode, remotePlatform);
                Log.Information("Executing {Active} of {Total} checks", checksToRun.Count, _checks.Count);

                var semaphore = new SemaphoreSlim(options.MaxThreads);
                var tasks = new List<Task>();
                int completedChecks = 0;

                foreach (var check in checksToRun)
                {
                    // ============================================================================
                    // CHECK FOR CANCELLATION BEFORE STARTING EACH CHECK
                    // ============================================================================
                    if (cancellationToken.IsCancellationRequested)
                    {
                        Log.Information("Scan cancelled - {Completed} of {Total} checks completed",
                            completedChecks, checksToRun.Count);
                        break;
                    }

                    await semaphore.WaitAsync(cancellationToken);

                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            // Check for cancellation before executing
                            if (cancellationToken.IsCancellationRequested)
                            {
                                return;
                            }

                            // Apply rate limiting
                            await ApplyRateLimit(rateLimit);

                            Log.Debug("Executing check: {CheckName}", check.Name);

                            // Set SSH manager for Linux checks
                            if (check.Category == CheckCategory.Linux &&
                                scanMode == "remote-ssh-linux" &&
                                sshManager != null)
                            {
                                if (check is BaseCheck baseCheck)
                                {
                                    baseCheck.SetSshManager(sshManager);
                                    Log.Debug("[{CheckName}] SSH manager assigned for remote execution", check.Name);
                                }
                            }

                            // Execute check
                            var checkFindings = await check.ExecuteAsync(targets, options);

                            if (checkFindings.Any())
                            {
                                lock (findings)
                                {
                                    findings.AddRange(checkFindings);
                                }

                                Log.Information("Check {CheckName} found {Count} issue(s)",
                                    check.Name, checkFindings.Count);
                            }

                            Interlocked.Increment(ref requestsSent);
                            Interlocked.Increment(ref completedChecks);
                        }
                        catch (OperationCanceledException)
                        {
                            Log.Debug("Check {CheckName} cancelled", check.Name);
                        }
                        catch (Exception ex)
                        {
                            Log.Error(ex, "Check {CheckName} failed", check.Name);
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }, cancellationToken));
                }

                // Wait for all checks to complete OR cancellation
                try
                {
                    await Task.WhenAll(tasks);
                }
                catch (OperationCanceledException)
                {
                    Log.Information("Scan cancelled by user - generating partial report");
                }

                // Clean up SSH connection
                sshManager?.Dispose();

                stopwatch.Stop();

                // Build summary
                var summary = new FindingSummary
                {
                    Critical = findings.Count(f => f.Severity == "critical"),
                    High     = findings.Count(f => f.Severity == "high"),
                    Medium   = findings.Count(f => f.Severity == "medium"),
                    Low      = findings.Count(f => f.Severity == "low"),
                    Info     = findings.Count(f => f.Severity == "info")
                };

                if (cancellationToken.IsCancellationRequested)
                {
                    Log.Warning("Scan interrupted after {Duration:F2}s", stopwatch.Elapsed.TotalSeconds);
                    Log.Information("Partial results: {Total} findings ({Critical}C/{High}H/{Medium}M/{Low}L/{Info}I)",
                        findings.Count, summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info);
                    
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"\n⚠ Scan interrupted - partial results saved");
                    Console.ResetColor();
                }
                else
                {
                    Log.Information("Scan completed in {Duration:F2}s", stopwatch.Elapsed.TotalSeconds);
                    Log.Information("Total findings: {Total} ({Critical}C/{High}H/{Medium}M/{Low}L/{Info}I)",
                        findings.Count, summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info);
                }

                // Build ScanResult BEFORE generating reports
                result = new ScanResult
                {
                    Success      = !cancellationToken.IsCancellationRequested,
                    ErrorMessage = cancellationToken.IsCancellationRequested
                        ? "Scan cancelled by user"
                        : null,
                    Summary      = summary,
                    Findings     = findings,
                    ScanDuration = stopwatch.Elapsed.TotalSeconds,
                    RequestsSent = requestsSent
                };

                // Generate reports with ScanResult (for proper DB status)
                await GenerateReportsAsync(options, findings, summary, stopwatch.Elapsed, requestsSent, result);

                return result;
            }
            catch (OperationCanceledException)
            {
                stopwatch.Stop();

                var summary = new FindingSummary
                {
                    Critical = findings.Count(f => f.Severity == "critical"),
                    High     = findings.Count(f => f.Severity == "high"),
                    Medium   = findings.Count(f => f.Severity == "medium"),
                    Low      = findings.Count(f => f.Severity == "low"),
                    Info     = findings.Count(f => f.Severity == "info")
                };

                Log.Warning("Scan interrupted after {Duration:F2}s", stopwatch.Elapsed.TotalSeconds);
                Log.Information("Partial results: {Total} findings ({Critical}C/{High}H/{Medium}M/{Low}L/{Info}I)",
                    findings.Count, summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info);

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"\n⚠ Scan interrupted - partial results saved");
                Console.ResetColor();

                result = new ScanResult
                {
                    Success      = false,
                    ErrorMessage = "Scan cancelled by user",
                    Summary      = summary,
                    Findings     = findings,
                    ScanDuration = stopwatch.Elapsed.TotalSeconds,
                    RequestsSent = requestsSent
                };

                // Generate reports with partial results
                try
                {
                    await GenerateReportsAsync(options, findings, summary, stopwatch.Elapsed, requestsSent, result);
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Failed to save cancelled scan report");
                }

                return result;
            }
            catch (InvalidOperationException ex) when (
                ex.Message.Contains("consent") ||
                ex.Message.Contains("Rate limit") ||
                ex.Message.Contains("Aggressive mode") ||
                ex.Message.Contains("No targets"))
            {
                stopwatch.Stop();

                Log.Error("Scan validation failed: {Error}", ex.Message);

                result = new ScanResult
                {
                    Success      = false,
                    ErrorMessage = ex.Message,
                    Summary      = new FindingSummary(),
                    Findings     = new List<Finding>(),
                    ScanDuration = stopwatch.Elapsed.TotalSeconds,
                    RequestsSent = 0
                };

                // DO NOT save validation errors to database - scan never executed
                Log.Debug("Validation error - scan not saved to database");

                return result;
            }
            catch (Exception ex)
            {
                stopwatch.Stop();

                Log.Fatal(ex, "Scan execution failed");

                var summary = new FindingSummary();

                result = new ScanResult
                {
                    Success      = false,
                    ErrorMessage = ex.Message,
                    Summary      = summary,
                    Findings     = findings,
                    ScanDuration = stopwatch.Elapsed.TotalSeconds,
                    RequestsSent = requestsSent
                };

                // Save failed scan to DB (scan started but failed mid-execution)
                try
                {
                    await GenerateReportsAsync(options, findings, summary, stopwatch.Elapsed, requestsSent, result);
                }
                catch (Exception reportEx)
                {
                    Log.Error(reportEx, "Failed to save failed scan report");
                }

                return result;
            }
        }

        /// <summary>
        /// Filter checks based on scan mode and detected remote platform
        /// </summary>
        /// <param name="allChecks">All registered checks</param>
        /// <param name="scanMode">Scan mode (local / remote / remote-ssh-linux / mixed)</param>
        /// <param name="remotePlatform">Detected remote platform (Linux / Unknown / null)</param>
        /// <returns>List of checks that should execute</returns>
        private List<ICheck> FilterChecksForScan(
            List<ICheck> allChecks, 
            string scanMode, 
            string? remotePlatform)
        {
            var filtered = new List<ICheck>();
            int skippedCount = 0;

            foreach (var check in allChecks)
            {
                // ========================================================================
                // CROSS-PLATFORM CHECKS (always execute)
                // ========================================================================
                if (check.Category == CheckCategory.CrossPlatform)
                {
                    filtered.Add(check);
                    continue;
                }

                // ========================================================================
                // LINUX CHECKS (execute if local Linux OR remote SSH Linux)
                // ========================================================================
                if (check.Category == CheckCategory.Linux)
                {
                    // Local scan on Linux OS
                    if (scanMode == "local" && RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    {
                        filtered.Add(check);
                        continue;
                    }

                    // Remote SSH scan with Linux target detected
                    if (scanMode == "remote-ssh-linux")
                    {
                        filtered.Add(check);
                        continue;
                    }

                    // Mixed scan (has local Linux)
                    if (scanMode == "mixed" && RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    {
                        filtered.Add(check);
                        continue;
                    }

                    // Skip in all other cases
                    Log.Debug("Skipping {CheckName}: Linux check, but not in Linux local/SSH mode", 
                        check.Name);
                    skippedCount++;
                    continue;
                }

                // ========================================================================
                // WINDOWS CHECKS (execute ONLY if local Windows)
                // ========================================================================
                if (check.Category == CheckCategory.Windows)
                {
                    // Local scan on Windows OS
                    if (scanMode == "local" && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        filtered.Add(check);
                        continue;
                    }

                    // Mixed scan (has local Windows)
                    if (scanMode == "mixed" && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        filtered.Add(check);
                        continue;
                    }

                    // Future WinRM support for remote Windows auditing, I will implement that here
                    // if (scanMode == "remote-winrm" && remotePlatform == "Windows")
                    // {
                    //     filtered.Add(check);
                    //     continue;
                    // }

                    // Skip in all other cases
                    Log.Debug("Skipping {CheckName}: Windows check requires local Windows execution or WinRM (not implemented)", 
                        check.Name);
                    skippedCount++;
                    continue;
                }

                // Default: add check if no category matched
                filtered.Add(check);
            }

            if (skippedCount > 0)
            {
                Log.Information("Skipped {Count} platform-specific checks (remote scan detected)", skippedCount);
            }

            return filtered;
        }

        /// <summary>
        /// Detect if a target is localhost (running on the same machine as Asterion)
        /// </summary>
        /// <param name="target">Target hostname or IP</param>
        /// <returns>True if target is localhost, false if remote</returns>
        private bool IsLocalTarget(string target)
        {
            if (string.IsNullOrWhiteSpace(target))
                return false;

            target = target.Trim().ToLowerInvariant();

            // Localhost variants
            if (target == "localhost" || 
                target == "127.0.0.1" || 
                target == "::1" || 
                target == "0.0.0.0" ||
                target == "127.0.0.0")
            {
                return true;
            }

            // Current machine name
            try
            {
                var machineName = Environment.MachineName.ToLowerInvariant();
                if (target == machineName || target == $"{machineName}.local")
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Failed to get machine name for local target detection");
            }

            // Local IPs of this system
            try
            {
                var localIPs = Dns.GetHostEntry(Dns.GetHostName())
                    .AddressList
                    .Select(ip => ip.ToString().ToLowerInvariant())
                    .ToList();

                if (localIPs.Contains(target))
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Failed to get local IPs for target detection");
            }

            return false;
        }

        /// <summary>
        /// Parse SSH credentials from string format "user:password"
        /// </summary>
        /// <param name="credentials">Credentials in format "user:password"</param>
        /// <returns>Tuple of (username, password)</returns>
        /// <exception cref="ArgumentException">If format is invalid</exception>
        private (string username, string password) ParseSshCredentials(string credentials)
        {
            var parts = credentials.Split(':', 2);
            if (parts.Length != 2)
            {
                throw new ArgumentException("SSH credentials must be in format: user:password");
            }

            var username = parts[0].Trim();
            var password = parts[1]; // Don't trim password (may have spaces)

            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException("SSH username cannot be empty");
            }

            return (username, password);
        }

        /// <summary>
        /// Detect if a target is likely a Linux system by probing SSH banner and open ports.
        /// Returns true if Linux is detected, false otherwise.
        /// </summary>
        private async Task<bool> DetectLinuxTargetAsync(string target)
        {
            try
            {
                // Method 1: Check if SSH port (22) is open
                var sshOpen = await NetworkUtils.IsPortOpenAsync(target, 22, 3000);
                
                if (!sshOpen)
                    return false;
                
                // Method 2: Try to read SSH banner
                try
                {
                    using var client = new System.Net.Sockets.TcpClient();
                    await client.ConnectAsync(target, 22).WaitAsync(TimeSpan.FromSeconds(3));
                    using var stream = client.GetStream();
                    using var reader = new System.IO.StreamReader(stream);
                    
                    var banner = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(2));
                    
                    if (banner != null)
                    {
                        var bannerLower = banner.ToLowerInvariant();
                        
                        // Check for Windows OpenSSH FIRST
                        if (bannerLower.Contains("openssh_for_windows") ||
                            bannerLower.Contains("openssh for windows") ||
                            bannerLower.Contains("windows"))
                        {
                            Log.Debug("Windows target detected via SSH banner: {Banner}", banner.Trim());
                            return false;  // NOT Linux!
                        }
                        
                        // NOW check for Linux/UNIX SSH banners
                        if (bannerLower.Contains("openssh") ||
                            bannerLower.Contains("ubuntu") ||
                            bannerLower.Contains("debian") ||
                            bannerLower.Contains("centos") ||
                            bannerLower.Contains("red hat") ||
                            bannerLower.Contains("rhel") ||
                            bannerLower.Contains("fedora") ||
                            bannerLower.Contains("suse") ||
                            bannerLower.Contains("arch") ||
                            bannerLower.Contains("kali") ||
                            bannerLower.Contains("freebsd") ||
                            bannerLower.Contains("openbsd") ||
                            bannerLower.Contains("netbsd") ||
                            bannerLower.Contains("linux"))
                        {
                            Log.Debug("Linux/UNIX target detected via SSH banner: {Banner}", banner.Trim());
                            return true;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug(ex, "Could not read SSH banner from {Target}", target);
                }
                
                // Method 3: Check port combinations (heuristic)
                // Linux: SSH open (22), SMB/RPC closed (445/135)
                // Windows: SSH + SMB + RPC typically all open
                var smbOpen = await NetworkUtils.IsPortOpenAsync(target, 445, 2000);
                var rpcOpen = await NetworkUtils.IsPortOpenAsync(target, 135, 2000);
                
                if (sshOpen && !smbOpen && !rpcOpen)
                {
                    Log.Debug("Linux/UNIX target detected: SSH open (22), SMB/RPC closed (445/135)");
                    return true;
                }
                
                // If SSH + SMB + RPC all open → likely Windows
                if (sshOpen && smbOpen && rpcOpen)
                {
                    Log.Debug("Windows target detected: SSH (22), SMB (445), RPC (135) all open");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Error detecting target OS for {Target}", target);
            }
            
            return false;
        }

        /// <summary>
        /// Apply rate limiting using token bucket algorithm.
        /// Allows concurrent execution while respecting rate limits.
        /// </summary>
        private async Task ApplyRateLimit(double requestsPerSecond)
        {
            if (requestsPerSecond <= 0)
                return; // No rate limiting
            
            await _rateLimiter.WaitAsync();
            try
            {
                // Calculate minimum delay between requests
                int delayMs = (int)(1000.0 / requestsPerSecond);
                
                // Calculate time since last request
                var timeSinceLastRequest = DateTime.UtcNow - _lastRequestTime;
                var remainingDelay = delayMs - (int)timeSinceLastRequest.TotalMilliseconds;
                
                // Wait if needed
                if (remainingDelay > 0)
                {
                    await Task.Delay(remainingDelay);
                }
                
                // Update last request time
                _lastRequestTime = DateTime.UtcNow;
            }
            finally
            {
                _rateLimiter.Release();
            }
        }

        /// <summary>
        /// Generate output reports (JSON and/or HTML)
        /// </summary>
        private async Task GenerateReportsAsync(
            ScanOptions options,
            List<Finding> findings,
            FindingSummary summary,
            TimeSpan duration,
            int requestsSent,
            ScanResult result) 
        {
            try
            {
                var reportBuilder = new ReportBuilder(_config);
                
                // Build report
                var report = reportBuilder.BuildReport(
                    tool: "asterion",
                    version: _config.General.Version,
                    target: options.Target,
                    mode: options.Mode,
                    findings: findings,
                    summary: summary,
                    scanDuration: duration.TotalSeconds,
                    requestsSent: requestsSent
                );
                
                // ============================================================================
                // STEP 1: Save JSON WITHOUT AI (for Python to read)
                // ============================================================================
                var jsonPath = await reportBuilder.SaveJsonAsync(report, options.Target);
                
                string? htmlPath = null;
                
                // ============================================================================
                // STEP 2: Generate AI analysis if enabled
                // ============================================================================
                if (options.UseAi)
                {
                    report = await GenerateAiAnalysisAsync(report, jsonPath, options.AiTone);
                    
                    // ============================================================================
                    // STEP 3: UPDATE JSON with AI analysis (overwrite original)
                    // ============================================================================
                    if (report.AiAnalysis != null)
                    {
                        Log.Information("Updating JSON report with AI analysis...");
                        
                        // Overwrite JSON with AI-enhanced version
                        var optionsJson = new JsonSerializerOptions
                        {
                            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                            WriteIndented = true,
                            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
                        };
                        
                        var updatedJson = JsonSerializer.Serialize(report, optionsJson);
                        await File.WriteAllTextAsync(jsonPath, updatedJson);
                        
                        Log.Information("✓ JSON updated with AI analysis");
                    }
                }
                
                // ============================================================================
                // STEP 4: Save HTML (with AI if generated)
                // ============================================================================
                if (_config.Reporting.Format.Html || options.OutputFormat.Contains("html"))
                {
                    htmlPath = await reportBuilder.SaveHtmlAsync(report, options.Target);
                }
                
                var database = new Database(_config);
                await database.InsertScanAsync(report, result, jsonPath, htmlPath);
                Log.Information("Scan results inserted into database");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to generate reports");
            }
        }

        /// <summary>
        /// Generate AI analysis using Python bridge (if enabled)
        /// </summary>
        private async Task<Report> GenerateAiAnalysisAsync(Report report, string jsonPath, string tone)
        {
            try
            {
                Log.Information("Generating AI analysis using Python bridge...");
                
                // Locate Python bridge script
                var scriptPath = FindPythonBridge();
                if (scriptPath == null)
                {
                    Log.Warning("Python bridge script not found, skipping AI analysis");
                    return report;
                }
                
                Log.Debug("Found Python bridge at: {Path}", scriptPath);
                
                var provider = _config.Ai.LangChain.Provider.ToLowerInvariant();
                string? apiKey = null;
                string? apiKeyEnvVar = null;
                
                if (provider == "openai")
                {
                    // All providers use AI_API_KEY for consistency
                    apiKeyEnvVar = "AI_API_KEY";
                    apiKey = Environment.GetEnvironmentVariable(apiKeyEnvVar);

                    if (string.IsNullOrEmpty(apiKey))
                    {
                        Log.Warning(
                            "AI provider 'openai' requires {EnvVar} to be set. Skipping AI analysis.",
                            apiKeyEnvVar
                        );
                        Log.Information("Set the API key: export {EnvVar}='your-key-here'", apiKeyEnvVar);
                        return report;
                    }

                    Log.Debug("API key found for OpenAI");
                }
                else if (provider == "anthropic")
                {
                    apiKeyEnvVar = "AI_API_KEY";
                    apiKey = Environment.GetEnvironmentVariable(apiKeyEnvVar);
                    
                    if (string.IsNullOrEmpty(apiKey))
                    {
                        Log.Warning(
                            "AI provider 'anthropic' requires {EnvVar} to be set. Skipping AI analysis.",
                            apiKeyEnvVar
                        );
                        Log.Information("Set the API key: export {EnvVar}='your-key-here'", apiKeyEnvVar);
                        return report;
                    }
                    
                    Log.Debug("API key found for Anthropic");
                }
                else if (provider == "ollama")
                {
                    // Ollama doesn't need API key, just log and continue
                    Log.Debug("Using Ollama");
                }
                else
                {
                    Log.Warning("Unknown AI provider '{Provider}', skipping AI analysis", provider);
                    return report;
                }
                
                // Prepare arguments
                var tempOutputPath = Path.GetTempFileName();
                var temperatureStr = _config.Ai.LangChain.Temperature.ToString(System.Globalization.CultureInfo.InvariantCulture);
                
                var args = $"\"{scriptPath}\" --input \"{jsonPath}\" --output \"{tempOutputPath}\" " +
                        $"--provider {_config.Ai.LangChain.Provider} " +
                        $"--model {_config.Ai.LangChain.Model} " +
                        $"--temperature {temperatureStr} " +
                        $"--tone {tone}";
                
                // Invoke Python
                // Use 'python' on Windows, 'python3' on Linux/Mac
                var pythonCmd = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "python" : "python3";

                var processInfo = new ProcessStartInfo
                {
                    FileName = pythonCmd,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                if (!string.IsNullOrEmpty(apiKey) && !string.IsNullOrEmpty(apiKeyEnvVar))
                {
                    processInfo.EnvironmentVariables[apiKeyEnvVar] = apiKey;
                    Log.Debug("Passed {EnvVar} to Python subprocess", apiKeyEnvVar);
                }
                
                using var process = Process.Start(processInfo);
                if (process == null)
                {
                    throw new Exception("Failed to start Python process");
                }
                
                // Capture stderr in real-time for progress logging
                var errorOutput = new System.Text.StringBuilder();
                
                process.ErrorDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        errorOutput.AppendLine(e.Data);
                        // Show Python progress in real-time
                        Log.Information("[AI] {Message}", e.Data);
                    }
                };
                
                process.BeginErrorReadLine();
                
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (process.ExitCode != 0)
                {
                    Log.Error("Python bridge failed (exit code {Code})", process.ExitCode);
                    var errorText = errorOutput.ToString().Trim();
                    if (!string.IsNullOrEmpty(errorText))
                    {
                        Log.Error("Error: {Error}", errorText);
                    }
                    return report;
                }
                
                Log.Debug("Python bridge completed successfully");
                
                // Read and parse AI-enhanced JSON
                if (File.Exists(tempOutputPath))
                {
                    var updatedJson = await File.ReadAllTextAsync(tempOutputPath);
                    
                    var options = new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                        PropertyNameCaseInsensitive = true
                    };
                    
                    var updatedReport = JsonSerializer.Deserialize<Report>(updatedJson, options);
                    
                    if (updatedReport?.AiAnalysis != null)
                    {
                        report.AiAnalysis = updatedReport.AiAnalysis;
                        
                        Log.Information("✓ AI analysis generated successfully");
                        Log.Information("  Provider: {Provider}", _config.Ai.LangChain.Provider);
                        Log.Information("  Model: {Model}", report.AiAnalysis.ModelUsed ?? "unknown");
                        Log.Information("  Tone: {Tone}", report.AiAnalysis.Tone ?? tone);
                        
                        // Cleanup temp file
                        try
                        {
                            File.Delete(tempOutputPath);
                        }
                        catch
                        {
                            // Ignore cleanup errors
                        }
                        
                        return report;
                    }
                    else
                    {
                        Log.Warning("AI analysis object not found in Python output");
                        return report;
                    }
                }
                else
                {
                    Log.Warning("Python output file not found: {Path}", tempOutputPath);
                    return report;
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to generate AI analysis");
                return report;
            }
        }

        /// <summary>
        /// Find Python bridge script in expected locations
        /// </summary>
        private string? FindPythonBridge()
        {
            var locations = new[]
            {
                "scripts/ai_analyzer.py",
                "../scripts/ai_analyzer.py",
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "scripts", "ai_analyzer.py"),
                Path.Combine(_config.Paths.ReportDir, "..", "scripts", "ai_analyzer.py")
            };

            foreach (var location in locations)
            {
                if (File.Exists(location))
                {
                    Log.Debug("Found Python bridge at: {Path}", location);
                    return Path.GetFullPath(location);
                }
            }

            return null;
        }

        /// <summary>
        /// Result of a scan execution
        /// </summary>
        public class ScanResult
        {
            public bool Success { get; set; }
            public string? ErrorMessage { get; set; }
            public FindingSummary Summary { get; set; } = new();
            public List<Finding> Findings { get; set; } = new();
            public double ScanDuration { get; set; }
            public int RequestsSent { get; set; }
        }
    }
}