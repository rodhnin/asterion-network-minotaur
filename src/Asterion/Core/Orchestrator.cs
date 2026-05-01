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
            _checks.Add(new Checks.CrossPlatform.SysvolCheck(_config));
            _checks.Add(new Checks.CrossPlatform.TlsScanner(_config));
            _checks.Add(new Checks.CrossPlatform.RdpScanner(_config));
            _checks.Add(new Checks.CrossPlatform.LdapScanner(_config));
            _checks.Add(new Checks.CrossPlatform.AdAggressiveCheck(_config));
            _checks.Add(new Checks.CrossPlatform.KerberosScanner(_config));
            _checks.Add(new Checks.CrossPlatform.SnmpScanner(_config));
            _checks.Add(new Checks.CrossPlatform.DnsScanner(_config));
            _checks.Add(new Checks.CrossPlatform.FtpScanner(_config));
            // WinRM remote checks — always registered; only executes when --winrm is provided
            _checks.Add(new Checks.CrossPlatform.WinRmChecks(_config));

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
            SshConnectionManager? sshManager = null;
            WinRmConnectionManager? winRmManager = null;

            try
            {
                Log.Information("Starting scan execution");
                Log.Information("Target: {Target}, Mode: {Mode}", options.Target, options.Mode);

                // MULTI-CRED: Load credentials from YAML file (if --creds-file was provided)
                if (!string.IsNullOrEmpty(options.CredsFile))
                {
                    ApplyCredentialsFile(options);
                }

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
                // OS DETECTION — per target (AST-FEATURE-003)
                // Runs before check dispatch so we can route correctly without SSH/WinRM.
                // ============================================================================
                var osDetector = new OsDetector(timeoutMs: _config.Scan.Timeout.Connect * 1000);
                var targetOsMap = new System.Collections.Generic.Dictionary<string, OsDetector.TargetOS>();

                if (targets.Count > 0 && !targets.All(IsLocalTarget))
                {
                    Console.WriteLine("\n[Phase 0] OS Detection...");
                    foreach (var t in targets)
                    {
                        if (IsLocalTarget(t))
                        {
                            targetOsMap[t] = OsDetector.TargetOS.Linux; // localhost always local OS
                            continue;
                        }
                        var (detectedOs, reason) = await osDetector.DetectAsync(t);
                        targetOsMap[t] = detectedOs;
                        var osColor = detectedOs switch
                        {
                            OsDetector.TargetOS.Windows => ConsoleColor.Cyan,
                            OsDetector.TargetOS.Linux   => ConsoleColor.Green,
                            OsDetector.TargetOS.Unix    => ConsoleColor.Green,
                            _                           => ConsoleColor.Yellow
                        };
                        Console.ForegroundColor = osColor;
                        Console.Write($"  {t,-20} → {detectedOs,-8}");
                        Console.ResetColor();
                        Console.WriteLine($"  ({reason})");
                    }
                    Console.WriteLine();
                }

                // Store in options so checks can access it
                options.TargetOsMap = targetOsMap;

                // ============================================================================
                // Detect platform and warn about --auth limitations on Linux
                // ============================================================================
                if (!string.IsNullOrEmpty(options.AuthCredentials) && string.IsNullOrEmpty(options.SshCredentials))
                {
                    var firstTarget = targets.FirstOrDefault();
                    if (!string.IsNullOrEmpty(firstTarget) && !IsLocalTarget(firstTarget))
                    {
                        // Use OS detector result if available, else fall back to old method
                        bool isLinux;
                        if (targetOsMap.TryGetValue(firstTarget, out var knownOs))
                            isLinux = knownOs == OsDetector.TargetOS.Linux || knownOs == OsDetector.TargetOS.Unix;
                        else
                            isLinux = await DetectLinuxTargetAsync(firstTarget);
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
                            Console.WriteLine("    • Use --ssh <user:password>          (password auth)");
                            Console.WriteLine($"      ast scan --target {firstTarget} --ssh \"user:password\"");
                            Console.WriteLine("    • Use --ssh-key <user:~/.ssh/id_rsa>  (key-based auth)");
                            Console.WriteLine($"      ast scan --target {firstTarget} --ssh-key \"user:~/.ssh/id_rsa\"");
                            Console.WriteLine("    • Add --sudo-password <pass>           (for privileged file access)");
                            Console.WriteLine("    • Add --bastion <host:user:pass>       (via jump host)");
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
                bool hasSshCredentials = !string.IsNullOrEmpty(options.SshCredentials)
                                      || !string.IsNullOrEmpty(options.SshKeyCredentials)
                                      || !string.IsNullOrEmpty(options.BastionHost);
                bool hasWinRmCredentials = !string.IsNullOrEmpty(options.WinRmCredentials);

                string scanMode;
                string? remotePlatform = null;

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

                    // ── Build SSH manager (bastion > key > password priority) ────
                    if (!string.IsNullOrEmpty(options.BastionHost))
                    {
                        var (bHost, bUser, bPass) = ParseBastionCredentials(options.BastionHost);
                        // Target credentials from --ssh (password) — key auth on target through bastion
                        // is not yet supported; if --ssh-key is provided instead, log a clear warning.
                        string tUser, tPass;
                        if (!string.IsNullOrEmpty(options.SshCredentials))
                        {
                            (tUser, tPass) = ParseSshCredentials(options.SshCredentials);
                        }
                        else if (!string.IsNullOrEmpty(options.SshKeyCredentials))
                        {
                            // Key-auth target via bastion: extract username, cannot use key through tunnel yet.
                            // The connection will fail auth but this at least uses the correct username.
                            var (kUser, _, _) = ParseSshKeyCredentials(options.SshKeyCredentials);
                            tUser = kUser;
                            tPass = "";
                            Log.Warning("[SSH] Bastion + key auth for target is not yet supported — provide --ssh user:pass for the target");
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine("  ⚠ Bastion + --ssh-key: key auth on target through bastion is not supported.");
                            Console.WriteLine("    Use --ssh user:pass to authenticate to the target through the bastion.");
                            Console.ResetColor();
                        }
                        else
                        {
                            // No target credentials at all — will fail auth
                            tUser = "root";
                            tPass = "";
                            Log.Warning("[SSH] Bastion mode set but no target credentials provided (--ssh or --ssh-key)");
                        }
                        sshManager = SshConnectionManager.CreateViaBastion(
                            bHost, bUser, bPass, sshTarget, tUser, tPass,
                            sudoPassword: options.SshSudoPassword);
                        Log.Information("[SSH] Bastion mode: {Bastion} → {Target}", bHost, sshTarget);
                    }
                    else if (!string.IsNullOrEmpty(options.SshKeyCredentials))
                    {
                        var (kUser, kPath, kPass) = ParseSshKeyCredentials(options.SshKeyCredentials);
                        sshManager = SshConnectionManager.CreateWithKeyAuth(
                            sshTarget, kUser, kPath, kPass, options.SshSudoPassword);
                        Log.Information("[SSH] Key auth mode: {User}@{Target} key={Key}", kUser, sshTarget, kPath);
                    }
                    else
                    {
                        var (username, password) = ParseSshCredentials(options.SshCredentials!);
                        sshManager = new SshConnectionManager(sshTarget, username, password, options.SshSudoPassword);
                    }

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
                            var authLabel = !string.IsNullOrEmpty(options.BastionHost) ? "via bastion"
                                          : !string.IsNullOrEmpty(options.SshKeyCredentials) ? "key auth"
                                          : "password auth";
                            Console.WriteLine($"\n✓ SSH connection established to Linux target: {sshTarget} ({authLabel})");
                            if (!string.IsNullOrEmpty(options.SshSudoPassword))
                                Console.WriteLine("  → Sudo elevation: enabled (privileged file access)");
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
                            Console.WriteLine("    • Use --winrm \"DOMAIN\\user:password\" (WinRM remote checks)");
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
                // WINRM SETUP — remote Windows auditing via WS-Man/PowerShell
                // ============================================================================
                if (hasWinRmCredentials)
                {
                    var winRmTarget = hasRemoteTarget
                        ? targets.First(t => !IsLocalTarget(t))
                        : targets.First();

                    // Guard: skip WinRM if OS detection already confirmed this is a Linux/Unix target
                    var detectedOs = targetOsMap.TryGetValue(winRmTarget, out var os) ? os : OsDetector.TargetOS.Unknown;
                    if (detectedOs == OsDetector.TargetOS.Linux || detectedOs == OsDetector.TargetOS.Unix)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"\n⚠ WARNING: --winrm provided but {winRmTarget} was detected as {detectedOs}.");
                        Console.ResetColor();
                        Console.WriteLine("  WinRM is a Windows protocol — skipping Windows remote checks.");
                        Console.WriteLine("  Use --ssh for Linux targets.");
                        Console.WriteLine();
                        Log.Warning("[WinRM] Skipping WinRM for {Target} — OS detection returned {OS}", winRmTarget, detectedOs);
                    }
                    else
                    {
                        var (winRmUser, winRmPass) = ParseWinRmCredentials(options.WinRmCredentials!);
                        winRmManager = new WinRmConnectionManager(winRmTarget, winRmUser, winRmPass);

                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine($"\n[WinRM] Connecting to {winRmTarget}:5985 as {winRmUser}...");
                        Console.ResetColor();

                        bool winRmConnected = await winRmManager.ConnectAsync();
                        if (winRmConnected)
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"✓ WinRM connected to {winRmTarget}");
                            Console.ResetColor();
                            Console.WriteLine("  → Windows checks: Firewall, Registry, Services, Privilege Escalation");
                            Console.WriteLine();
                            Log.Information("[WinRM] Connection established to {Target}", winRmTarget);
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine($"\n⚠ WARNING: WinRM connection failed to {winRmTarget}");
                            Console.ResetColor();
                            Console.WriteLine("  Windows remote checks will be skipped.");
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine("  ℹ Ensure WinRM is enabled on the target:");
                            Console.WriteLine("    • Enable-PSRemoting -Force");
                            Console.WriteLine("    • Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value \"*\"");
                            Console.WriteLine("    • winrm quickconfig");
                            Console.ResetColor();
                            Console.WriteLine();
                            winRmManager.Dispose();
                            winRmManager = null;
                        }
                    }
                }

                // ── Suggest --winrm if Windows target detected but no WinRM credentials provided ──
                if (!hasWinRmCredentials && !hasSshCredentials)
                {
                    foreach (var t in targets)
                    {
                        if (targetOsMap.TryGetValue(t, out var tOs) && tOs == OsDetector.TargetOS.Windows)
                        {
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine($"  ℹ {t} detected as Windows — add --winrm \"DOMAIN\\user:pass\" to enable remote system checks");
                            Console.ResetColor();
                            break;  // only show once
                        }
                    }
                }

                // ============================================================================
                // FILTER CHECKS & EXECUTE WITH CANCELLATION SUPPORT
                // ============================================================================
                var checksToRun = FilterChecksForScan(_checks, scanMode, remotePlatform, winRmManager != null);
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

                            // Set WinRM manager for Windows checks — but NOT for local Windows scans
                            // (local checks use native Registry/PS paths; WinRM is only for remote targets)
                            if (winRmManager != null && check is BaseCheck winRmBaseCheck)
                            {
                                bool isLocalWindows = scanMode == "local" &&
                                    RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

                                if (!isLocalWindows &&
                                    (check.Category == CheckCategory.Windows ||
                                     check is Checks.CrossPlatform.WinRmChecks))
                                {
                                    winRmBaseCheck.SetWinRmManager(winRmManager);
                                    Log.Debug("[{CheckName}] WinRM manager assigned for remote execution", check.Name);
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

                // Clean up SSH and WinRM connections
                sshManager?.Dispose();
                winRmManager?.Dispose();

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

                // Print risk score to console after reports are saved
                double rawScore = summary.Critical * 3.5 + summary.High * 1.5 + summary.Medium * 0.3 + summary.Low * 0.05;
                double riskScore = Math.Round(Math.Min(10.0, rawScore), 1);
                string riskLabel = riskScore switch
                {
                    >= 8.0 => "Critical Risk",
                    >= 6.0 => "High Risk",
                    >= 4.0 => "Medium Risk",
                    >= 2.0 => "Low Risk",
                    >  0.0 => "Minimal Risk",
                    _      => "Secure"
                };
                Console.ForegroundColor = riskScore >= 8.0 ? ConsoleColor.Red
                                        : riskScore >= 6.0 ? ConsoleColor.DarkRed
                                        : riskScore >= 4.0 ? ConsoleColor.DarkYellow
                                        : riskScore >= 2.0 ? ConsoleColor.Yellow
                                        : ConsoleColor.Green;
                Console.WriteLine($"\n  Risk Score: {riskScore:F1}/10 — {riskLabel}");
                Console.ResetColor();

                return result;
            }
            catch (OperationCanceledException)
            {
                stopwatch.Stop();
                sshManager?.Dispose();
                winRmManager?.Dispose();

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
                sshManager?.Dispose();
                winRmManager?.Dispose();

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
            string? remotePlatform,
            bool winRmActive = false)
        {
            var filtered = new List<ICheck>();
            int skippedCount = 0;

            foreach (var check in allChecks)
            {
                // ========================================================================
                // CROSS-PLATFORM CHECKS (always execute, except WinRmChecks on local Windows)
                // ========================================================================
                if (check.Category == CheckCategory.CrossPlatform)
                {
                    // Skip WinRmChecks dispatcher when scanning localhost on Windows —
                    // the native Windows checks (Category.Windows) already cover everything locally.
                    if (check is Checks.CrossPlatform.WinRmChecks &&
                        scanMode == "local" &&
                        RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        Log.Debug("Skipping WinRmChecks: local Windows scan uses native checks directly");
                        skippedCount++;
                        continue;
                    }

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
                // WINDOWS CHECKS (local Windows OR remote via WinRM)
                // ========================================================================
                if (check.Category == CheckCategory.Windows)
                {
                    // Local scan on Windows OS — native checks run directly, no WinRM needed
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

                    // Remote Windows auditing via WinRM — only for remote targets
                    if (winRmActive && !(scanMode == "local" && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)))
                    {
                        filtered.Add(check);
                        continue;
                    }

                    // Skip in all other cases
                    Log.Debug("Skipping {CheckName}: Windows check requires local Windows or --winrm", check.Name);
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
        /// Parse SSH key credentials from "user:keypath" or "user:keypath:passphrase".
        /// Expands ~ to home directory.
        /// </summary>
        private (string username, string keyPath, string? passphrase) ParseSshKeyCredentials(string credentials)
        {
            // Format: user:~/.ssh/id_rsa  or  user:~/.ssh/id_rsa:passphrase
            // Split on ':' but path may contain ':' on Windows — limit to 3 parts
            var parts = credentials.Split(':', 3);
            if (parts.Length < 2)
                throw new ArgumentException("--ssh-key must be in format: user:keypath or user:keypath:passphrase");

            var username = parts[0].Trim();
            var rawPath  = parts[1].Trim();
            var passphrase = parts.Length == 3 ? parts[2] : null;

            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("SSH key username cannot be empty");
            if (string.IsNullOrEmpty(rawPath))
                throw new ArgumentException("SSH key path cannot be empty");

            var keyPath = rawPath.Replace("~",
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));

            return (username, keyPath, passphrase);
        }

        /// <summary>
        /// Parse bastion host credentials from "bastionhost:user:password".
        /// </summary>
        private (string host, string username, string password) ParseBastionCredentials(string credentials)
        {
            // Format: host:user:password
            var parts = credentials.Split(':', 3);
            if (parts.Length != 3)
                throw new ArgumentException("--bastion must be in format: bastionhost:user:password");

            var host     = parts[0].Trim();
            var username = parts[1].Trim();
            var password = parts[2]; // Don't trim

            if (string.IsNullOrEmpty(host))
                throw new ArgumentException("Bastion host cannot be empty");
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Bastion username cannot be empty");

            return (host, username, password);
        }

        /// <summary>
        /// Parse WinRM credentials from "DOMAIN\user:password" or "user:password".
        /// Returns (username, password). Domain is preserved in username if present.
        /// </summary>
        private (string username, string password) ParseWinRmCredentials(string credentials)
        {
            // Split on the LAST colon to handle "DOMAIN\user:password" correctly
            int lastColon = credentials.LastIndexOf(':');
            if (lastColon < 0)
                throw new ArgumentException("--winrm must be in format: user:password or DOMAIN\\user:password");

            var username = credentials[..lastColon].Trim();
            var password = credentials[(lastColon + 1)..]; // Don't trim password

            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("WinRM username cannot be empty");

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
                // ATTACK CHAIN ANALYSIS — correlate co-existing findings into chained vectors
                // ============================================================================
                var attackChains = AttackChainAnalyzer.Analyze(findings);
                if (attackChains.Count > 0)
                {
                    report.AttackChains = attackChains;
                    Log.Warning("[AttackChain] {Count} attack chain(s) identified — review required", attackChains.Count);
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"\n  ⚠  Attack Chains: {attackChains.Count} multi-step vector(s) detected");
                    foreach (var chain in attackChains)
                        Console.WriteLine($"     • [{chain.Severity.ToUpper()}] {chain.Id}: {chain.Title}");
                    Console.ResetColor();
                }

                // ============================================================================
                // STEP 1: Save JSON WITHOUT AI (for Python to read)
                // ============================================================================
                var jsonPath = await reportBuilder.SaveJsonAsync(report, options.Target);

                // ============================================================================
                // STEP 2: Insert scan into DB early (htmlPath=null) to obtain scan_id,
                // which is forwarded to the AI bridge for cost tracking linkage.
                // html_path is updated after HTML generation (STEP 5).
                // ============================================================================
                var database = new Database(_config);
                var scanId = await database.InsertScanAsync(report, result, jsonPath, htmlPath: null);
                Log.Information("Scan results inserted into database (scan_id={ScanId})", scanId);

                string? htmlPath = null;

                // ============================================================================
                // STEP 3: Generate AI analysis if enabled (scan_id now available)
                // ============================================================================
                if (options.UseAi)
                {
                    report = await GenerateAiAnalysisAsync(report, jsonPath, options.AiTone, options, scanId);

                    // ============================================================================
                    // STEP 4: UPDATE JSON with AI analysis (overwrite original)
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
                // STEP 5: Save HTML (with AI if generated) + update DB html_path
                // ============================================================================
                if (_config.Reporting.Format.Html || options.OutputFormat == "html" || options.OutputFormat == "both")
                {
                    htmlPath = await reportBuilder.SaveHtmlAsync(report, options.Target);
                    await database.UpdateScanHtmlPathAsync(scanId, htmlPath);
                }

                // ============================================================================
                // STEP 6: Compute diff if --diff was requested
                // ============================================================================
                if (!string.IsNullOrEmpty(options.DiffRef))
                {
                    report.Diff = await ComputeDiffAsync(database, scanId, options.DiffRef, options.Target, options.Mode);

                    if (report.Diff != null)
                    {
                        Log.Information(
                            "Diff computed: {New} new, {Fixed} fixed, {Persisting} persisting",
                            report.Diff.New.Count, report.Diff.Fixed.Count, report.Diff.Persisting.Count);

                        // Rewrite JSON with diff included
                        var jsonOptions = new JsonSerializerOptions
                        {
                            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                            WriteIndented = true,
                            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
                        };
                        await File.WriteAllTextAsync(jsonPath, JsonSerializer.Serialize(report, jsonOptions));
                        Log.Information("✓ JSON updated with diff section");

                        // Regenerate HTML if needed
                        if (htmlPath != null)
                        {
                            var rb2 = new ReportBuilder(_config);
                            htmlPath = await rb2.SaveHtmlAsync(report, options.Target);
                            Log.Information("✓ HTML updated with diff section");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to generate reports");
            }
        }

        /// <summary>
        /// Generate AI analysis using Python bridge (if enabled)
        /// </summary>
        private async Task<Report> GenerateAiAnalysisAsync(Report report, string jsonPath, string tone, ScanOptions options, int scanId = 0)
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
                
                // CLI flags override config defaults
                var provider = (!string.IsNullOrEmpty(options.AiProvider)
                    ? options.AiProvider
                    : _config.Ai.LangChain.Provider).ToLowerInvariant();

                var model = !string.IsNullOrEmpty(options.AiModel)
                    ? options.AiModel
                    : _config.Ai.LangChain.Model;

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

                var argsBuilder = new System.Text.StringBuilder();
                argsBuilder.Append($"\"{scriptPath}\" --input \"{jsonPath}\" --output \"{tempOutputPath}\"");
                argsBuilder.Append($" --provider {provider}");
                argsBuilder.Append($" --model {model}");
                argsBuilder.Append($" --temperature {temperatureStr}");
                argsBuilder.Append($" --tone {tone}");

                if (options.AiBudget > 0)
                    argsBuilder.Append($" --budget {options.AiBudget.ToString(System.Globalization.CultureInfo.InvariantCulture)}");

                if (options.AiStream)
                    argsBuilder.Append(" --stream");

                if (options.AiAgent)
                    argsBuilder.Append(" --agent");

                if (!string.IsNullOrEmpty(options.AiCompare))
                    argsBuilder.Append($" --compare \"{options.AiCompare}\"");

                if (scanId > 0)
                    argsBuilder.Append($" --scan-id {scanId}");

                var args = argsBuilder.ToString();

                // Invoke Python
                // Use 'python' on Windows, 'python3' on Linux/Mac
                var pythonCmd = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "python" : "python3";

                var processInfo = new ProcessStartInfo
                {
                    FileName = pythonCmd,
                    Arguments = args,
                    WorkingDirectory = Path.GetDirectoryName(scriptPath) ?? AppDomain.CurrentDomain.BaseDirectory,
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
                        Log.Information("[AI] {Message}", e.Data);
                    }
                };

                process.BeginErrorReadLine();

                // IMPROV-006: When streaming, print stdout tokens to console in real-time.
                // In non-streaming mode, stdout is empty (result goes to temp file via --output).
                if (options.AiStream)
                {
                    // Print each character as it arrives so the user sees live output
                    Console.Write("[AI STREAM] ");
                    var buf = new char[1];
                    while (!process.StandardOutput.EndOfStream)
                    {
                        var read = await process.StandardOutput.ReadAsync(buf, 0, 1);
                        if (read > 0)
                            Console.Write(buf[0]);
                    }
                    Console.WriteLine();
                }
                else
                {
                    // Drain stdout (normally empty in non-stream mode)
                    await process.StandardOutput.ReadToEndAsync();
                }

                await process.WaitForExitAsync();

                if (process.ExitCode != 0)
                {
                    var errorText = errorOutput.ToString().Trim();
                    if (process.ExitCode == 2)
                    {
                        // Exit code 2 = AI authentication error (invalid API key)
                        Log.Error("AI authentication failed — invalid API key for provider '{Provider}'", provider);
                        Log.Error("Fix: export AI_API_KEY='<your-correct-key>'");
                        if (provider.Equals("openai", StringComparison.OrdinalIgnoreCase))
                            Log.Information("Get your key: https://platform.openai.com/account/api-keys");
                        else if (provider.Equals("anthropic", StringComparison.OrdinalIgnoreCase))
                            Log.Information("Get your key: https://console.anthropic.com/settings/keys");
                        Log.Warning("Skipping AI analysis — report will be generated without AI content");
                    }
                    else
                    {
                        Log.Error("Python bridge failed (exit code {Code})", process.ExitCode);
                        if (!string.IsNullOrEmpty(errorText))
                            Log.Error("Error: {Error}", errorText);
                    }
                    return report;
                }

                Log.Debug("Python bridge completed successfully");

                // Read and parse AI-enhanced JSON from temp output file
                if (File.Exists(tempOutputPath))
                {
                    var updatedJson = await File.ReadAllTextAsync(tempOutputPath);

                    var jsonOptions = new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                        PropertyNameCaseInsensitive = true
                    };

                    var updatedReport = JsonSerializer.Deserialize<Report>(updatedJson, jsonOptions);

                    if (updatedReport?.AiAnalysis != null)
                    {
                        report.AiAnalysis = updatedReport.AiAnalysis;

                        // Propagate OWASP/CVE/compliance enrichment from Python bridge back to findings
                        if (updatedReport.Findings?.Count == report.Findings?.Count && updatedReport.Findings != null)
                            report.Findings = updatedReport.Findings;

                        Log.Information("✓ AI analysis generated successfully");
                        Log.Information("  Provider: {Provider}", provider);
                        Log.Information("  Model: {Model}", report.AiAnalysis.ModelUsed ?? "unknown");
                        Log.Information("  Tone: {Tone}", report.AiAnalysis.Tone ?? tone);

                        // IMPROV-005: Show cost if available
                        if (report.AiAnalysis.Cost != null)
                        {
                            var cost = report.AiAnalysis.Cost;
                            Log.Information("  AI Cost: ${Cost:F4} USD", cost.TotalUsd);
                            if (options.AiBudget > 0)
                                Log.Information("  Budget used: {Pct:F1}% of ${Budget:F2}",
                                    (cost.TotalUsd / options.AiBudget) * 100, options.AiBudget);
                        }

                        // Cleanup temp file
                        try { File.Delete(tempOutputPath); } catch { /* ignore */ }

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
        /// Compute diff between current scan and a reference scan.
        /// diffRef can be "last" or a numeric scan_id string.
        /// </summary>
        private async Task<Models.ScanDiff?> ComputeDiffAsync(
            Database database, int currentScanId, string diffRef, string target, string currentMode)
        {
            try
            {
                // Resolve reference scan
                (int ScanId, string Date, string Target, string Mode)? refScan = null;

                if (diffRef.Trim().ToLowerInvariant() == "last")
                {
                    refScan = await database.GetPreviousScanAsync(target, currentScanId);
                    if (refScan == null)
                    {
                        Log.Warning("--diff last: no previous completed scan found for target '{Target}'", target);
                        return null;
                    }
                }
                else if (int.TryParse(diffRef.Trim(), out int refId))
                {
                    refScan = await database.GetScanMetaAsync(refId);
                    if (refScan == null)
                    {
                        Log.Warning("--diff {RefId}: scan not found in database", refId);
                        return null;
                    }
                }
                else
                {
                    Log.Warning("--diff: invalid value '{DiffRef}'. Use 'last' or a numeric scan_id.", diffRef);
                    return null;
                }

                if (refScan.Value.ScanId == currentScanId)
                {
                    Log.Warning("--diff: reference scan is the same as current scan — skipped");
                    return null;
                }

                Log.Information("Computing diff: scan #{Current} vs scan #{Ref}", currentScanId, refScan.Value.ScanId);

                // Fetch findings for both scans
                var currentFindings = await database.GetScanFindingsForDiffAsync(currentScanId);
                var refFindings     = await database.GetScanFindingsForDiffAsync(refScan.Value.ScanId);

                // GroupBy handles duplicate codes (e.g. same check on multiple ports/targets)
                var currentCodes = currentFindings
                    .GroupBy(f => f.Code)
                    .ToDictionary(g => g.Key, g => g.First());
                var refCodes = refFindings
                    .GroupBy(f => f.Code)
                    .ToDictionary(g => g.Key, g => g.First());

                var newCodes        = currentCodes.Keys.Except(refCodes.Keys).ToHashSet();
                var fixedCodes      = refCodes.Keys.Except(currentCodes.Keys).ToHashSet();
                var persistingCodes = currentCodes.Keys.Intersect(refCodes.Keys).ToHashSet();

                bool modeMismatch = !string.IsNullOrEmpty(refScan.Value.Mode)
                    && !string.IsNullOrEmpty(currentMode)
                    && !refScan.Value.Mode.Equals(currentMode, StringComparison.OrdinalIgnoreCase);

                if (modeMismatch)
                {
                    Log.Warning(
                        "Diff mode mismatch: current='{Current}' vs ref='{Ref}' — " +
                        "'Fixed' findings may include checks not run in {Current} mode",
                        currentMode, refScan.Value.Mode);
                }

                return new Models.ScanDiff
                {
                    RefScanId    = refScan.Value.ScanId,
                    RefDate      = refScan.Value.Date,
                    RefTarget    = refScan.Value.Target,
                    RefMode      = refScan.Value.Mode,
                    CurrentMode  = currentMode,
                    ModeMismatch = modeMismatch,
                    New = currentFindings
                        .Where(f => newCodes.Contains(f.Code))
                        .OrderBy(f => f.Code)
                        .Select(f => new Models.DiffFinding { Id = f.Code, Title = f.Title, Severity = f.Severity })
                        .ToList(),
                    Fixed = refFindings
                        .Where(f => fixedCodes.Contains(f.Code))
                        .OrderBy(f => f.Code)
                        .Select(f => new Models.DiffFinding { Id = f.Code, Title = f.Title, Severity = f.Severity })
                        .ToList(),
                    Persisting = currentFindings
                        .Where(f => persistingCodes.Contains(f.Code))
                        .OrderBy(f => f.Code)
                        .Select(f => new Models.DiffFinding { Id = f.Code, Title = f.Title, Severity = f.Severity })
                        .ToList(),
                };
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to compute diff");
                return null;
            }
        }

        /// <summary>
        /// Load credentials from a YAML file and apply them to scan options.
        /// Fields already set via CLI flags are not overridden (CLI takes precedence).
        /// Supports multi-cred YAML format: auth, auth_ntlm, kerberos, ssh at top level
        /// or as a list under a 'credentials' key (first entry of each type is used).
        /// </summary>
        private void ApplyCredentialsFile(ScanOptions options)
        {
            try
            {
                if (!File.Exists(options.CredsFile))
                {
                    Log.Warning("Credentials file not found: {Path}", options.CredsFile);
                    return;
                }

                var yaml = File.ReadAllText(options.CredsFile!);
                var deserializer = new YamlDotNet.Serialization.DeserializerBuilder()
                    .WithNamingConvention(YamlDotNet.Serialization.NamingConventions.UnderscoredNamingConvention.Instance)
                    .IgnoreUnmatchedProperties()
                    .Build();

                // Try flat format first: top-level auth/auth_ntlm/kerberos/ssh keys
                var flat = deserializer.Deserialize<Dictionary<string, object?>>(yaml);
                if (flat == null) return;

                int applied = 0;

                // Helper to safely get string value
                string? GetStr(string key) =>
                    flat.TryGetValue(key, out var v) && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

                // Apply credentials only if not already set by CLI flags
                if (string.IsNullOrEmpty(options.AuthCredentials))
                {
                    var v = GetStr("auth");
                    if (v != null) { options.AuthCredentials = v; applied++; Log.Information("MULTI-CRED: Loaded auth credentials from file"); }
                }
                if (string.IsNullOrEmpty(options.AuthNtlm))
                {
                    var v = GetStr("auth_ntlm");
                    if (v != null) { options.AuthNtlm = v; applied++; Log.Information("MULTI-CRED: Loaded NTLM credentials from file"); }
                }
                if (string.IsNullOrEmpty(options.KerberosCredentials))
                {
                    var v = GetStr("kerberos");
                    if (v != null) { options.KerberosCredentials = v; applied++; Log.Information("MULTI-CRED: Loaded Kerberos credentials from file"); }
                }
                if (string.IsNullOrEmpty(options.SshCredentials))
                {
                    var v = GetStr("ssh");
                    if (v != null) { options.SshCredentials = v; applied++; Log.Information("MULTI-CRED: Loaded SSH credentials from file"); }
                }
                if (string.IsNullOrEmpty(options.SshKeyCredentials))
                {
                    var v = GetStr("ssh_key");
                    if (v != null) { options.SshKeyCredentials = v; applied++; Log.Information("MULTI-CRED: Loaded SSH key credentials from file"); }
                }
                if (string.IsNullOrEmpty(options.SshSudoPassword))
                {
                    var v = GetStr("sudo_password");
                    if (v != null) { options.SshSudoPassword = v; applied++; Log.Information("MULTI-CRED: Loaded sudo password from file"); }
                }
                if (string.IsNullOrEmpty(options.BastionHost))
                {
                    var v = GetStr("bastion");
                    if (v != null) { options.BastionHost = v; applied++; Log.Information("MULTI-CRED: Loaded bastion host from file"); }
                }
                if (string.IsNullOrEmpty(options.WinRmCredentials))
                {
                    var v = GetStr("winrm");
                    if (v != null) { options.WinRmCredentials = v; applied++; Log.Information("MULTI-CRED: Loaded WinRM credentials from file"); }
                }

                // Support credentials[] list format — use first entry of each type
                if (flat.TryGetValue("credentials", out var credsList) && credsList is List<object> list)
                {
                    foreach (var item in list)
                    {
                        if (item is not Dictionary<object, object> entry) continue;
                        string? Get(string k) =>
                            entry.TryGetValue(k, out var ev) && ev is string es && !string.IsNullOrWhiteSpace(es) ? es : null;

                        if (string.IsNullOrEmpty(options.AuthCredentials))     { var v = Get("auth");          if (v != null) { options.AuthCredentials    = v; applied++; } }
                        if (string.IsNullOrEmpty(options.AuthNtlm))            { var v = Get("auth_ntlm");     if (v != null) { options.AuthNtlm            = v; applied++; } }
                        if (string.IsNullOrEmpty(options.KerberosCredentials)) { var v = Get("kerberos");      if (v != null) { options.KerberosCredentials = v; applied++; } }
                        if (string.IsNullOrEmpty(options.SshCredentials))      { var v = Get("ssh");           if (v != null) { options.SshCredentials      = v; applied++; } }
                        if (string.IsNullOrEmpty(options.SshKeyCredentials))   { var v = Get("ssh_key");       if (v != null) { options.SshKeyCredentials   = v; applied++; } }
                        if (string.IsNullOrEmpty(options.SshSudoPassword))     { var v = Get("sudo_password"); if (v != null) { options.SshSudoPassword     = v; applied++; } }
                        if (string.IsNullOrEmpty(options.BastionHost))         { var v = Get("bastion");       if (v != null) { options.BastionHost         = v; applied++; } }
                        if (string.IsNullOrEmpty(options.WinRmCredentials))    { var v = Get("winrm");         if (v != null) { options.WinRmCredentials    = v; applied++; } }
                    }
                }

                if (applied > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"  [MULTI-CRED] Loaded {applied} credential set(s) from: {options.CredsFile}");
                    Console.ResetColor();
                }
                else
                {
                    Log.Warning("MULTI-CRED: No credentials found in file or all overridden by CLI flags: {Path}", options.CredsFile);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "MULTI-CRED: Failed to load credentials file: {Path}", options.CredsFile);
            }
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