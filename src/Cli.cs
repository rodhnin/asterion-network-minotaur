using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;

namespace Asterion
{
    /// <summary>
    /// Command-Line Interface for Asterion
    /// Handles argument parsing and command routing
    /// </summary>
    public class Cli
    {
        private readonly RootCommand _rootCommand;

        public Cli()
        {
            _rootCommand = BuildRootCommand();
        }

        public async Task<int> InvokeAsync(string[] args)
        {
            return await _rootCommand.InvokeAsync(args);
        }

        private RootCommand BuildRootCommand()
        {
            var rootCommand = new RootCommand("Asterion Network Security Auditor - The Minotaur of the Argos Suite");
            
            // Create options ONCE and store them
            var targetOption = CreateTargetOption();
            var modeOption = CreateModeOption();
            var outputOption = CreateOutputOption();
            var portsOption = CreatePortsOption();
            var authOption = CreateAuthOption();
            var authNtlmOption = CreateAuthNtlmOption();
            var kerberosOption = CreateKerberosOption();
            var sshOption = CreateSshOption();
            var threadsOption = CreateThreadsOption();
            var rateOption = CreateRateOption();
            var timeoutOption = CreateTimeoutOption();
            var verifySslOption = CreateVerifySslOption();
            var useAiOption = CreateUseAiOption();
            var aiToneOption = CreateAiToneOption();
            var aiProviderOption = CreateAiProviderOption();
            var aiModelOption = CreateAiModelOption();
            var aiBudgetOption = CreateAiBudgetOption();
            var aiStreamOption = CreateAiStreamOption();
            var aiAgentOption = CreateAiAgentOption();
            var aiCompareOption = CreateAiCompareOption();
            var diffOption = CreateDiffOption();
            var verboseOption = CreateVerboseOption();
            var credsFileOption = CreateCredsFileOption();
            var sshKeyOption = CreateSshKeyOption();
            var sudoPasswordOption = CreateSudoPasswordOption();
            var bastionOption = CreateBastionOption();
            var winRmOption = CreateWinRmOption();

            var scanCommand = new Command("scan", "Perform a security scan of network infrastructure")
            {
                targetOption,
                modeOption,
                outputOption,
                portsOption,
                authOption,
                authNtlmOption,
                kerberosOption,
                sshOption,
                threadsOption,
                rateOption,
                timeoutOption,
                verifySslOption,
                useAiOption,
                aiToneOption,
                aiProviderOption,
                aiModelOption,
                aiBudgetOption,
                aiStreamOption,
                aiAgentOption,
                aiCompareOption,
                diffOption,
                verboseOption,
                credsFileOption,
                sshKeyOption,
                sudoPasswordOption,
                bastionOption,
                winRmOption
            };

            scanCommand.SetHandler(async (InvocationContext context) =>
            {
                await HandleScanCommand(
                    context,
                    targetOption,
                    modeOption,
                    outputOption,
                    portsOption,
                    authOption,
                    authNtlmOption,
                    kerberosOption,
                    sshOption,
                    threadsOption,
                    rateOption,
                    timeoutOption,
                    verifySslOption,
                    useAiOption,
                    aiToneOption,
                    aiProviderOption,
                    aiModelOption,
                    aiBudgetOption,
                    aiStreamOption,
                    aiAgentOption,
                    aiCompareOption,
                    diffOption,
                    verboseOption,
                    credsFileOption,
                    sshKeyOption,
                    sudoPasswordOption,
                    bastionOption,
                    winRmOption
                );
            });

            // ============================================================================
            // CONSENT COMMANDS
            // ============================================================================
            var consentCommand = new Command("consent", "Manage consent tokens for aggressive scanning");

            // Generate consent token
            var genConsentCommand = new Command("generate", "Generate a consent token for a domain");
            var genDomainOption = new Option<string>("--domain", "Target domain") { IsRequired = true };
            genConsentCommand.AddOption(genDomainOption);
            genConsentCommand.SetHandler(async (string domain) =>
            {
                await HandleGenerateConsent(domain);
            }, genDomainOption);

            // Verify consent token
            var verifyConsentCommand = new Command("verify", "Verify a consent token");
            var verifyMethodOption = new Option<string>("--method", () => "http", "Verification method (http, dns, or ssh)");
            var verifyDomainOption = new Option<string>("--domain", "Target domain") { IsRequired = true };
            var verifyTokenOption = new Option<string>("--token", "Consent token to verify") { IsRequired = true };
            var verifySshOption = new Option<string?>("--ssh", "SSH credentials (user:pass) - only for method=ssh");

            verifyConsentCommand.AddOption(verifyMethodOption);
            verifyConsentCommand.AddOption(verifyDomainOption);
            verifyConsentCommand.AddOption(verifyTokenOption);
            verifyConsentCommand.AddOption(verifySshOption);

            verifyConsentCommand.SetHandler(async (string method, string domain, string token, string? ssh) =>
            {
                await HandleVerifyConsent(method, domain, token, ssh);
            }, verifyMethodOption, verifyDomainOption, verifyTokenOption, verifySshOption);

            consentCommand.AddCommand(genConsentCommand);
            consentCommand.AddCommand(verifyConsentCommand);

            // ============================================================================
            // VERSION COMMAND
            // ============================================================================
            var versionCommand = new Command("version", "Display version information");
            versionCommand.SetHandler(() =>
            {
                Console.WriteLine("Asterion Network Security Auditor");
                Console.WriteLine("Version: 0.2.0");
                Console.WriteLine("Author: Rodney Dhavid Jimenez Chacin (rodhnin)");
                Console.WriteLine("Part of the Argos Security Suite");
            });

            // Add commands to root
            rootCommand.AddCommand(scanCommand);
            rootCommand.AddCommand(consentCommand);
            rootCommand.AddCommand(versionCommand);

            return rootCommand;
        }

        // ============================================================================
        // OPTION DEFINITIONS
        // ============================================================================

        private Option<string> CreateTargetOption()
        {
            return new Option<string>(
                aliases: new[] { "--target", "-t" },
                description: "Target to scan (IP, CIDR range, or domain)"
            ) { IsRequired = true };
        }

        private Option<string> CreateModeOption()
        {
            return new Option<string>(
                aliases: new[] { "--mode", "-m" },
                getDefaultValue: () => "safe",
                description: "Scan mode: safe (non-intrusive) or aggressive (requires consent)"
            );
        }

        private Option<string> CreateOutputOption()
        {
            return new Option<string>(
                aliases: new[] { "--output", "-o" },
                getDefaultValue: () => "json",
                description: "Output format: json, html, or both"
            );
        }

        private Option<string?> CreatePortsOption()
        {
            return new Option<string?>(
                aliases: new[] { "--ports", "-p" },
                description: "Comma-separated list of ports or ranges (e.g., 80,443,8000-9000)"
            );
        }

        private Option<string?> CreateAuthOption()
        {
            return new Option<string?>(
                "--auth",
                description: "Authentication credentials (format: user:pass or DOMAIN\\user:pass). " +
                            "Optimized for Windows targets (SMB/RPC/WMI). "
            );
        }

        private Option<string?> CreateAuthNtlmOption()
        {
            return new Option<string?>(
                "--auth-ntlm",
                description: "NTLM hash for authentication (format: user:ntlmhash). "+
                            "Optimized for Windows targets (SMB/RPC/WMI). "
            );
        }

        private Option<string?> CreateKerberosOption()
        {
            return new Option<string?>(
                "--kerberos",
                description: "Kerberos credentials (format: user:pass@REALM). "+
                            "Optimized for Windows targets (SMB/RPC/WMI). "
            );
        }

        private Option<string?> CreateSshOption()
        {
            return new Option<string?>(
                "--ssh",
                description: "SSH credentials for remote Linux/UNIX auditing (format: user:pass). " +
                            "Provides comprehensive Linux system analysis."
            );
        }

        private Option<int> CreateThreadsOption()
        {
            return new Option<int>(
                "--threads",
                getDefaultValue: () => 5,
                description: "Number of concurrent threads (1-20)"
            );
        }

        private Option<double> CreateRateOption()
        {
            return new Option<double>(
                "--rate",
                getDefaultValue: () => 5.0,
                description: "Request rate limit (requests per second)"
            );
        }

        private Option<int> CreateTimeoutOption()
        {
            return new Option<int>(
                "--timeout",
                getDefaultValue: () => 10,
                description: "Connection timeout in seconds"
            );
        }

        private Option<bool> CreateVerifySslOption()
        {
            return new Option<bool>(
                "--verify-ssl",
                getDefaultValue: () => true,
                description: "Verify SSL certificates"
            );
        }

        private Option<bool> CreateUseAiOption()
        {
            return new Option<bool>(
                "--use-ai",
                getDefaultValue: () => false,
                description: "Enable AI-powered analysis (requires key or Ollama)"
            );
        }

        private Option<string> CreateAiToneOption()
        {
            return new Option<string>(
                "--ai-tone",
                getDefaultValue: () => "technical",
                description: "AI analysis tone: technical, non_technical, or both"
            ).FromAmong("technical", "non_technical", "both");
        }

        private Option<string?> CreateAiProviderOption()
        {
            return new Option<string?>(
                "--ai-provider",
                description: "AI provider override: openai, anthropic, or ollama (default: from config)"
            );
        }

        private Option<string?> CreateAiModelOption()
        {
            return new Option<string?>(
                "--ai-model",
                description: "AI model override (e.g. gpt-4o-mini-2024-07-18, claude-3-5-haiku-20241022)"
            );
        }

        private Option<double> CreateAiBudgetOption()
        {
            return new Option<double>(
                "--ai-budget",
                getDefaultValue: () => 0.0,
                description: "AI cost budget in USD — aborts AI analysis if exceeded (0 = no limit)"
            );
        }

        private Option<bool> CreateAiStreamOption()
        {
            return new Option<bool>(
                "--ai-stream",
                getDefaultValue: () => false,
                description: "Stream AI output tokens to console in real-time (IMPROV-006)"
            );
        }

        private Option<bool> CreateAiAgentOption()
        {
            return new Option<bool>(
                "--ai-agent",
                getDefaultValue: () => false,
                description: "Use agent mode with NVD CVE lookup for network services (IMPROV-008)"
            );
        }

        private Option<string?> CreateAiCompareOption()
        {
            return new Option<string?>(
                "--ai-compare",
                getDefaultValue: () => null,
                description: "Compare multiple AI providers: 'openai/gpt-4o-mini,anthropic/claude-3-5-haiku' (IMPROV-007)"
            );
        }

        private Option<string?> CreateDiffOption()
        {
            return new Option<string?>(
                "--diff",
                getDefaultValue: () => null,
                description: "Compare with a previous scan. Use 'last' for the most recent scan of the same target, or provide a specific scan_id from the database (e.g. --diff 42)"
            ) { ArgumentHelpName = "last|scan_id" };
        }

        private Option<bool> CreateVerboseOption()
        {
            return new Option<bool>(
                aliases: new[] { "--verbose", "-v" },
                getDefaultValue: () => false,
                description: "Enable verbose logging"
            );
        }

        private Option<string?> CreateCredsFileOption()
        {
            return new Option<string?>(
                "--creds-file",
                getDefaultValue: () => null,
                description: "Path to a YAML credentials file containing multiple credential sets (MULTI-CRED)"
            ) { ArgumentHelpName = "credentials.yaml" };
        }

        private Option<string?> CreateSshKeyOption()
        {
            return new Option<string?>(
                "--ssh-key",
                getDefaultValue: () => null,
                description: "SSH key credentials for Linux auditing (format: user:~/.ssh/id_rsa or user:~/.ssh/id_rsa:passphrase). " +
                             "Takes precedence over --ssh password auth when both are specified."
            ) { ArgumentHelpName = "user:keypath[:passphrase]" };
        }

        private Option<string?> CreateSudoPasswordOption()
        {
            return new Option<string?>(
                "--sudo-password",
                getDefaultValue: () => null,
                description: "Sudo password for privilege elevation on remote Linux hosts (used with --ssh or --ssh-key). " +
                             "Enables reading protected files such as /etc/shadow and kernel audit logs."
            ) { ArgumentHelpName = "password" };
        }

        private Option<string?> CreateWinRmOption()
        {
            return new Option<string?>(
                "--winrm",
                getDefaultValue: () => null,
                description: "WinRM credentials for remote Windows auditing (format: \"DOMAIN\\user:password\" or \"user:password\"). " +
                             "Enables remote execution of Windows checks (firewall, registry, services, privesc) via WS-Man/PowerShell. " +
                             "WinRM must be enabled on the target: Enable-PSRemoting -Force"
            ) { ArgumentHelpName = "credentials" };
        }

        private Option<string?> CreateBastionOption()
        {
            return new Option<string?>(
                "--bastion",
                getDefaultValue: () => null,
                description: "SSH jump/bastion host (format: bastionhost:user:password). " +
                             "SSH connection to the target will be tunnelled through this host."
            ) { ArgumentHelpName = "host:user:password" };
        }

        // ============================================================================
        // COMMAND HANDLERS
        // ============================================================================

        private async Task HandleScanCommand(
            InvocationContext context,
            Option<string> targetOption,
            Option<string> modeOption,
            Option<string> outputOption,
            Option<string?> portsOption,
            Option<string?> authOption,
            Option<string?> authNtlmOption,
            Option<string?> kerberosOption,
            Option<string?> sshOption,
            Option<int> threadsOption,
            Option<double> rateOption,
            Option<int> timeoutOption,
            Option<bool> verifySslOption,
            Option<bool> useAiOption,
            Option<string> aiToneOption,
            Option<string?> aiProviderOption,
            Option<string?> aiModelOption,
            Option<double> aiBudgetOption,
            Option<bool> aiStreamOption,
            Option<bool> aiAgentOption,
            Option<string?> aiCompareOption,
            Option<string?> diffOption,
            Option<bool> verboseOption,
            Option<string?> credsFileOption,
            Option<string?> sshKeyOption,
            Option<string?> sudoPasswordOption,
            Option<string?> bastionOption,
            Option<string?> winRmOption)
        {
            try
            {
                // Extract options
                var target = context.ParseResult.GetValueForOption(targetOption);
                var mode = context.ParseResult.GetValueForOption(modeOption);
                var output = context.ParseResult.GetValueForOption(outputOption);
                var portsRaw = context.ParseResult.GetValueForOption(portsOption);
                var ports = string.IsNullOrEmpty(portsRaw) 
                    ? null 
                    : portsRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                var auth = context.ParseResult.GetValueForOption(authOption);
                var authNtlm = context.ParseResult.GetValueForOption(authNtlmOption);
                var kerberos = context.ParseResult.GetValueForOption(kerberosOption);
                var ssh = context.ParseResult.GetValueForOption(sshOption);
                var threads = context.ParseResult.GetValueForOption(threadsOption);
                var rate = context.ParseResult.GetValueForOption(rateOption);
                var timeout = context.ParseResult.GetValueForOption(timeoutOption);
                var verifySsl = context.ParseResult.GetValueForOption(verifySslOption);
                var useAi = context.ParseResult.GetValueForOption(useAiOption);
                var aiTone = context.ParseResult.GetValueForOption(aiToneOption) ?? "technical";
                var aiProvider = context.ParseResult.GetValueForOption(aiProviderOption);
                var aiModel = context.ParseResult.GetValueForOption(aiModelOption);
                var aiBudget = context.ParseResult.GetValueForOption(aiBudgetOption);
                var aiStream = context.ParseResult.GetValueForOption(aiStreamOption);
                var aiAgent = context.ParseResult.GetValueForOption(aiAgentOption);
                var aiCompare = context.ParseResult.GetValueForOption(aiCompareOption);
                var diff = context.ParseResult.GetValueForOption(diffOption);
                var verbose = context.ParseResult.GetValueForOption(verboseOption);
                var credsFile = context.ParseResult.GetValueForOption(credsFileOption);
                var sshKey = context.ParseResult.GetValueForOption(sshKeyOption);
                var sudoPassword = context.ParseResult.GetValueForOption(sudoPasswordOption);
                var bastion = context.ParseResult.GetValueForOption(bastionOption);
                var winRm = context.ParseResult.GetValueForOption(winRmOption);

                // Configure logging level
                if (verbose)
                {
                    Log.Logger = new LoggerConfiguration()
                        .MinimumLevel.Debug()
                        .WriteTo.Console()
                        .CreateLogger();
                }

                Log.Information("Starting scan of target: {Target}", target);
                Log.Information("Scan mode: {Mode}", mode);

                // Load configuration
                var config = Config.Load();

                // Create orchestrator
                var orchestrator = new Orchestrator(config);

                // Build scan options
                var scanOptions = new ScanOptions
                {
                    Target = target!,
                    Mode = mode!,
                    OutputFormat = output!,
                    Ports = ports,
                    AuthCredentials = auth,
                    AuthNtlm = authNtlm,
                    KerberosCredentials = kerberos,
                    SshCredentials = ssh,
                    MaxThreads = threads,
                    RateLimit = rate,
                    TimeoutSeconds = timeout,
                    VerifySsl = verifySsl,
                    UseAi = useAi,
                    AiTone = aiTone,
                    AiProvider = aiProvider,
                    AiModel = aiModel,
                    AiBudget = aiBudget,
                    AiStream = aiStream,
                    AiAgent = aiAgent,
                    AiCompare = aiCompare,
                    DiffRef = diff,
                    Verbose = verbose,
                    CredsFile = credsFile,
                    SshKeyCredentials = sshKey,
                    SshSudoPassword = sudoPassword,
                    BastionHost = bastion,
                    WinRmCredentials = winRm
                };

                // Execute scan
                var result = await orchestrator.ExecuteScanAsync(scanOptions);

                // Handle result
                if (result.Success)
                {
                    Log.Information("Scan completed successfully");
                    Log.Information("Findings: {Critical} critical, {High} high, {Medium} medium",
                        result.Summary.Critical, result.Summary.High, result.Summary.Medium);
                    
                    context.ExitCode = 0;
                }
                else
                {
                    // ============================================================================
                    // IMPROVED ERROR HANDLING
                    // ============================================================================
                    if (!string.IsNullOrEmpty(result.ErrorMessage))
                    {
                        Log.Error("Scan failed: {Error}", result.ErrorMessage);
                    }
                    else
                    {
                        Log.Error("Scan failed: Unknown error (no error message provided)");
                    }
                    
                    context.ExitCode = 1;
                }
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Fatal error during scan");
                context.ExitCode = 1;
            }
        }

        private async Task HandleGenerateConsent(string domain)
        {
            try
            {
                Log.Information("Generating consent token for domain: {Domain}", domain);
                
                var config = Config.Load();
                var validator = new ConsentValidator(config);
                var database = new Database(config);
                
                var (token, expiration) = validator.GenerateToken(domain);

                // Save token to database with method=NULL (pending state)
                try
                {
                    await database.InsertConsentTokenAsync(domain, token, expiration);
                    Log.Debug("Consent token saved to database (pending verification)");
                }
                catch (Exception dbEx)
                {
                    Log.Error(dbEx, "Failed to save consent token to database (continuing anyway)");
                }

                validator.PrintInstructions(domain, token);
                
                Log.Information("Token generated successfully");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to generate consent token");
            }
        }

        private async Task HandleVerifyConsent(string method, string domain, string token, string? sshCredentials)
        {
            try
            {
                Log.Information("Verifying consent token for domain: {Domain} via {Method}", domain, method);
                
                var config = Config.Load();
                var validator = new ConsentValidator(config);
                var database = new Database(config);
                
                bool success;
                string? result;
                
                var methodLower = method.ToLower();
                if (methodLower == "http")
                {
                    (success, result) = await validator.VerifyHttpAsync(domain, token);
                }
                else if (methodLower == "dns")
                {
                    (success, result) = await validator.VerifyDnsAsync(domain, token);
                }
                else if (methodLower == "ssh")
                {
                    if (string.IsNullOrEmpty(sshCredentials))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("✗ SSH method requires --ssh credentials (format: user:pass)");
                        Console.ResetColor();
                        Log.Error("SSH verification requested but no credentials provided");
                        return;
                    }
                    (success, result) = await validator.VerifySshAsync(domain, token, sshCredentials);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"✗ Invalid verification method: {method}");
                    Console.ResetColor();
                    Console.WriteLine("Valid methods: http, dns, ssh");
                    Log.Error("Invalid verification method: {Method}", method);
                    return;
                }
                
                if (success)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"✓ Consent verification successful!");
                    Console.ResetColor();
                    Console.WriteLine($"Proof: {result}");
                    
                    // Save proof to file
                    var proofPath = validator.SaveProof(domain, token, method, result!);
                    Console.WriteLine($"Proof saved to: {proofPath}");

                    // Update database with verification
                    try
                    {
                        var updated = await database.UpdateConsentTokenVerificationAsync(token, method, proofPath);
                        
                        if (updated)
                        {
                            Log.Information("Consent token verification saved to database");
                        }
                        else
                        {
                            Log.Warning("Consent token not found in database - verification proof saved to file only");
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine("⚠ Warning: Token not found in database. Run 'ast consent generate' first.");
                            Console.ResetColor();
                        }
                    }
                    catch (Exception dbEx)
                    {
                        Log.Error(dbEx, "Failed to save verification to database (proof file saved successfully)");
                    }
                    
                    Log.Information("Consent verified successfully");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"✗ Consent verification failed");
                    Console.ResetColor();
                    Console.WriteLine($"Error: {result}");
                    
                    Log.Warning("Consent verification failed: {Error}", result);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to verify consent token");
            }
        }
    }
}