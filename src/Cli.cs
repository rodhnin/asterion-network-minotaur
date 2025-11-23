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
            var verboseOption = CreateVerboseOption();
            
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
                verboseOption
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
                    verboseOption
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
                Console.WriteLine("Version: 0.1.0");
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

        private Option<bool> CreateVerboseOption()
        {
            return new Option<bool>(
                aliases: new[] { "--verbose", "-v" },
                getDefaultValue: () => false,
                description: "Enable verbose logging"
            );
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
            Option<bool> verboseOption)
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
                var verbose = context.ParseResult.GetValueForOption(verboseOption);

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
                    Verbose = verbose
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