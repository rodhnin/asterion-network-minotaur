using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DnsClient;
using Serilog;
using Renci.SshNet;

namespace Asterion.Core
{
    /// <summary>
    /// Consent Token System for Asterion
    /// Implements ownership verification via:
    /// - HTTP file placement (/.well-known/token.txt)
    /// - DNS TXT record verification
    /// - SSH file verification (for local agent mode)
    /// 
    /// Required before --aggressive or --use-ai modes.
    /// </summary>
    public class ConsentValidator
    {
        private readonly Config _config;
        private readonly Regex _tokenPattern;
        private readonly HttpClient _httpClient;

        public ConsentValidator(Config config)
        {
            _config = config;
            _tokenPattern = new Regex(@"^verify-[a-f0-9]{16}$");
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(10)
            };
        }

        /// <summary>
        /// Generate a unique consent token for a domain
        /// Format: verify-{16 hex chars}
        /// </summary>
        public (string Token, DateTime Expiration) GenerateToken(string domain)
        {
            var cleanDomain = NormalizeDomain(domain);

            // Generate token: verify-{16 hex chars}
            var randomBytes = RandomNumberGenerator.GetBytes(_config.Consent.TokenHexLength / 2);
            var randomHex = Convert.ToHexString(randomBytes).ToLower();
            var token = $"verify-{randomHex}";

            // Calculate expiration
            var expiration = DateTime.UtcNow.AddHours(_config.Consent.TokenExpiryHours);

            Log.Information("Generated consent token for {Domain}: {Token}", cleanDomain, token);
            Log.Information("Token expires at: {Expiration:o}", expiration);

            return (token, expiration);
        }

        /// <summary>
        /// Print human-readable instructions for token placement
        /// </summary>
        public void PrintInstructions(string domain, string token)
        {
            var normalizedDomain = NormalizeDomain(domain);
            var hasPort = normalizedDomain.Contains(':');
            
            // Construct URL with port if present
            var protocol = hasPort ? "http" : "https";
            var httpPath = $"{protocol}://{normalizedDomain}{_config.Consent.HttpVerificationPath}{token}.txt";
            
            // Display domain without port for DNS
            var displayDomain = GetBaseDomain(domain);

            Console.WriteLine();
            Console.WriteLine("=".PadRight(70, '='));
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("DOMAIN OWNERSHIP VERIFICATION REQUIRED");
            Console.ResetColor();
            Console.WriteLine("=".PadRight(70, '='));
            Console.WriteLine();
            Console.WriteLine($"Domain: {displayDomain}");
            Console.WriteLine($"Token: {token}");
            Console.WriteLine($"Expires: {_config.Consent.TokenExpiryHours} hours from now");
            Console.WriteLine();
            
            // Method 1: HTTP File
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("┌─ METHOD 1: HTTP File (Recommended)");
            Console.ResetColor();
            Console.WriteLine("│");
            Console.WriteLine("│  1. Create a text file containing EXACTLY this:");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"│     {token}");
            Console.ResetColor();
            Console.WriteLine("│");
            Console.WriteLine("│  2. Upload it to:");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"│     {httpPath}");
            Console.ResetColor();
            Console.WriteLine("│");
            Console.WriteLine("│  3. Verify it's accessible in your browser");
            Console.WriteLine("│");
            Console.WriteLine("│  4. Run verification:");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"│     ast consent verify --method http --domain {normalizedDomain} --token {token}");
            Console.ResetColor();
            Console.WriteLine("└─");
            Console.WriteLine();
            
            // Method 2: DNS TXT Record
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("┌─ METHOD 2: DNS TXT Record (Alternative)");
            Console.ResetColor();
            Console.WriteLine("│");
            Console.WriteLine("│  1. Add a TXT record to your DNS:");
            Console.WriteLine($"│     Host: {displayDomain}");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"│     Value: {_config.Consent.DnsTxtPrefix}{token}");
            Console.ResetColor();
            Console.WriteLine("│");
            Console.WriteLine("│  2. Wait for DNS propagation (5-30 minutes)");
            Console.WriteLine("│");
            Console.WriteLine("│  3. Run verification:");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"│     ast consent verify --method dns --domain {normalizedDomain} --token {token}");
            Console.ResetColor();
            Console.WriteLine("└─");
            Console.WriteLine();
            
            // Method 3: SSH File (for server-side verification)
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("┌─ METHOD 3: SSH File (For Server Access)");
            Console.ResetColor();
            Console.WriteLine("│");
            Console.WriteLine("│  1. SSH into the target server and create a file:");
            Console.WriteLine("│     Linux: /tmp/consent_{token}");
            Console.WriteLine("│     Windows: C:\\Consent\\{token}.txt");
            Console.WriteLine("│");
            Console.WriteLine("│  2. File content (same as above):");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"│     {token}");
            Console.ResetColor();
            Console.WriteLine("│");
            Console.WriteLine("│  3. Run verification with SSH credentials:");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"│     ast consent verify --method ssh --domain {normalizedDomain} --token {token} --ssh user:pass");
            Console.ResetColor();
            Console.WriteLine("└─");
            Console.WriteLine();
            
            Console.WriteLine("=".PadRight(70, '='));
            Console.WriteLine("NOTE: You must verify ownership before using --aggressive or --use-ai");
            Console.WriteLine("=".PadRight(70, '='));
            Console.WriteLine();
        }

        /// <summary>
        /// Verify consent token via HTTP file
        /// Tries HTTPS first, then HTTP
        /// Preserves port in domain if present
        /// </summary>
        public async Task<(bool Success, string? ProofOrError)> VerifyHttpAsync(string domain, string token)
        {
            if (!ValidateTokenFormat(token))
            {
                return (false, $"Invalid token format: {token}");
            }

            var normalizedDomain = NormalizeDomain(domain);
            var hasPort = normalizedDomain.Contains(':');
            
            // Try protocols
            var protocols = hasPort ? new[] { "http" } : new[] { "https", "http" };

            foreach (var protocol in protocols)
            {
                var url = $"{protocol}://{normalizedDomain}{_config.Consent.HttpVerificationPath}{token}.txt";
                
                Log.Information("Attempting HTTP verification: {Url}", url);

                try
                {
                    var response = await _httpClient.GetAsync(url);

                    if (response.IsSuccessStatusCode)
                    {
                        var content = (await response.Content.ReadAsStringAsync()).Trim();

                        if (content == token)
                        {
                            Log.Information("✓ HTTP verification successful: {Url}", url);
                            return (true, url);
                        }
                        else
                        {
                            Log.Warning("Token mismatch. Expected: {Expected}, Got: {Got}", token, content);
                            return (false, $"Token content mismatch at {url}");
                        }
                    }
                    else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        Log.Information("Token file not found at {Url}", url);
                        continue;
                    }
                    else
                    {
                        Log.Warning("Unexpected status code {StatusCode} at {Url}", response.StatusCode, url);
                    }
                }
                catch (HttpRequestException ex)
                {
                    Log.Information("Request failed for {Url}: {Error}", url, ex.Message);
                    continue;
                }
            }

            return (false, $"Token file not accessible at {normalizedDomain}{_config.Consent.HttpVerificationPath}{token}.txt");
        }

        /// <summary>
        /// Verify consent token via DNS TXT record
        /// Strips port from domain (DNS doesn't use ports)
        /// First tries to resolve domain's authoritative nameservers, then falls back to system DNS
        /// </summary>
        public async Task<(bool Success, string? ProofOrError)> VerifyDnsAsync(string domain, string token)
        {
            if (!ValidateTokenFormat(token))
            {
                return (false, $"Invalid token format: {token}");
            }

            var domainForDns = GetBaseDomain(domain);
            var expectedTxt = $"{_config.Consent.DnsTxtPrefix}{token}";

            Log.Information("Attempting DNS verification for {Domain}", domainForDns);
            Log.Information("Looking for TXT record: {Expected}", expectedTxt);

            try
            {
                // ====================================================================
                // STRATEGY 1: Try to get authoritative nameservers for the domain
                // ====================================================================
                ILookupClient? authoritativeLookup = null;
                
                try
                {
                    var systemLookup = new LookupClient();
                    var nsResponse = await systemLookup.QueryAsync(domainForDns, QueryType.NS);
                    
                    var nameservers = nsResponse.Answers.NsRecords()
                        .Select(ns => ns.NSDName.Value)
                        .ToList();
                    
                    if (nameservers.Any())
                    {
                        Log.Information("Found {Count} authoritative nameserver(s): {Nameservers}", 
                            nameservers.Count, string.Join(", ", nameservers));
                        
                        // Use first authoritative nameserver
                        var nsHost = nameservers.First();
                        
                        // Resolve NS hostname to IP
                        var nsIpResponse = await systemLookup.QueryAsync(nsHost, QueryType.A);
                        var nsIp = nsIpResponse.Answers.ARecords().FirstOrDefault()?.Address;
                        
                        if (nsIp != null)
                        {
                            Log.Information("Using authoritative nameserver: {NS} ({IP})", nsHost, nsIp);
                            
                            authoritativeLookup = new LookupClient(nsIp);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Warning("Could not resolve authoritative nameservers: {Error}", ex.Message);
                }

                // ====================================================================
                // STRATEGY 2: Fall back to system DNS if no authoritative NS found
                // ====================================================================
                var lookup = authoritativeLookup ?? new LookupClient();
                var response = await lookup.QueryAsync(domainForDns, QueryType.TXT);

                // ====================================================================
                // Log all TXT records found
                // ====================================================================
                var txtRecordCount = response.Answers.TxtRecords().Count();
                Log.Debug("Found {Count} TXT record(s) for {Domain}", txtRecordCount, domainForDns);

                if (txtRecordCount == 0)
                {
                    Log.Warning("No TXT records found for {Domain}", domainForDns);
                    return (false, $"No TXT records found for {domainForDns}");
                }

                foreach (var txtRecord in response.Answers.TxtRecords())
                {
                    Log.Debug("Processing TXT record with {TextCount} text value(s)", txtRecord.Text.Count());
                    
                    foreach (var txtValue in txtRecord.Text)
                    {
                        Log.Debug("Raw TXT value: [{Raw}]", txtValue);
                        
                        var cleanTxtValue = txtValue.Trim().Trim('"');
                        
                        Log.Debug("Cleaned TXT value: [{Cleaned}]", cleanTxtValue);
                        Log.Debug("Match: {Match}", cleanTxtValue == expectedTxt);
                        
                        if (cleanTxtValue == expectedTxt)
                        {
                            Log.Information("✓ DNS verification successful for {Domain}", domainForDns);
                            return (true, cleanTxtValue);
                        }
                    }
                }

                Log.Warning("Token not found in any TXT records for {Domain}", domainForDns);
                return (false, $"Token not found in TXT records for {domainForDns}");
            }
            catch (DnsResponseException ex)
            {
                var codeStr = ex.DnsError?.ToString();
                var nxDomEnumName = DnsResponseCode.NotExistentDomain.ToString();

                if (string.Equals(codeStr, nxDomEnumName, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(codeStr, "NXDOMAIN", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(codeStr, "NxDomain", StringComparison.OrdinalIgnoreCase))
                {
                    return (false, $"Domain {domainForDns} does not exist");
                }

                return (false, $"DNS query failed ({codeStr ?? "Unknown"}): {ex.Message}");
            }
        }

        /// <summary>
        /// Verify consent token via SSH file on remote server
        /// Connects via SSH and checks for token file
        /// Linux: /tmp/consent_{token}
        /// Windows: C:\Consent\{token}.txt
        /// </summary>
        public async Task<(bool Success, string? ProofOrError)> VerifySshAsync(
            string domain, 
            string token, 
            string sshCredentials)
        {
            if (!ValidateTokenFormat(token))
            {
                return (false, $"Invalid token format: {token}");
            }

            // Parse SSH credentials (format: user:pass)
            var parts = sshCredentials.Split(':', 2);
            if (parts.Length != 2)
            {
                return (false, "Invalid SSH credentials format. Use: user:pass");
            }

            var username = parts[0];
            var password = parts[1];
            var host = GetBaseDomain(domain);

            Log.Information("Attempting SSH verification for {Host}", host);

            SshClient? client = null;

            try
            {
                client = new SshClient(host, username, password);
                
                // Connect with error handling
                await Task.Run(() => 
                {
                    try
                    {
                        client.Connect();
                    }
                    catch (System.Net.Sockets.SocketException sockEx)
                    {
                        // Translate socket errors to user-friendly messages
                        var message = sockEx.SocketErrorCode switch
                        {
                            System.Net.Sockets.SocketError.HostNotFound => 
                                "Host not found - check DNS",
                            System.Net.Sockets.SocketError.HostUnreachable => 
                                "Host unreachable - check network/firewall",
                            System.Net.Sockets.SocketError.NetworkUnreachable => 
                                "Network unreachable",
                            System.Net.Sockets.SocketError.ConnectionRefused => 
                                "Connection refused - SSH not running?",
                            System.Net.Sockets.SocketError.TimedOut => 
                                "Connection timeout",
                            System.Net.Sockets.SocketError.AccessDenied => 
                                "Access denied",
                            System.Net.Sockets.SocketError.AddressNotAvailable => 
                                "Address not available",
                            _ => sockEx.Message
                        };
                        throw new Exception(message);
                    }
                    catch (Renci.SshNet.Common.SshAuthenticationException)
                    {
                        throw new Exception("SSH authentication failed - check username/password");
                    }
                });

                if (!client.IsConnected)
                {
                    return (false, $"Failed to connect to {host} via SSH");
                }

                // Detect OS (basic check)
                var unameCmd = client.RunCommand("uname");
                bool isLinux = unameCmd.ExitStatus == 0 && unameCmd.Result.Contains("Linux");

                // Try appropriate paths
                string[] pathsToCheck = isLinux
                    ? new[] { $"/tmp/consent_{token}", $"/var/tmp/consent_{token}" }
                    : new[] { $@"C:\Consent\{token}.txt", $@"C:\Temp\consent_{token}.txt" };

                foreach (var path in pathsToCheck)
                {
                    var catCmd = isLinux 
                        ? client.RunCommand($"cat {path}")
                        : client.RunCommand($"type {path}");

                    if (catCmd.ExitStatus == 0)
                    {
                        var content = catCmd.Result.Trim();
                        
                        if (content == token)
                        {
                            Log.Information("✓ SSH verification successful: Found token at {Path}", path);
                            return (true, $"SSH:{host}:{path}");
                        }
                        else
                        {
                            Log.Warning("Token mismatch at {Path}. Expected: {Expected}, Got: {Got}", 
                                path, token, content);
                        }
                    }
                }

                return (false, $"Token file not found on {host} via SSH");
            }
            catch (Exception ex)
            {
                // Don't pass exception object to Log - causes stack trace
                Log.Warning("SSH verification failed for {Host}: {Error}", host, ex.Message);
                return (false, ex.Message);
            }
            finally
            {
                // Cleanup
                if (client != null)
                {
                    try
                    {
                        if (client.IsConnected)
                        {
                            client.Disconnect();
                        }
                        client.Dispose();
                    }
                    catch { }
                }
            }
        }

        /// <summary>
        /// Save verification proof to file
        /// </summary>
        public string SaveProof(string domain, string token, string method, string proof)
        {
            var baseDomain = GetBaseDomain(domain);
            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            var filename = $"{baseDomain}_{method}_{timestamp}.txt";

            var proofPath = Path.Combine(_config.Paths.ConsentProofsDir, filename);
            
            // Ensure directory exists
            Directory.CreateDirectory(_config.Paths.ConsentProofsDir);

            var normalizedDomain = NormalizeDomain(domain);

            var proofContent = $@"Domain: {normalizedDomain}
Token: {token}
Method: {method}
Verified: {DateTime.UtcNow:o}
Proof: {proof}
";

            File.WriteAllText(proofPath, proofContent);

            Log.Information("Verification proof saved: {Path}", proofPath);
            return proofPath;
        }

        /// <summary>
        /// Normalize domain string (remove protocol and path, PRESERVE port)
        /// </summary>
        private string NormalizeDomain(string domain)
        {
            // If it looks like a URL, parse it
            if (domain.Contains("://"))
            {
                var uri = new Uri(domain);
                domain = uri.Authority;
            }

            // Remove path (but keep port)
            if (domain.Contains('/'))
            {
                domain = domain.Split('/')[0];
            }

            return domain.Trim().ToLower();
        }

        /// <summary>
        /// Get base domain without port (for DNS queries and display)
        /// </summary>
        private string GetBaseDomain(string domain)
        {
            var normalized = NormalizeDomain(domain);

            // Remove port if present
            if (normalized.Contains(':'))
            {
                return normalized.Split(':')[0];
            }

            return normalized;
        }

        /// <summary>
        /// Validate token format (verify-{16 hex chars})
        /// </summary>
        private bool ValidateTokenFormat(string token)
        {
            return _tokenPattern.IsMatch(token);
        }
    }
}