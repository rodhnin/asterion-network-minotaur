using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Serilog;

namespace Asterion.Core.Utils
{
    /// <summary>
    /// Authentication Manager - Handles NTLM, Kerberos, and standard authentication
    /// 
    /// Features:
    /// - Pass-the-hash via impacket-smbclient (NTLM)
    /// - Kerberos authentication (native .NET)
    /// - Standard username/password authentication
    /// - Impacket availability detection
    /// - SMB share enumeration via impacket
    /// 
    /// NTLM Implementation:
    /// Uses impacket-smbclient via Process.Start() for pass-the-hash attacks.
    /// Requires impacket to be installed on the system.
    /// 
    /// Kerberos Implementation:
    /// Uses System.DirectoryServices.Protocols with AuthType.Kerberos
    /// </summary>
    public class AuthenticationManager
    {
        private bool? _impacketAvailable = null;
        private string? _impacketPath = null;

        /// <summary>
        /// Check if impacket-smbclient is available on the system (cross-platform, robust)
        /// </summary>
        public async Task<bool> IsImpacketAvailableAsync()
        {
            if (_impacketAvailable.HasValue)
                return _impacketAvailable.Value;

            try
            {
                var candidates = new List<string>();

                // 1) OS resolver (which/where)
                try
                {
                    var resolver = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "where" : "which";
                    using var p = Process.Start(new ProcessStartInfo
                    {
                        FileName = resolver,
                        Arguments = "impacket-smbclient",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    });
                    if (p != null)
                    {
                        var so = await p.StandardOutput.ReadToEndAsync();
                        await p.WaitForExitAsync();
                        if (!string.IsNullOrWhiteSpace(so))
                        {
                            foreach (var line in so.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
                            {
                                var path = line.Trim();
                                if (!string.IsNullOrEmpty(path) && !candidates.Contains(path))
                                    candidates.Add(path);
                            }
                        }
                    }
                }
                catch { /* continue with extra paths */ }

                // 2) Known paths
                var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    candidates.AddRange(new[]
                    {
                        @"C:\Python39\Scripts\impacket-smbclient.exe",
                        @"C:\Python311\Scripts\impacket-smbclient.exe",
                        @"C:\Program Files\Impacket\impacket-smbclient.exe",
                        "impacket-smbclient"
                    }.Where(p => !candidates.Contains(p)));
                }
                else
                {
                    candidates.AddRange(new[]
                    {
                        "/usr/bin/impacket-smbclient",
                        "/bin/impacket-smbclient",
                        "/usr/local/bin/impacket-smbclient",
                        "/snap/bin/impacket-smbclient",
                        Path.Combine(home, ".local", "bin", "impacket-smbclient"),
                        "impacket-smbclient"
                    }.Where(p => !candidates.Contains(p)));
                }

                // 3) Validate candidates by executing -h and filtering ModuleNotFoundError
                foreach (var candidate in candidates)
                {
                    try
                    {
                        // If absolute path but not exists -> skip (unless it's a bare name)
                        if (Path.IsPathRooted(candidate) && !File.Exists(candidate))
                        {
                            Log.Debug("[AuthenticationManager] Candidate not found: {Candidate}", candidate);
                            continue;
                        }

                        var (ok, resolved) = await ValidateImpacketCandidateAsync(candidate);
                        if (!ok)
                            continue;

                        _impacketPath = resolved;
                        _impacketAvailable = true;
                        Log.Debug("[AuthenticationManager] Impacket OK at: {Path}", _impacketPath);
                        return true;
                    }
                    catch (System.ComponentModel.Win32Exception ex)
                    {
                        Log.Debug(ex, "[AuthenticationManager] Cannot start candidate: {Candidate}", candidate);
                        continue;
                    }
                    catch (Exception ex)
                    {
                        Log.Debug(ex, "[AuthenticationManager] Error validating candidate: {Candidate}", candidate);
                        continue;
                    }
                }

                // 4) Fallback: only Python package present (no script)
                if (await CanImportImpacketAsync())
                {
                    _impacketAvailable = true;
                    _impacketPath = "impacket-python"; // marker: available via Python, but script path unknown
                    Log.Debug("[AuthenticationManager] impacket importable desde Python.");
                    return true;
                }

                _impacketAvailable = false;
                Log.Warning("[AuthenticationManager] Impacket no encontrado o no usable. Instala con: python3 -m pip install --upgrade impacket");
                return false;
            }
            catch (Exception ex)
            {
                _impacketAvailable = false;
                Log.Debug(ex, "[AuthenticationManager] Failed to check for impacket");
                return false;
            }
        }

        /// <summary>
        /// Validate a candidate path/name for impacket-smbclient by running '-h'
        /// </summary>
        private async Task<(bool ok, string resolvedPath)> ValidateImpacketCandidateAsync(string candidate)
        {
            // Bare name allowed (will be resolved by shell PATH)
            var usePython = candidate.EndsWith(".py", StringComparison.OrdinalIgnoreCase);
            var (exe, args) = BuildHelpCommand(candidate, usePython);

            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });

            if (p == null)
                return (false, candidate);

            var soTask = p.StandardOutput.ReadToEndAsync();
            var seTask = p.StandardError.ReadToEndAsync();
            var finished = p.WaitForExit(4000);
            var so = await soTask;
            var se = await seTask;

            var combined = (so ?? "") + (se ?? "");
            if (combined.IndexOf("ModuleNotFoundError", StringComparison.OrdinalIgnoreCase) >= 0 ||
                combined.IndexOf("No module named 'impacket'", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Log.Debug("[AuthenticationManager] Candidate {Candidate} failed: ModuleNotFoundError", candidate);
                return (false, candidate);
            }

            if (finished && (p.ExitCode == 0 || !string.IsNullOrWhiteSpace(combined)))
                return (true, candidate);

            return (false, candidate);
        }

        /// <summary>
        /// Build the command to show help for a candidate (handles .py vs executable)
        /// </summary>
        private (string exe, string args) BuildHelpCommand(string path, bool forcePython = false)
        {
            if (forcePython || path.EndsWith(".py", StringComparison.OrdinalIgnoreCase))
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    return ("py", $"-3 \"{path}\" -h");
                else
                    return ("python3", $"\"{path}\" -h");
            }
            return (path, "-h");
        }

        /// <summary>
        /// Check if Python can import 'impacket' (fallback)
        /// </summary>
        private async Task<bool> CanImportImpacketAsync()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    using var p = Process.Start(new ProcessStartInfo
                    {
                        FileName = "py",
                        Arguments = "-3 -c \"import impacket; print('IMPACKET_OK')\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    });
                    if (p != null)
                    {
                        var so = await p.StandardOutput.ReadToEndAsync();
                        await p.WaitForExitAsync();
                        if ((so ?? "").Contains("IMPACKET_OK")) return true;
                    }
                }

                // Use 'python' on Windows, 'python3' on Linux/Mac
                var pythonCmd = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "python" : "python3";

                using var p2 = Process.Start(new ProcessStartInfo
                {
                    FileName = pythonCmd,
                    Arguments = "-c \"import impacket; print('IMPACKET_OK')\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                });
                if (p2 != null)
                {
                    var so2 = await p2.StandardOutput.ReadToEndAsync();
                    await p2.WaitForExitAsync();
                    if ((so2 ?? "").Contains("IMPACKET_OK")) return true;
                }
            }
            catch { /* ignore */ }

            return false;
        }

        /// <summary>
        /// Parse standard credentials in format: DOMAIN\user:password or user:password
        /// </summary>
        public (string? username, string? password, string? domain) ParseCredentials(string credentials)
        {
            if (string.IsNullOrEmpty(credentials))
                return (null, null, null);

            try
            {
                var colonIndex = credentials.LastIndexOf(':');
                if (colonIndex == -1)
                    return (credentials, null, null);

                var password = credentials.Substring(colonIndex + 1);
                var userPart = credentials.Substring(0, colonIndex);

                var backslashIndex = userPart.IndexOf('\\');
                if (backslashIndex != -1)
                {
                    var domain = userPart.Substring(0, backslashIndex);
                    var username = userPart.Substring(backslashIndex + 1);
                    return (username, password, domain);
                }

                return (userPart, password, null);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "[AuthenticationManager] Failed to parse credentials");
                return (null, null, null);
            }
        }

        /// <summary>
        /// Parse NTLM credentials in format: username:ntlmhash
        /// </summary>
        public (string? username, string? ntlmHash) ParseNtlmCredentials(string ntlmAuth)
        {
            if (string.IsNullOrEmpty(ntlmAuth))
                return (null, null);

            try
            {
                var parts = ntlmAuth.Split(':');
                if (parts.Length != 2)
                {
                    Log.Error("[AuthenticationManager] Invalid NTLM format. Expected: username:ntlmhash");
                    return (null, null);
                }

                var username = parts[0];
                var ntlmHash = parts[1];

                if (ntlmHash.Length != 32 || !IsHexString(ntlmHash))
                {
                    Log.Error("[AuthenticationManager] Invalid NTLM hash format. Expected 32 hex characters.");
                    return (null, null);
                }

                return (username, ntlmHash);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "[AuthenticationManager] Failed to parse NTLM credentials");
                return (null, null);
            }
        }

        /// <summary>
        /// Parse Kerberos credentials in format: user:password@REALM or user@REALM
        /// </summary>
        public (string? username, string? password, string? realm) ParseKerberosCredentials(string kerberosAuth)
        {
            if (string.IsNullOrEmpty(kerberosAuth))
                return (null, null, null);
            
            try
            {
                var atIndex = kerberosAuth.LastIndexOf('@');
                if (atIndex == -1)
                {
                    Log.Error("[AuthenticationManager] Invalid Kerberos format. Expected: user:password@REALM or user@REALM");
                    return (null, null, null);
                }
                
                var realm = kerberosAuth.Substring(atIndex + 1);
                var userPass = kerberosAuth.Substring(0, atIndex);
                
                var colonIndex = userPass.LastIndexOf(':');
                if (colonIndex == -1)
                {
                    var username = userPass;
                    Log.Debug("[AuthenticationManager] Parsed Kerberos principal (no password): {User}@{Realm}", username, realm);
                    return (username, null, realm);
                }
                
                var usernameWithPass = userPass.Substring(0, colonIndex);
                var password = userPass.Substring(colonIndex + 1);
                Log.Debug("[AuthenticationManager] Parsed Kerberos credentials: {User}@{Realm}", usernameWithPass, realm);
                return (usernameWithPass, password, realm);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "[AuthenticationManager] Failed to parse Kerberos credentials");
                return (null, null, null);
            }
        }

        /// <summary>
        /// Convert Kerberos credentials to Basic auth format
        /// From: user:password@REALM -> (username, password, domain=REALM)
        /// </summary>
        public (string? username, string? password, string? domain) ConvertKerberosToBasic(string kerberosAuth)
        {
            var (username, password, realm) = ParseKerberosCredentials(kerberosAuth);

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password) || string.IsNullOrEmpty(realm))
            {
                return (null, null, null);
            }
            return (username, password, realm);
        }

        /// <summary>
        /// Check if Kerberos is configured on Linux (/etc/krb5.conf exists)
        /// </summary>
        public bool IsKerberosConfigured()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return true; // Windows siempre soporta Kerberos via SSPI
            
            // Check for krb5.conf
            var configPaths = new[]
            {
                "/etc/krb5.conf",
                Environment.GetEnvironmentVariable("KRB5_CONFIG"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".krb5.conf")
            };
            
            return configPaths.Any(p => !string.IsNullOrEmpty(p) && File.Exists(p));
        }

        /// <summary>
        /// Check if there's a valid Kerberos ticket (klist)
        /// </summary>
        public async Task<bool> HasValidKerberosTicketAsync(string? principal = null)
        {
            try
            {
                using var process = Process.Start(new ProcessStartInfo
                {
                    FileName = "klist",
                    Arguments = string.Empty,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                });
                
                if (process == null)
                    return false;
                
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                if (process.ExitCode != 0)
                    return false;
                
                // Check if ticket exists and is not expired
                if (!output.Contains("Ticket cache:", StringComparison.OrdinalIgnoreCase) &&
                    !output.Contains("Default principal:", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
                
                // If principal specified, verify it matches
                if (!string.IsNullOrEmpty(principal))
                {
                    if (!output.Contains(principal, StringComparison.OrdinalIgnoreCase))
                    {
                        Log.Debug("[AuthenticationManager] Kerberos ticket exists but not for principal: {Principal}", principal);
                        return false;
                    }
                }
                
                Log.Debug("[AuthenticationManager] Valid Kerberos ticket found");
                return true;
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[AuthenticationManager] Failed to check Kerberos ticket");
                return false;
            }
        }

        /// <summary>
        /// Obtain Kerberos ticket using kinit
        /// </summary>
        public async Task<bool> ObtainKerberosTicketAsync(string username, string password, string realm)
        {
            try
            {
                var principal = $"{username}@{realm}";
                
                Log.Information("[AuthenticationManager] Obtaining Kerberos ticket for {Principal}", principal);
                
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "kinit",
                        Arguments = principal,
                        RedirectStandardInput = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                
                // Send password to kinit
                await process.StandardInput.WriteLineAsync(password);
                await process.StandardInput.FlushAsync();
                process.StandardInput.Close();
                
                var output = await process.StandardOutput.ReadToEndAsync();
                var error = await process.StandardError.ReadToEndAsync();
                
                await process.WaitForExitAsync();
                
                if (process.ExitCode == 0)
                {
                    Log.Information("[AuthenticationManager] Kerberos ticket obtained successfully for {Principal}", principal);
                    return true;
                }
                
                var combined = output + error;
                Log.Warning("[AuthenticationManager] Failed to obtain Kerberos ticket: {Error}", combined);
                return false;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[AuthenticationManager] Error obtaining Kerberos ticket");
                return false;
            }
        }

        /// <summary>
        /// Enumerate SMB shares using NTLM hash via impacket-smbclient
        /// </summary>
        public async Task<(bool success, List<SmbShareInfo> shares, string rawOutput)> EnumerateSharesNtlmAsync(
            string target,
            string username,
            string ntlmHash,
            int timeoutSeconds = 30)
        {
            if (!await IsImpacketAvailableAsync())
            {
                Log.Error("[AuthenticationManager] NTLM share enumeration requires impacket. Install with: pip3 install impacket");
                return (false, new List<SmbShareInfo>(), "Impacket not installed");
            }

            try
            {
                // Build command using validated path
                string exe, args;
                if (!string.IsNullOrEmpty(_impacketPath) && _impacketPath.EndsWith(".py", StringComparison.OrdinalIgnoreCase))
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                        (exe, args) = ("py", $"-3 \"{_impacketPath}\" -hashes :{ntlmHash} {username}@{target} -no-pass");
                    else
                        (exe, args) = ("python3", $"\"{_impacketPath}\" -hashes :{ntlmHash} {username}@{target} -no-pass");
                }
                else if (!string.IsNullOrEmpty(_impacketPath) && (!Path.IsPathRooted(_impacketPath) || File.Exists(_impacketPath)))
                {
                    // Executable wrapper (e.g., /usr/share/impacket/script or /usr/bin/impacket-smbclient)
                    (exe, args) = (_impacketPath, $"-hashes :{ntlmHash} {username}@{target} -no-pass");
                }
                else
                {
                    // Fallback to PATH name
                    (exe, args) = ("impacket-smbclient", $"-hashes :{ntlmHash} {username}@{target} -no-pass");
                }

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = exe,
                        Arguments = args,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        RedirectStandardInput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                var output = new StringBuilder();
                var error = new StringBuilder();

                process.OutputDataReceived += (sender, e) => { if (e.Data != null) output.AppendLine(e.Data); };
                process.ErrorDataReceived += (sender, e) => { if (e.Data != null) error.AppendLine(e.Data); };

                Log.Debug("[AuthenticationManager] Executing: {Exe} -hashes :*** {Username}@{Target}", Path.GetFileName(exe), username, target);

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                // Dar tiempo a que el wrapper/cliente inicialice
                await Task.Delay(1500);

                if (process.HasExited)
                {
                    var earlyOutput = output.ToString() + error.ToString();
                    Log.Warning("[AuthenticationManager] impacket-smbclient exited prematurely (exit code: {ExitCode})", process.ExitCode);
                    Log.Debug("[AuthenticationManager] Output: {Output}", earlyOutput);

                    if (earlyOutput.Contains("STATUS_LOGON_FAILURE") || earlyOutput.Contains("[-]"))
                    {
                        return (false, new List<SmbShareInfo>(), "Authentication failed - invalid NTLM hash or account locked");
                    }

                    return (false, new List<SmbShareInfo>(), earlyOutput);
                }

                try
                {
                    // ✅ FIX: Enviar "shares" y esperar MÁS tiempo para el output completo
                    await process.StandardInput.WriteLineAsync("shares");
                    await process.StandardInput.FlushAsync();
                    
                    Log.Debug("[AuthenticationManager] Sent 'shares' command, waiting for output...");
                    
                    // ✅ FIX: Esperar 3 segundos (antes era 2s) para asegurar output completo
                    await Task.Delay(3000);
                    
                    // ✅ FIX: Enviar "exit" para cerrar limpiamente
                    await process.StandardInput.WriteLineAsync("exit");
                    await process.StandardInput.FlushAsync();
                    process.StandardInput.Close();
                    
                    Log.Debug("[AuthenticationManager] Sent 'exit' command");
                }
                catch (IOException ex)
                {
                    Log.Warning("[AuthenticationManager] Process died while sending commands: {Error}", ex.Message);
                }

                var completed = await Task.Run(() => process.WaitForExit(timeoutSeconds * 1000));

                if (!completed)
                {
                    try { process.Kill(); } catch { /* ignore */ }
                    Log.Warning("[AuthenticationManager] NTLM share enumeration timed out after {Timeout}s", timeoutSeconds);
                    return (false, new List<SmbShareInfo>(), "Timeout");
                }

                var fullOutput = output.ToString() + error.ToString();

                // Basic success/failure heuristic
                if (!fullOutput.Contains("smb:", StringComparison.OrdinalIgnoreCase) &&
                    !fullOutput.Contains("shares", StringComparison.OrdinalIgnoreCase) &&
                    process.ExitCode != 0)
                {
                    Log.Warning("[AuthenticationManager] NTLM authentication may have failed: {Output}", fullOutput.Trim());
                    return (false, new List<SmbShareInfo>(), fullOutput);
                }

                Log.Information("[AuthenticationManager] NTLM authentication succeeded: {Username}@{Target}", username, target);

                var shares = ParseImpacketShares(fullOutput);

                Log.Information("[AuthenticationManager] Found {Count} SMB shares on {Target}", shares.Count, target);

                return (true, shares, fullOutput);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[AuthenticationManager] NTLM share enumeration error");
                return (false, new List<SmbShareInfo>(), ex.Message);
            }
        }

        /// <summary>
        /// Parse impacket-smbclient output to extract share information
        /// </summary>
        private List<SmbShareInfo> ParseImpacketShares(string output)
        {
            var shares = new List<SmbShareInfo>();
            
            try
            {
                var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                
                foreach (var line in lines)
                {
                    if (line.Contains("Impacket v", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("Copyright", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("Fortra", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("Type help", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("smb:", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("Type", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("----") ||
                        line.Equals("#", StringComparison.OrdinalIgnoreCase) ||
                        string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }
                    
                    var trimmed = line.Trim();
                    
                    if (trimmed.StartsWith("# "))
                    {
                        trimmed = trimmed.Substring(2).Trim();
                    }
                    
                    if (trimmed.Length > 0 && 
                        trimmed.Length <= 20 &&
                        Regex.IsMatch(trimmed, @"^[A-Za-z0-9_$-]+$"))
                    {
                        bool isSensitive = IsSensitiveShare(trimmed);
                        
                        shares.Add(new SmbShareInfo
                        {
                            Name = trimmed,
                            Type = "Unknown",
                            Comment = string.Empty,
                            IsSensitive = isSensitive
                        });
                        
                        Log.Debug("[AuthenticationManager] Parsed share: {Name} - Sensitive: {Sensitive}",
                            trimmed, isSensitive);
                    }
                    else
                    {
                        Log.Debug("[AuthenticationManager] Skipping invalid line: {Line}", 
                            trimmed.Substring(0, Math.Min(50, trimmed.Length)));
                    }
                }
                
                if (shares.Count == 0)
                {
                    Log.Warning("[AuthenticationManager] No shares parsed from output");
                }
                else
                {
                    Log.Information("[AuthenticationManager] Successfully parsed {Count} share(s)", shares.Count);
                }
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "[AuthenticationManager] Failed to parse impacket shares output");
            }
            
            return shares;
        }

        /// <summary>
        /// Determine if a share name is sensitive
        /// </summary>
        private bool IsSensitiveShare(string shareName)
        {
            var sensitiveShares = new[]
            {
                "ADMIN$",
                "C$",
                "D$",
                "E$",
                "SYSVOL",
                "NETLOGON",
                "Users",
                "Backup",
                "Backups"
            };

            return sensitiveShares.Any(s => shareName.Equals(s, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Test if a string is valid hex
        /// </summary>
        private bool IsHexString(string str)
        {
            return str.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
        }
    }

    /// <summary>
    /// SMB Share information parsed from impacket output
    /// </summary>
    public class SmbShareInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Comment { get; set; } = string.Empty;
        public bool IsSensitive { get; set; }
    }
}
