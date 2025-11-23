using System;
using System.Threading.Tasks;
using Renci.SshNet;
using Serilog;

namespace Asterion.Core
{
    /// <summary>
    /// Manages SSH connections to remote for authenticated auditing.
    /// Provides command execution and platform detection capabilities.
    /// </summary>
    public class SshConnectionManager : IDisposable
    {
        private readonly string _host;
        private readonly string _username;
        private readonly string _password;
        private SshClient? _client;
        private bool _isConnected;

        /// <summary>
        /// Initialize SSH connection manager
        /// </summary>
        /// <param name="host">Target hostname or IP address</param>
        /// <param name="username">SSH username</param>
        /// <param name="password">SSH password (plaintext)</param>
        public SshConnectionManager(string host, string username, string password)
        {
            _host = host;
            _username = username;
            _password = password;
            _isConnected = false;
        }

        /// <summary>
        /// Check if SSH connection is active
        /// </summary>
        public bool IsConnected => _isConnected && _client != null && _client.IsConnected;

        /// <summary>
        /// Establish SSH connection to remote host
        /// </summary>
        /// <returns>True if connection successful, false otherwise</returns>
        public async Task<bool> ConnectAsync()
        {
            try
            {
                Log.Debug("Attempting SSH connection to {Host} as {User}", _host, _username);

                // Create SSH client with timeout
                _client = new SshClient(_host, _username, _password)
                {
                    ConnectionInfo = 
                    {
                        Timeout = TimeSpan.FromSeconds(10)
                    }
                };

                // Connect (blocking operation, run in Task)
                await Task.Run(() => _client.Connect());

                _isConnected = true;
                Log.Information("SSH connection successful: {User}@{Host}", _username, _host);
                
                return true;
            }
            catch (Renci.SshNet.Common.SshAuthenticationException ex)
            {
                Log.Error("SSH authentication failed for {User}@{Host}: {Error}", 
                    _username, _host, ex.Message);
                return false;
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                Log.Error("SSH connection failed to {Host} (network error): {Error}", 
                    _host, ex.Message);
                return false;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "SSH connection failed to {Host}", _host);
                return false;
            }
        }

        /// <summary>
        /// Execute a shell command on the remote system via SSH
        /// </summary>
        /// <param name="command">Command to execute (e.g., "cat /etc/ssh/sshd_config")</param>
        /// <returns>Command output (stdout)</returns>
        /// <exception cref="InvalidOperationException">If SSH not connected</exception>
        public async Task<string> ExecuteCommandAsync(string command)
        {
            if (!IsConnected)
            {
                throw new InvalidOperationException("SSH connection not established");
            }

            try
            {
                // Log.Debug("Executing SSH command: {Command}", command);

                // Create and execute command
                var cmd = _client!.CreateCommand(command);
                var result = await Task.Run(() => cmd.Execute());

                // Check exit status
                if (cmd.ExitStatus != 0)
                {
                    //Log.Warning("SSH command '{Command}' failed with exit code {Code}", command, cmd.ExitStatus);
                    
                    if (!string.IsNullOrEmpty(cmd.Error))
                    {
                        Log.Debug("SSH command stderr: {Error}", cmd.Error.Trim());
                    }
                }

                return result.Trim();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to execute SSH command: {Command}", command);
                throw;
            }
        }

        /// <summary>
        /// Detect the operating system of the remote host via SSH.
        /// Tries multiple detection methods for cross-platform compatibility.
        /// </summary>
        /// <returns>"Linux", "Windows", or "Unknown"</returns>
        public async Task<string> DetectPlatformAsync()
        {
            if (!IsConnected)
            {
                Log.Warning("Cannot detect platform: SSH not connected");
                return "Unknown";
            }

            try
            {
                // ============================================================================
                // METHOD 1: Try 'uname -s' (Linux/Unix/macOS)
                // ============================================================================
                var unameOutput = await ExecuteCommandAsync("uname -s 2>/dev/null");
                
                if (!string.IsNullOrWhiteSpace(unameOutput))
                {
                    var platform = unameOutput.Trim().ToLowerInvariant();
                    
                    if (platform.Contains("linux"))
                    {
                        Log.Information("Remote platform detected via 'uname -s': Linux");
                        return "Linux";
                    }
                    else if (platform.Contains("darwin"))
                    {
                        Log.Information("Remote platform detected via 'uname -s': macOS (Darwin)");
                        return "macOS";
                    }
                    else if (platform.Contains("freebsd") || platform.Contains("openbsd") || platform.Contains("netbsd"))
                    {
                        Log.Information("Remote platform detected via 'uname -s': BSD");
                        return "BSD";
                    }
                }

                // ============================================================================
                // METHOD 2: Try 'ver' (Windows Command Prompt)
                // ============================================================================
                var verOutput = await ExecuteCommandAsync("ver 2>nul");
                
                if (!string.IsNullOrWhiteSpace(verOutput) && 
                    (verOutput.Contains("Windows") || verOutput.Contains("Microsoft")))
                {
                    Log.Information("Remote platform detected via 'ver': Windows");
                    return "Windows";
                }

                // ============================================================================
                // METHOD 3: Try PowerShell $PSVersionTable (Windows PowerShell)
                // ============================================================================
                var psOutput = await ExecuteCommandAsync("powershell -Command \"$PSVersionTable.PSVersion.Major\" 2>nul");
                
                if (!string.IsNullOrWhiteSpace(psOutput) && int.TryParse(psOutput.Trim(), out _))
                {
                    Log.Information("Remote platform detected via PowerShell: Windows");
                    return "Windows";
                }

                // ============================================================================
                // METHOD 4: Try 'wmic' (Windows Management Instrumentation)
                // ============================================================================
                var wmicOutput = await ExecuteCommandAsync("wmic os get caption 2>nul");
                
                if (!string.IsNullOrWhiteSpace(wmicOutput) && wmicOutput.Contains("Windows"))
                {
                    Log.Information("Remote platform detected via 'wmic': Windows");
                    return "Windows";
                }

                // ============================================================================
                // METHOD 5: Try environment variable check (cross-platform)
                // ============================================================================
                // Check for OS environment variable (Windows has OS=Windows_NT)
                var osEnvOutput = await ExecuteCommandAsync("echo %OS% 2>nul");
                
                if (!string.IsNullOrWhiteSpace(osEnvOutput) && osEnvOutput.Contains("Windows"))
                {
                    Log.Information("Remote platform detected via %%OS%% variable: Windows");
                    return "Windows";
                }

                // ============================================================================
                // FALLBACK: Unable to detect
                // ============================================================================
                Log.Warning("Unable to detect remote platform via SSH (uname failed or returned: '{Output}')", unameOutput);
                return "Unknown";
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error detecting remote platform via SSH");
                return "Unknown";
            }
        }

        /// <summary>
        /// Check if a file exists on the remote system
        /// </summary>
        /// <param name="path">File path to check</param>
        /// <returns>True if file exists, false otherwise</returns>
        public async Task<bool> FileExistsAsync(string path)
        {
            try
            {
                var result = await ExecuteCommandAsync($"test -f '{path}' && echo 'exists'");
                return result.Trim().Equals("exists", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Read contents of a remote file
        /// </summary>
        /// <param name="path">File path to read</param>
        /// <returns>File contents, or empty string if file doesn't exist</returns>
        public async Task<string> ReadFileAsync(string path)
        {
            try
            {
                var result = await ExecuteCommandAsync($"cat '{path}' 2>/dev/null");
                return result;
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to read remote file: {Path}", path);
                return string.Empty;
            }
        }

        /// <summary>
        /// Clean up SSH connection
        /// </summary>
        public void Dispose()
        {
            try
            {
                if (_client != null && _client.IsConnected)
                {
                    Log.Debug("Disconnecting SSH from {Host}", _host);
                    _client.Disconnect();
                }
                _client?.Dispose();
                _isConnected = false;
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Error during SSH disconnect");
            }
        }
    }
}