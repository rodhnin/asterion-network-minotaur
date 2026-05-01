using System;
using System.IO;
using System.Threading.Tasks;
using Renci.SshNet;
using Serilog;

namespace Asterion.Core
{
    /// <summary>
    /// Manages SSH connections to remote for authenticated auditing.
    /// Supports password auth, key auth, sudo elevation, and bastion/jump hosts.
    /// </summary>
    public class SshConnectionManager : IDisposable
    {
        private readonly string _host;
        private readonly string _username;

        // Password auth
        private readonly string? _password;

        // Key auth
        private readonly string? _privateKeyPath;
        private readonly string? _passphrase;
        private readonly bool _useKeyAuth;

        // Sudo
        private readonly string? _sudoPassword;

        // Bastion
        private SshClient? _bastionClient;
        private ForwardedPortLocal? _forwardedPort;

        private SshClient? _client;
        private bool _isConnected;

        /// <summary>Password-based SSH connection.</summary>
        public SshConnectionManager(string host, string username, string password, string? sudoPassword = null)
        {
            _host = host;
            _username = username;
            _password = password;
            _sudoPassword = sudoPassword;
            _useKeyAuth = false;
            _isConnected = false;
        }

        /// <summary>Private constructor for key-auth and bastion factory methods.</summary>
        private SshConnectionManager(string host, string username, string privateKeyPath, string? passphrase,
            bool useKeyAuth, string? sudoPassword = null)
        {
            _host = host;
            _username = username;
            _privateKeyPath = privateKeyPath;
            _passphrase = passphrase;
            _useKeyAuth = useKeyAuth;
            _sudoPassword = sudoPassword;
            _isConnected = false;
        }

        /// <summary>
        /// Create an SSH connection manager that authenticates with a private key.
        /// </summary>
        /// <param name="host">Target hostname or IP</param>
        /// <param name="username">SSH username</param>
        /// <param name="privateKeyPath">Path to private key file (PEM/OpenSSH format)</param>
        /// <param name="passphrase">Optional key passphrase</param>
        /// <param name="sudoPassword">Optional sudo password for privilege elevation</param>
        public static SshConnectionManager CreateWithKeyAuth(
            string host, string username, string privateKeyPath,
            string? passphrase = null, string? sudoPassword = null)
        {
            return new SshConnectionManager(host, username, privateKeyPath, passphrase,
                useKeyAuth: true, sudoPassword: sudoPassword);
        }

        /// <summary>
        /// Create an SSH manager that tunnels through a bastion/jump host.
        /// The tunnel is established synchronously when ConnectAsync() is called.
        /// </summary>
        /// <param name="bastionHost">Bastion hostname or IP</param>
        /// <param name="bastionUsername">Bastion SSH username</param>
        /// <param name="bastionPassword">Bastion SSH password (use key overload for key auth)</param>
        /// <param name="targetHost">Final target hostname or IP</param>
        /// <param name="targetUsername">Target SSH username</param>
        /// <param name="targetPassword">Target SSH password</param>
        /// <param name="targetPort">Target SSH port (default: 22)</param>
        /// <param name="sudoPassword">Optional sudo password for privilege elevation on target</param>
        public static SshConnectionManager CreateViaBastion(
            string bastionHost, string bastionUsername, string bastionPassword,
            string targetHost, string targetUsername, string targetPassword,
            int targetPort = 22, string? sudoPassword = null)
        {
            // The manager's _host/_username/_password refer to the FINAL target.
            // The bastion details are stored separately for the tunnel.
            var mgr = new SshConnectionManager(targetHost, targetUsername, targetPassword, sudoPassword);
            mgr._pendingBastionHost     = bastionHost;
            mgr._pendingBastionUser     = bastionUsername;
            mgr._pendingBastionPassword = bastionPassword;
            mgr._pendingTargetPort      = targetPort;
            return mgr;
        }

        // Bastion pending params (set by factory, consumed in ConnectAsync)
        private string? _pendingBastionHost;
        private string? _pendingBastionUser;
        private string? _pendingBastionPassword;
        private int _pendingTargetPort = 22;

        /// <summary>
        /// Check if SSH connection is active
        /// </summary>
        public bool IsConnected => _isConnected && _client != null && _client.IsConnected;

        /// <summary>
        /// Establish SSH connection to remote host (password, key, or via bastion tunnel).
        /// </summary>
        /// <returns>True if connection successful, false otherwise</returns>
        public async Task<bool> ConnectAsync()
        {
            try
            {
                // ── Bastion tunnel setup ──────────────────────────────────────────
                if (_pendingBastionHost != null)
                {
                    Log.Debug("[SSH] Setting up bastion tunnel: {Bastion} → {Target}", _pendingBastionHost, _host);

                    _bastionClient = new SshClient(_pendingBastionHost, _pendingBastionUser, _pendingBastionPassword)
                    {
                        ConnectionInfo = { Timeout = TimeSpan.FromSeconds(15) }
                    };
                    await Task.Run(() => _bastionClient.Connect());

                    if (!_bastionClient.IsConnected)
                    {
                        Log.Error("[SSH] Bastion connection failed to {Bastion}", _pendingBastionHost);
                        return false;
                    }
                    Log.Debug("[SSH] Bastion connected: {Bastion}", _pendingBastionHost);

                    // Forward a random local port to target:targetPort through the bastion
                    _forwardedPort = new ForwardedPortLocal("127.0.0.1", 0, _host, (uint)_pendingTargetPort);
                    _bastionClient.AddForwardedPort(_forwardedPort);
                    _forwardedPort.Start();

                    // Build connection through the tunnel (127.0.0.1 : bound local port)
                    int localPort = (int)_forwardedPort.BoundPort;
                    Log.Debug("[SSH] Tunnel opened 127.0.0.1:{LocalPort} → {Target}:{TargetPort}", localPort, _host, _pendingTargetPort);

                    var connInfo = new ConnectionInfo("127.0.0.1", localPort, _username,
                        new PasswordAuthenticationMethod(_username, _password))
                    {
                        Timeout = TimeSpan.FromSeconds(15)
                    };
                    _client = new SshClient(connInfo);
                }
                // ── Key-based auth ────────────────────────────────────────────────
                else if (_useKeyAuth && _privateKeyPath != null)
                {
                    Log.Debug("[SSH] Key auth: {User}@{Host} key={Key}", _username, _host, _privateKeyPath);

                    var expandedPath = _privateKeyPath.Replace("~", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                    PrivateKeyFile keyFile = string.IsNullOrEmpty(_passphrase)
                        ? new PrivateKeyFile(expandedPath)
                        : new PrivateKeyFile(expandedPath, _passphrase);

                    var authMethod = new PrivateKeyAuthenticationMethod(_username, keyFile);
                    var connInfo = new ConnectionInfo(_host, _username, authMethod)
                    {
                        Timeout = TimeSpan.FromSeconds(10)
                    };
                    _client = new SshClient(connInfo);
                }
                // ── Password auth (default) ───────────────────────────────────────
                else
                {
                    Log.Debug("[SSH] Password auth: {User}@{Host}", _username, _host);
                    _client = new SshClient(_host, _username, _password)
                    {
                        ConnectionInfo = { Timeout = TimeSpan.FromSeconds(10) }
                    };
                }

                await Task.Run(() => _client!.Connect());
                _isConnected = true;

                var authDesc = _useKeyAuth ? "key" : _pendingBastionHost != null ? "bastion" : "password";
                Log.Information("[SSH] Connected ({Auth}): {User}@{Host}", authDesc, _username, _host);
                return true;
            }
            catch (Renci.SshNet.Common.SshAuthenticationException ex)
            {
                Log.Error("[SSH] Authentication failed for {User}@{Host}: {Error}", _username, _host, ex.Message);
                return false;
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                Log.Error("[SSH] Network error connecting to {Host}: {Error}", _host, ex.Message);
                return false;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[SSH] Connection failed to {Host}", _host);
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
        /// Execute a command with sudo privilege elevation on the remote system.
        /// Uses the sudo password supplied at construction / factory time.
        /// Falls back to plain ExecuteCommandAsync if no sudo password is stored.
        /// </summary>
        /// <param name="command">Command to run as root (e.g., "cat /etc/shadow")</param>
        /// <returns>Command output (stdout)</returns>
        public async Task<string> ExecuteWithSudoAsync(string command)
        {
            if (string.IsNullOrEmpty(_sudoPassword))
            {
                // No sudo password — try plain execution
                Log.Debug("[SSH] ExecuteWithSudoAsync: no sudo password stored, running plain: {Cmd}", command);
                return await ExecuteCommandAsync(command);
            }

            // Escape single quotes in password (replace ' with '"'"')
            var escapedPass = _sudoPassword.Replace("'", "'\"'\"'");
            // Pipe password into sudo -S so it never appears in process list as argv
            var sudoCmd = $"echo '{escapedPass}' | sudo -S -p '' {command}";
            return await ExecuteCommandAsync(sudoCmd);
        }

        /// <summary>
        /// Execute a command with sudo using an explicit password (ignores stored sudo password).
        /// </summary>
        public async Task<string> ExecuteWithSudoAsync(string command, string sudoPassword)
        {
            var escapedPass = sudoPassword.Replace("'", "'\"'\"'");
            var sudoCmd = $"echo '{escapedPass}' | sudo -S -p '' {command}";
            return await ExecuteCommandAsync(sudoCmd);
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
        /// Clean up SSH connection (and bastion tunnel if active).
        /// </summary>
        public void Dispose()
        {
            try
            {
                if (_client != null && _client.IsConnected)
                {
                    Log.Debug("[SSH] Disconnecting from {Host}", _host);
                    _client.Disconnect();
                }
                _client?.Dispose();
                _isConnected = false;

                // Tear down bastion tunnel
                if (_forwardedPort != null)
                {
                    _forwardedPort.Stop();
                    _forwardedPort.Dispose();
                }
                if (_bastionClient != null && _bastionClient.IsConnected)
                {
                    Log.Debug("[SSH] Disconnecting bastion tunnel: {Bastion}", _pendingBastionHost);
                    _bastionClient.Disconnect();
                }
                _bastionClient?.Dispose();
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "[SSH] Error during disconnect");
            }
        }
    }
}