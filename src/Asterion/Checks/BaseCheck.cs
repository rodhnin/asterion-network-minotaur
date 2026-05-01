using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Models;

namespace Asterion.Checks
{
    /// <summary>
    /// Base class for all security checks.
    /// Provides common functionality and validation logic.
    /// Inherit from this instead of implementing ICheck directly.
    /// </summary>
    public abstract class BaseCheck : ICheck
    {
        protected readonly Config _config;

        // SSH connection manager for remote Linux checks (set by Orchestrator)
        protected SshConnectionManager? SshManager { get; private set; }

        // WinRM connection manager for remote Windows checks (set by Orchestrator)
        protected WinRmConnectionManager? WinRmManager { get; private set; }

        // Abstract properties - must be implemented by derived classes
        public abstract string Name { get; }
        public abstract CheckCategory Category { get; }
        public abstract string Description { get; }

        // Virtual properties - can be overridden if needed
        public virtual bool RequiresAuthentication => false;
        public virtual bool RequiresAggressiveMode => false;

        /// <summary>
        /// Constructor - all checks must receive Config
        /// </summary>
        protected BaseCheck(Config config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        /// <summary>
        /// Set SSH connection manager for remote Linux checks.
        /// Called by Orchestrator before executing Linux checks via SSH.
        /// </summary>
        public void SetSshManager(SshConnectionManager? sshManager)
        {
            SshManager = sshManager;
        }

        /// <summary>
        /// Set WinRM connection manager for remote Windows checks.
        /// Called by Orchestrator before executing Windows checks via WinRM.
        /// When set, Windows checks run PowerShell remotely instead of using local Windows APIs.
        /// </summary>
        public void SetWinRmManager(WinRmConnectionManager? winRmManager)
        {
            WinRmManager = winRmManager;
        }

        /// <summary>
        /// Validate platform compatibility and prerequisites.
        /// Override this method if additional validation is needed.
        /// </summary>
        public virtual bool CanExecute()
        {
            // Check platform compatibility
            switch (Category)
            {
                case CheckCategory.Windows:
                    // Allow Windows checks when:
                    //   a) Running locally on Windows, OR
                    //   b) WinRM manager is connected (remote execution via PowerShell)
                    if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) &&
                        (WinRmManager == null || !WinRmManager.IsConnected))
                    {
                        Log.Debug("{CheckName} skipped: Requires Windows or WinRM connection", Name);
                        return false;
                    }
                    break;

                case CheckCategory.Linux:
                    // Linux checks can run locally OR remotely via SSH
                    break;

                case CheckCategory.CrossPlatform:
                    // Always can execute
                    break;
            }

            return true;
        }

        /// <summary>
        /// Main execution method - must be implemented by derived classes
        /// </summary>
        public abstract Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options);

        // ============================================================================
        // COMMAND EXECUTION HELPERS (Local vs Remote via SSH)
        // ============================================================================

        /// <summary>
        /// Execute a command either locally or remotely via SSH.
        /// Automatically detects execution mode based on SshManager availability.
        /// </summary>
        /// <param name="command">Command to execute (e.g., "uname", "cat")</param>
        /// <param name="arguments">Command arguments (e.g., "-a", "/etc/hosts")</param>
        /// <returns>Tuple of (success, output)</returns>
        protected async Task<(bool success, string output)> ExecuteCommandAsync(string command, string arguments = "")
        {
            if (SshManager != null && SshManager.IsConnected)
            {
                // Remote execution via SSH
                return await ExecuteRemoteCommandAsync(command, arguments);
            }
            else
            {
                // Local execution via Process.Start
                return await ExecuteLocalCommandAsync(command, arguments);
            }
        }

        /// <summary>
        /// Read a file either locally or remotely via SSH.
        /// </summary>
        /// <param name="filePath">Absolute path to file</param>
        /// <returns>File contents, or empty string if file doesn't exist</returns>
        protected async Task<string> ReadFileAsync(string filePath)
        {
            if (SshManager != null && SshManager.IsConnected)
            {
                // Remote file read via SSH
                return await SshManager.ReadFileAsync(filePath);
            }
            else
            {
                // Local file read
                try
                {
                    if (System.IO.File.Exists(filePath))
                    {
                        return await System.IO.File.ReadAllTextAsync(filePath);
                    }
                    return string.Empty;
                }
                catch (Exception ex)
                {
                    Log.Debug("[{CheckName}] Failed to read local file: {Path} - {Error}", 
                    Name, filePath, ex.Message);
                    return string.Empty;
                }
            }
        }

        /// <summary>
        /// Check if a file exists either locally or remotely via SSH.
        /// </summary>
        /// <param name="filePath">Absolute path to file</param>
        /// <returns>True if file exists</returns>
        protected async Task<bool> FileExistsAsync(string filePath)
        {
            if (SshManager != null && SshManager.IsConnected)
            {
                // Remote file check via SSH
                return await SshManager.FileExistsAsync(filePath);
            }
            else
            {
                // Local file check
                return System.IO.File.Exists(filePath);
            }
        }

        /// <summary>
        /// Check if a command exists (via 'which' command)
        /// </summary>
        /// <param name="command">Command name (e.g., "iptables", "ufw")</param>
        /// <returns>True if command exists</returns>
        protected async Task<bool> CommandExistsAsync(string command)
        {
            var (success, _) = await ExecuteCommandAsync("which", command);
            return success;
        }

        /// <summary>
        /// Check if running as root (UID 0)
        /// </summary>
        /// <returns>True if root/administrator</returns>
        protected async Task<bool> IsRootAsync()
        {
            var (success, output) = await ExecuteCommandAsync("id", "-u");
            return success && output.Trim() == "0";
        }

        // ============================================================================
        // PRIVATE EXECUTION METHODS
        // ============================================================================

        /// <summary>
        /// Execute command locally via Process.Start
        /// </summary>
        private async Task<(bool success, string output)> ExecuteLocalCommandAsync(string command, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = command,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) return (false, string.Empty);

                var output = await process.StandardOutput.ReadToEndAsync();
                var error = await process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync();

                // Combine stdout and stderr
                var combinedOutput = output + error;

                return (process.ExitCode == 0, combinedOutput.Trim());
            }
            catch (Exception ex)
            {
                Log.Debug("[{CheckName}] Failed to execute local command: {Command} {Arguments} - {Error}", 
                    Name, command, arguments, ex.Message);
                return (false, string.Empty);
            }
        }

        /// <summary>
        /// Execute command remotely via SSH
        /// </summary>
        private async Task<(bool success, string output)> ExecuteRemoteCommandAsync(string command, string arguments)
        {
            try
            {
                // Combine command and arguments
                var fullCommand = string.IsNullOrEmpty(arguments) 
                    ? command 
                    : $"{command} {arguments}";

                // Execute via SSH manager
                var output = await SshManager!.ExecuteCommandAsync(fullCommand);

                // SSH.NET doesn't provide exit code directly in ExecuteCommandAsync
                // We assume success if no exception was thrown
                return (true, output.Trim());
            }
            catch (Exception ex)
            {
                Log.Debug("[{CheckName}] Failed to execute remote command via SSH: {Command} {Arguments} - {Error}", 
                    Name, command, arguments, ex.Message);
                return (false, string.Empty);
            }
        }

        // ============================================================================
        // EXISTING HELPER METHODS (unchanged)
        // ============================================================================

        /// <summary>
        /// Helper: Create a finding with common defaults
        /// </summary>
        protected Finding CreateFinding(
            string id,
            string title,
            string severity,
            string recommendation,
            string? description = null,
            Evidence? evidence = null,
            string? affectedComponent = null,
            string confidence = "high")
        {
            return new Finding
            {
                Id = id,
                Title = title,
                Severity = severity,
                Confidence = confidence,
                Recommendation = recommendation,
                Description = description,
                Evidence = evidence,
                AffectedComponent = affectedComponent
            };
        }

        /// <summary>
        /// Helper: Validate if check should run based on scan mode
        /// Call this at the start of ExecuteAsync()
        /// </summary>
        protected bool ShouldExecute(ScanOptions options)
        {
            // Skip if aggressive mode required but not enabled
            if (RequiresAggressiveMode && options.Mode.ToLower() != "aggressive")
            {
                Log.Debug("{CheckName} skipped: Requires aggressive mode", Name);
                return false;
            }

            // Skip if authentication required but not provided
            if (RequiresAuthentication && 
                string.IsNullOrEmpty(options.AuthCredentials) &&
                string.IsNullOrEmpty(options.AuthNtlm) &&
                string.IsNullOrEmpty(options.KerberosCredentials))
            {
                Log.Debug("{CheckName} skipped: Requires authentication", Name);
                return false;
            }

            return true;
        }

        /// <summary>
        /// Helper: Log check execution results
        /// Call this at the end of ExecuteAsync()
        /// </summary>
        protected void LogExecution(int targetCount, int findingsCount)
        {
            if (findingsCount > 0)
            {
                Log.Information("{CheckName}: Found {Count} issue(s) across {Targets} target(s)", 
                    Name, findingsCount, targetCount);
            }
            else
            {
                Log.Debug("{CheckName}: No issues found across {Targets} target(s)", 
                    Name, targetCount);
            }
        }

        /// <summary>
        /// Helper: Parse credentials from string
        /// Format: "user:pass" or "DOMAIN\\user:pass"
        /// </summary>
        protected (string? username, string? password, string? domain) ParseCredentials(string? credentials)
        {
            if (string.IsNullOrEmpty(credentials))
                return (null, null, null);

            var parts = credentials.Split(':', 2);
            if (parts.Length != 2)
                return (null, null, null);

            var userPart = parts[0];
            var password = parts[1];

            // Check for domain
            if (userPart.Contains("\\"))
            {
                var domainUser = userPart.Split('\\', 2);
                return (domainUser[1], password, domainUser[0]);
            }

            return (userPart, password, null);
        }
    }
}