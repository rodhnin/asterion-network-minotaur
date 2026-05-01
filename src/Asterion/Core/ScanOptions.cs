using System.Collections.Generic;
using Asterion.Core.Utils;

namespace Asterion.Core
{
    /// <summary>
    /// Options for configuring a security scan
    /// </summary>
    public class ScanOptions
    {
        public required string Target { get; set; }
        public required string Mode { get; set; }
        public required string OutputFormat { get; set; }
        public string[]? Ports { get; set; }
        public string? AuthCredentials { get; set; }
        public string? AuthNtlm { get; set; }
        public string? KerberosCredentials { get; set; }
        public string? SshCredentials { get; set; }

        /// <summary>
        /// SSH key credentials (format: user:~/.ssh/id_rsa or user:~/.ssh/id_rsa:passphrase).
        /// When set, key-based auth is used instead of password auth.
        /// </summary>
        public string? SshKeyCredentials { get; set; }

        /// <summary>
        /// Sudo password for privilege elevation on remote Linux hosts.
        /// When set, ExecuteWithSudoAsync() prepends echo 'PASS' | sudo -S.
        /// </summary>
        public string? SshSudoPassword { get; set; }

        /// <summary>
        /// Bastion/jump host (format: bastionhost:user:password or bastionhost:user:~/.ssh/key).
        /// When set, SSH connection to target is tunnelled through this host.
        /// </summary>
        public string? BastionHost { get; set; }

        /// <summary>
        /// WinRM credentials for remote Windows auditing (format: "DOMAIN\user:password" or "user:password").
        /// When set, Windows checks (firewall, registry, services, privesc) run remotely via WS-Man/PowerShell
        /// instead of requiring Asterion to run locally on the target Windows host.
        /// WinRM must be enabled on the target: Enable-PSRemoting -Force
        /// </summary>
        public string? WinRmCredentials { get; set; }
        public int MaxThreads { get; set; } = 5;
        public double RateLimit { get; set; } = 5.0;
        public int TimeoutSeconds { get; set; } = 10;
        public bool VerifySsl { get; set; } = true;
        public bool UseAi { get; set; } = false;
        public string AiTone { get; set; } = "technical";
        public string? AiProvider { get; set; }
        public string? AiModel { get; set; }
        public double AiBudget { get; set; } = 0.0;
        public bool AiStream { get; set; } = false;
        public bool AiAgent { get; set; } = false;
        public string? AiCompare { get; set; }
        public bool Verbose { get; set; } = false;

        /// <summary>
        /// Diff reference: "last" for previous scan of same target, or a specific scan_id from the DB.
        /// If null, no diff is computed.
        /// </summary>
        public string? DiffRef { get; set; }

        /// <summary>
        /// Path to a YAML credentials file containing multiple credential sets.
        /// When set, Asterion iterates through each credential set and merges findings.
        /// Format: see docker/.env.example for structure.
        /// </summary>
        public string? CredsFile { get; set; }

        /// <summary>
        /// Per-target OS detection results populated by OsDetector before check dispatch.
        /// Key: target hostname/IP. Value: detected OS enum.
        /// Checks can read this to skip irrelevant logic without probing again.
        /// </summary>
        public Dictionary<string, OsDetector.TargetOS> TargetOsMap { get; set; } = new();
    }
}