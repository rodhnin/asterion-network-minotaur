using System.Collections.Generic;
using System.Threading.Tasks;
using Asterion.Core;
using Asterion.Models;

namespace Asterion.Checks
{
    /// <summary>
    /// Interface for all security checks.
    /// Each check implements this interface and is registered in Orchestrator.
    /// 
    /// Checks are categorized by platform compatibility:
    /// - CrossPlatform: Works from any OS, scans network services remotely
    /// - Windows: Requires Windows OS, audits local system
    /// - Linux: Requires Linux OS, audits local system
    /// </summary>
    public interface ICheck
    {
        /// <summary>
        /// Human-readable name of the check (for logging and reporting)
        /// Example: "SMB Security Scanner", "RDP Configuration Check"
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Check category determines when/where the check can run
        /// </summary>
        CheckCategory Category { get; }

        /// <summary>
        /// Brief description of what this check detects
        /// Used in verbose output and documentation generation
        /// Example: "Detects anonymous SMB share access and SMBv1 usage"
        /// </summary>
        string Description { get; }

        /// <summary>
        /// Indicates if this check requires authenticated credentials
        /// Used to skip checks when credentials are not provided
        /// </summary>
        bool RequiresAuthentication { get; }

        /// <summary>
        /// Indicates if this check should only run in aggressive mode
        /// Safe mode checks are non-intrusive (port scanning, banner grabbing)
        /// Aggressive checks may generate noise (WMI queries, authenticated enumeration)
        /// </summary>
        bool RequiresAggressiveMode { get; }

        /// <summary>
        /// Validate if this check can run in the current environment.
        /// Checks platform compatibility, required tools, permissions, etc.
        /// </summary>
        /// <returns>True if check can run, false otherwise</returns>
        bool CanExecute();

        /// <summary>
        /// Execute the security check against one or more targets.
        /// </summary>
        /// <param name="targets">List of targets to scan (IPs, hostnames, or domains)</param>
        /// <param name="options">Scan options containing mode, credentials, rate limits, etc.</param>
        /// <returns>List of findings discovered (empty list if none)</returns>
        Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options);
    }
}