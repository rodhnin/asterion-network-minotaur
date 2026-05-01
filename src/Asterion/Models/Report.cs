using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Asterion.Models
{
    /// <summary>
    /// Complete security scan report conforming to Argos Suite schema.
    /// </summary>
    public class Report
    {
        /// <summary>
        /// Tool that generated this report: "asterion"
        /// </summary>
        [JsonPropertyName("tool")]
        public string Tool { get; set; } = "asterion";

        /// <summary>
        /// Tool version (semantic versioning, e.g., "0.2.0")
        /// </summary>
        [JsonPropertyName("version")]
        public string Version { get; set; } = string.Empty;

        /// <summary>
        /// Target URL, IP, CIDR range, or domain scanned
        /// </summary>
        [JsonPropertyName("target")]
        public string Target { get; set; } = string.Empty;

        /// <summary>
        /// Scan completion timestamp (ISO 8601 UTC)
        /// </summary>
        [JsonPropertyName("date")]
        public string Date { get; set; } = string.Empty;

        /// <summary>
        /// Scan mode: "safe" (non-intrusive) or "aggressive" (requires consent)
        /// </summary>
        [JsonPropertyName("mode")]
        public string Mode { get; set; } = string.Empty;

        /// <summary>
        /// Count of findings by severity level
        /// </summary>
        [JsonPropertyName("summary")]
        public FindingSummary Summary { get; set; } = new();

        /// <summary>
        /// List of security findings/vulnerabilities detected
        /// </summary>
        [JsonPropertyName("findings")]
        public List<Finding> Findings { get; set; } = new();

        /// <summary>
        /// Additional metadata and scanning context
        /// </summary>
        [JsonPropertyName("notes")]
        public ReportNotes? Notes { get; set; }

        /// <summary>
        /// Ownership verification details (if aggressive mode used)
        /// </summary>
        [JsonPropertyName("consent")]
        public ConsentInfo? Consent { get; set; }

        /// <summary>
        /// AI-generated summaries (if --use-ai enabled)
        /// </summary>
        [JsonPropertyName("aiAnalysis")]
        public AiAnalysis? AiAnalysis { get; set; }

        /// <summary>
        /// Aggregate risk score 0-10 computed from finding severities
        /// </summary>
        [JsonPropertyName("riskScore")]
        public double? RiskScore { get; set; }

        /// <summary>
        /// Human-readable risk label derived from RiskScore
        /// </summary>
        [JsonPropertyName("riskLabel")]
        public string? RiskLabel { get; set; }

        /// <summary>
        /// Diff comparison with a previous scan (if --diff was used)
        /// </summary>
        [JsonPropertyName("diff")]
        public ScanDiff? Diff { get; set; }

        /// <summary>
        /// Correlated attack chains — multi-step attack vectors derived from co-existing findings
        /// </summary>
        [JsonPropertyName("attackChains")]
        public List<AttackChain>? AttackChains { get; set; }
    }

    /// <summary>
    /// A multi-step attack vector formed by the combination of two or more findings
    /// </summary>
    public class AttackChain
    {
        /// <summary>Attack chain identifier (e.g., AST-CHAIN-001)</summary>
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        /// <summary>Short title describing the attack scenario</summary>
        [JsonPropertyName("title")]
        public string Title { get; set; } = string.Empty;

        /// <summary>Narrative description of the chained attack</summary>
        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;

        /// <summary>Overall severity of the chain (critical/high/medium/low)</summary>
        [JsonPropertyName("severity")]
        public string Severity { get; set; } = string.Empty;

        /// <summary>MITRE ATT&amp;CK technique IDs relevant to this chain</summary>
        [JsonPropertyName("mitre")]
        public string Mitre { get; set; } = string.Empty;

        /// <summary>Ordered attack steps as strings</summary>
        [JsonPropertyName("steps")]
        public List<string> Steps { get; set; } = new();

        /// <summary>Finding IDs that compose this chain</summary>
        [JsonPropertyName("findingIds")]
        public List<string> FindingIds { get; set; } = new();

        /// <summary>Consolidated remediation guidance</summary>
        [JsonPropertyName("remediation")]
        public string Remediation { get; set; } = string.Empty;

        /// <summary>True when optional bonus findings are also present, making the chain more severe</summary>
        [JsonPropertyName("enhanced")]
        public bool Enhanced { get; set; }
    }

    /// <summary>
    /// Diff result between the current scan and a reference scan
    /// </summary>
    public class ScanDiff
    {
        [JsonPropertyName("ref_scan_id")]
        public int RefScanId { get; set; }

        [JsonPropertyName("ref_date")]
        public string? RefDate { get; set; }

        [JsonPropertyName("ref_target")]
        public string? RefTarget { get; set; }

        [JsonPropertyName("ref_mode")]
        public string? RefMode { get; set; }

        [JsonPropertyName("current_mode")]
        public string? CurrentMode { get; set; }

        [JsonPropertyName("mode_mismatch")]
        public bool ModeMismatch { get; set; }

        [JsonPropertyName("new")]
        public List<DiffFinding> New { get; set; } = new();

        [JsonPropertyName("fixed")]
        public List<DiffFinding> Fixed { get; set; } = new();

        [JsonPropertyName("persisting")]
        public List<DiffFinding> Persisting { get; set; } = new();
    }

    /// <summary>
    /// Minimal finding representation used in diff output
    /// </summary>
    public class DiffFinding
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("title")]
        public string Title { get; set; } = string.Empty;

        [JsonPropertyName("severity")]
        public string Severity { get; set; } = string.Empty;
    }

    /// <summary>
    /// Summary counts of findings by severity level
    /// </summary>
    public class FindingSummary
    {
        /// <summary>
        /// Immediate action required (e.g., exposed credentials)
        /// </summary>
        [JsonPropertyName("critical")]
        public int Critical { get; set; }

        /// <summary>
        /// Serious vulnerabilities (e.g., known CVE with exploit)
        /// </summary>
        [JsonPropertyName("high")]
        public int High { get; set; }

        /// <summary>
        /// Moderate risk (e.g., version disclosure, weak config)
        /// </summary>
        [JsonPropertyName("medium")]
        public int Medium { get; set; }

        /// <summary>
        /// Minor issues (e.g., missing best practices)
        /// </summary>
        [JsonPropertyName("low")]
        public int Low { get; set; }

        /// <summary>
        /// Informational only (e.g., technology fingerprint)
        /// </summary>
        [JsonPropertyName("info")]
        public int Info { get; set; }

        /// <summary>
        /// Total number of findings
        /// </summary>
        [JsonIgnore]
        public int Total => Critical + High + Medium + Low + Info;
    }

    /// <summary>
    /// Additional scan metadata
    /// </summary>
    public class ReportNotes
    {
        /// <summary>
        /// Total scan duration in seconds
        /// </summary>
        [JsonPropertyName("scan_duration_seconds")]
        public double ScanDurationSeconds { get; set; }

        /// <summary>
        /// Number of network requests/checks performed
        /// </summary>
        [JsonPropertyName("requests_sent")]
        public int RequestsSent { get; set; }

        /// <summary>
        /// Whether rate limiting was applied
        /// </summary>
        [JsonPropertyName("rate_limit_applied")]
        public bool RateLimitApplied { get; set; }

        /// <summary>
        /// Any scope restrictions or assumptions made
        /// </summary>
        [JsonPropertyName("scope_limitations")]
        public string? ScopeLimitations { get; set; }

        /// <summary>
        /// Disclaimer about manual verification
        /// </summary>
        [JsonPropertyName("false_positive_disclaimer")]
        public string FalsePositiveDisclaimer { get; set; } =
            "Manual verification recommended for all findings before remediation.";
    }
}