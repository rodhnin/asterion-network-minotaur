using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Asterion.Models
{
    /// <summary>
    /// A single compliance control reference (one framework entry).
    /// </summary>
    public class ComplianceControl
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;   // e.g. "CIS-4"

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty; // e.g. "Secure Configuration..."
    }

    /// <summary>
    /// Compliance framework mappings for a finding — CIS Controls v8, NIST CSF 2.0, PCI-DSS 4.0.
    /// Populated by compliance.py enrichment during AI analysis.
    /// </summary>
    public class ComplianceMapping
    {
        [JsonPropertyName("cis")]
        public ComplianceControl? Cis { get; set; }

        [JsonPropertyName("nist")]
        public ComplianceControl? Nist { get; set; }

        [JsonPropertyName("pci")]
        public ComplianceControl? Pci { get; set; }
    }

    /// <summary>
    /// OWASP Top 10 2021 category reference for a finding.
    /// </summary>
    public class OWASPCategory
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;   // e.g. "A05"

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty; // e.g. "Security Misconfiguration"
    }

    /// <summary>
    /// A CVE record linked to a finding — populated by cve_lookup.py enrichment.
    /// </summary>
    public class Vulnerability
    {
        [JsonPropertyName("cve_id")]
        public string CveId { get; set; } = string.Empty;

        [JsonPropertyName("title")]
        public string Title { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [JsonPropertyName("link")]
        public string? Link { get; set; }

        [JsonPropertyName("cvss_score")]
        public double? CvssScore { get; set; }

        [JsonPropertyName("cvss_severity")]
        public string? CvssSeverity { get; set; }

        [JsonPropertyName("cwe_id")]
        public string? CweId { get; set; }

        [JsonPropertyName("cwe_name")]
        public string? CweName { get; set; }

        [JsonPropertyName("published")]
        public string? Published { get; set; }
    }

    /// <summary>
    /// Represents a security finding/vulnerability detected during a scan.
    /// Follows the Argos Suite report schema.
    /// </summary>
    public class Finding
    {
        /// <summary>
        /// Unique finding identifier (e.g., "AST-SMB-001")
        /// Pattern: ^[A-Z]+-[A-Z]+-\\d{3}$
        /// </summary>
        public string Id { get; set; } = string.Empty;

        /// <summary>
        /// Short, descriptive title of the finding (max 200 chars)
        /// </summary>
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// Detailed explanation of the vulnerability or issue
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// Severity rating: critical, high, medium, low, info
        /// </summary>
        public string Severity { get; set; } = string.Empty;

        /// <summary>
        /// Confidence level: high (confirmed), medium, low (heuristic)
        /// </summary>
        public string Confidence { get; set; } = string.Empty;

        /// <summary>
        /// Proof of the finding (URL, header, file path, etc.)
        /// </summary>
        public Evidence? Evidence { get; set; }

        /// <summary>
        /// Actionable remediation guidance
        /// </summary>
        public string Recommendation { get; set; } = string.Empty;

        /// <summary>
        /// External references (CVE, OWASP, vendor docs)
        /// </summary>
        public List<string>? References { get; set; }

        /// <summary>
        /// Related CVE identifiers (pattern: ^CVE-\\d{4}-\\d{4,}$)
        /// </summary>
        public List<string>? Cve { get; set; }

        /// <summary>
        /// Specific component affected (e.g., plugin name, file path, host)
        /// </summary>
        public string? AffectedComponent { get; set; }

        /// <summary>
        /// OWASP Top 10 2021 category — populated by owasp.py enrichment.
        /// </summary>
        [JsonPropertyName("owasp")]
        public OWASPCategory? Owasp { get; set; }

        /// <summary>
        /// CVE records from NVD — populated by cve_lookup.py enrichment.
        /// </summary>
        [JsonPropertyName("vulnerabilities")]
        public List<Vulnerability>? Vulnerabilities { get; set; }

        /// <summary>
        /// Highest CVSS score across all linked CVEs — set by cve_lookup.py.
        /// </summary>
        [JsonPropertyName("cvss")]
        public double? Cvss { get; set; }

        /// <summary>
        /// Compliance framework mapping — populated by compliance.py enrichment.
        /// Contains CIS Controls v8, NIST CSF 2.0, and PCI-DSS 4.0 control IDs.
        /// </summary>
        [JsonPropertyName("compliance")]
        public ComplianceMapping? Compliance { get; set; }

        /// <summary>
        /// Create a finding with required fields
        /// </summary>
        public static Finding Create(
            string id,
            string title,
            string severity,
            string confidence,
            string recommendation)
        {
            return new Finding
            {
                Id = id,
                Title = title,
                Severity = severity,
                Confidence = confidence,
                Recommendation = recommendation
            };
        }

        /// <summary>
        /// Fluent API for building findings
        /// </summary>
        public Finding WithDescription(string description)
        {
            Description = description;
            return this;
        }

        public Finding WithEvidence(Evidence evidence)
        {
            Evidence = evidence;
            return this;
        }

        public Finding WithEvidence(string type, string value, string? context = null)
        {
            Evidence = new Evidence
            {
                Type = type,
                Value = value,
                Context = context
            };
            return this;
        }

        public Finding WithReferences(params string[] references)
        {
            References = new List<string>(references);
            return this;
        }

        public Finding WithCve(params string[] cve)
        {
            Cve = new List<string>(cve);
            return this;
        }

        public Finding WithAffectedComponent(string component)
        {
            AffectedComponent = component;
            return this;
        }
    }
}