using System.Collections.Generic;

namespace Asterion.Models
{
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