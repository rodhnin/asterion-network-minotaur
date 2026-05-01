using System.Text.Json;
using System.Text.Json.Serialization;

namespace Asterion.Models
{
    /// <summary>
    /// AI-generated summaries and remediation guidance.
    /// Only present if --use-ai was enabled.
    /// </summary>
    public class AiAnalysis
    {
        /// <summary>
        /// Non-technical summary for stakeholders (markdown format)
        /// </summary>
        [JsonPropertyName("executiveSummary")]
        public string? ExecutiveSummary { get; set; }

        /// <summary>
        /// Step-by-step technical guidance for engineers (markdown format)
        /// </summary>
        [JsonPropertyName("technicalRemediation")]
        public string? TechnicalRemediation { get; set; }

        /// <summary>
        /// AI generation timestamp (ISO 8601 UTC)
        /// </summary>
        [JsonPropertyName("generatedAt")]
        public string GeneratedAt { get; set; } = string.Empty;

        /// <summary>
        /// AI model identifier (e.g., "gpt-4o-mini-2024-07-18", "claude-3-5-haiku-20241022")
        /// </summary>
        [JsonPropertyName("modelUsed")]
        public string ModelUsed { get; set; } = string.Empty;

        /// <summary>
        /// Tone used for analysis (technical, non_technical, both, agent, compare)
        /// </summary>
        [JsonPropertyName("tone")]
        public string Tone { get; set; } = string.Empty;

        /// <summary>
        /// Agent mode analysis with CVE enrichment (IMPROV-008)
        /// </summary>
        [JsonPropertyName("agentAnalysis")]
        public string? AgentAnalysis { get; set; }

        /// <summary>
        /// Multi-provider comparison results (IMPROV-007)
        /// </summary>
        [JsonPropertyName("compareResults")]
        public JsonElement? CompareResults { get; set; }

        /// <summary>
        /// Token usage and cost for this AI call (IMPROV-005)
        /// </summary>
        [JsonPropertyName("cost")]
        public AiCostInfo? Cost { get; set; }

        /// <summary>
        /// Create AI analysis with summaries
        /// </summary>
        public static AiAnalysis Create(
            string executiveSummary,
            string technicalRemediation,
            string modelUsed,
            string tone)
        {
            return new AiAnalysis
            {
                ExecutiveSummary = executiveSummary,
                TechnicalRemediation = technicalRemediation,
                GeneratedAt = System.DateTime.UtcNow.ToString("o").Replace("+00:00", "Z"),
                ModelUsed = modelUsed,
                Tone = tone
            };
        }
    }

    /// <summary>
    /// Token usage and USD cost for one AI analysis call (IMPROV-005)
    /// </summary>
    public class AiCostInfo
    {
        [JsonPropertyName("total_usd")]
        public double TotalUsd { get; set; }

        [JsonPropertyName("provider")]
        public string Provider { get; set; } = string.Empty;

        [JsonPropertyName("model")]
        public string Model { get; set; } = string.Empty;

        [JsonPropertyName("breakdown")]
        public JsonElement? Breakdown { get; set; }
    }
}