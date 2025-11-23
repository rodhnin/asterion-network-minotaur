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
        /// AI model identifier (e.g., "gpt-4-turbo-preview", "claude-sonnet-4")
        /// </summary>
        [JsonPropertyName("modelUsed")]
        public string ModelUsed { get; set; } = string.Empty;
        
        /// <summary>
        /// Tone used for analysis (technical or non_technical)
        /// </summary>
        [JsonPropertyName("tone")]
        public string Tone { get; set; } = string.Empty;
        
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
}