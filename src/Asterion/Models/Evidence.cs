using System.Text.Json.Serialization;

namespace Asterion.Models
{
    /// <summary>
    /// Evidence supporting a security finding.
    /// Types: url, header, body, path, screenshot, other
    /// </summary>
    public class Evidence
    {
        /// <summary>
        /// Type of evidence collected
        /// </summary>
        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        /// <summary>
        /// Evidence content (sanitized, no secrets)
        /// </summary>
        [JsonPropertyName("value")]
        public string Value { get; set; } = string.Empty;

        /// <summary>
        /// Additional context (e.g., HTTP status code, response time)
        /// </summary>
        [JsonPropertyName("context")]
        public string? Context { get; set; }

        /// <summary>
        /// Create evidence from common patterns
        /// </summary>
        public static Evidence FromUrl(string url, string? context = null)
        {
            return new Evidence
            {
                Type = "url",
                Value = url,
                Context = context
            };
        }

        public static Evidence FromHeader(string header, string? context = null)
        {
            return new Evidence
            {
                Type = "header",
                Value = header,
                Context = context
            };
        }

        public static Evidence FromPath(string path, string? context = null)
        {
            return new Evidence
            {
                Type = "path",
                Value = path,
                Context = context
            };
        }

        public static Evidence FromService(string service, string? context = null)
        {
            return new Evidence
            {
                Type = "other",
                Value = service,
                Context = context
            };
        }
    }
}