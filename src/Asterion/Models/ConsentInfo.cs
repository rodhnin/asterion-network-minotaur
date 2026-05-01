using System.Text.Json.Serialization;

namespace Asterion.Models
{
    /// <summary>
    /// Ownership verification details (required for aggressive/AI mode)
    /// </summary>
    public class ConsentInfo
    {
        /// <summary>
        /// Verification method used: http, dns, or ssh
        /// </summary>
        [JsonPropertyName("method")]
        public string Method { get; set; } = string.Empty;

        /// <summary>
        /// Consent token (format: verify-{16 hex chars})
        /// </summary>
        [JsonPropertyName("token")]
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// Verification timestamp (ISO 8601 UTC)
        /// </summary>
        [JsonPropertyName("verified_at")]
        public string VerifiedAt { get; set; } = string.Empty;

        /// <summary>
        /// Create consent info from verification
        /// </summary>
        public static ConsentInfo Create(string method, string token, string verifiedAt)
        {
            return new ConsentInfo
            {
                Method = method,
                Token = token,
                VerifiedAt = verifiedAt
            };
        }
    }
}