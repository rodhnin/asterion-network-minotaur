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
        public int MaxThreads { get; set; } = 5;
        public double RateLimit { get; set; } = 5.0;
        public int TimeoutSeconds { get; set; } = 10;
        public bool VerifySsl { get; set; } = true;
        public bool UseAi { get; set; } = false;
        public string AiTone { get; set; } = "technical";
        public bool Verbose { get; set; } = false;
    }
}