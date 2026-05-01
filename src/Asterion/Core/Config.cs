using System;
using System.Collections.Generic;
using System.IO;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Serilog;

namespace Asterion.Core
{
    /// <summary>
    /// Configuration management for Asterion
    /// Loads settings from defaults.yaml (YAML is source of truth)
    /// </summary>
    public class Config
    {
        // General
        public GeneralConfig General { get; set; } = new();
        public PathsConfig Paths { get; set; } = new();
        public ScanConfig Scan { get; set; } = new();
        public NetworkConfig Network { get; set; } = new();
        
        // Protocol-specific
        public SmbConfig Smb { get; set; } = new();
        public RdpConfig Rdp { get; set; } = new();
        public LdapConfig Ldap { get; set; } = new();
        public KerberosConfig Kerberos { get; set; } = new();
        public SnmpConfig Snmp { get; set; } = new();
        public DnsConfig Dns { get; set; } = new();
        public SshConfig Ssh { get; set; } = new();
        public NfsConfig Nfs { get; set; } = new();
        
        // System
        public ConsentConfig Consent { get; set; } = new();
        public ReportingConfig Reporting { get; set; } = new();
        public LoggingConfig Logging { get; set; } = new();
        public AiConfig Ai { get; set; } = new();
        public AdvancedConfig Advanced { get; set; } = new();
        public WindowsConfig Windows { get; set; } = new();
        public LinuxConfig Linux { get; set; } = new();
        public DockerConfig Docker { get; set; } = new();

        /// <summary>
        /// Load configuration from defaults.yaml
        /// </summary>
        public static Config Load(string? configPath = null)
        {
            try
            {
                // Determine config file path
                if (string.IsNullOrEmpty(configPath))
                {
                    var locations = new[]
                    {
                        "config/defaults.yaml",
                        "defaults.yaml",
                        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "defaults.yaml"),
                        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "defaults.yaml")
                    };
                    
                    foreach (var loc in locations)
                    {
                        if (File.Exists(loc))
                        {
                            configPath = loc;
                            break;
                        }
                    }
                    
                    if (string.IsNullOrEmpty(configPath))
                    {
                        throw new FileNotFoundException("Configuration file not found: config/defaults.yaml");
                    }
                }

                Log.Information("Loading configuration from: {ConfigPath}", configPath);
                
                // Read YAML
                var yaml = File.ReadAllText(configPath);
                
                var deserializer = new DeserializerBuilder()
                    .WithNamingConvention(UnderscoredNamingConvention.Instance)
                    .IgnoreUnmatchedProperties()
                    .Build();

                var config = deserializer.Deserialize<Config>(yaml);
                
                // Expand paths (~ to home directory)
                config.ExpandPaths();
                
                Log.Information("Configuration loaded successfully");
                return config;
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Failed to load configuration - YAML is required");
                throw;
            }
        }

        public void ExpandPaths()
        {
            // AUTO-DETECT Docker environment
            var inDocker = IsRunningInDocker();
            if (inDocker && !Docker.InContainer)
            {
                Log.Debug("Docker environment detected, adjusting paths");
                Docker.InContainer = true;
            }

            // If running in Docker, use container paths
            if (Docker.InContainer)
            {
                Log.Information("Running in Docker container, using container paths");
                Paths.ReportDir = Docker.ContainerReportDir;
                Paths.Database = Docker.ContainerDbPath;
                Paths.LogFile = "/logs/asterion.log";
                Paths.ConsentProofsDir = "/root/.asterion/consent-proofs";
                return;
            }

            // Otherwise expand ~ paths normally
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            Paths.ReportDir = ExpandPath(Paths.ReportDir, home);
            Paths.Database = ExpandPath(Paths.Database, home);
            Paths.LogFile = ExpandPath(Paths.LogFile, home);
            Paths.ConsentProofsDir = ExpandPath(Paths.ConsentProofsDir, home);
        }

        /// <summary>
        /// Detect if running inside a Docker container
        /// </summary>
        private bool IsRunningInDocker()
        {
            // Method 0: Explicit environment variable (highest priority, like Argus)
            var asterionInDocker = Environment.GetEnvironmentVariable("ASTERION_IN_DOCKER");
            Log.Debug("Docker detection - ASTERION_IN_DOCKER: {Value}", asterionInDocker ?? "null");
            if (!string.IsNullOrEmpty(asterionInDocker) && asterionInDocker.ToLower() == "true")
            {
                Log.Information("Docker detected via ASTERION_IN_DOCKER environment variable");
                return true;
            }

            // Method 1: Check for .dockerenv file
            var dockerEnvExists = File.Exists("/.dockerenv");
            Log.Debug("Docker detection - /.dockerenv exists: {Exists}", dockerEnvExists);
            if (dockerEnvExists)
            {
                Log.Information("Docker detected via /.dockerenv file");
                return true;
            }

            // Method 2: Check DOTNET_RUNNING_IN_CONTAINER environment variable
            var dotnetInContainer = Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER");
            Log.Debug("Docker detection - DOTNET_RUNNING_IN_CONTAINER: {Value}", dotnetInContainer ?? "null");
            if (!string.IsNullOrEmpty(dotnetInContainer) && dotnetInContainer.ToLower() == "true")
            {
                Log.Information("Docker detected via DOTNET_RUNNING_IN_CONTAINER");
                return true;
            }

            // Method 3: Check for "docker" in cgroup (Linux only)
            try
            {
                if (File.Exists("/proc/1/cgroup"))
                {
                    var cgroup = File.ReadAllText("/proc/1/cgroup");
                    Log.Debug("Docker detection - /proc/1/cgroup content: {Content}", cgroup.Substring(0, Math.Min(100, cgroup.Length)));
                    if (cgroup.Contains("docker") || cgroup.Contains("/kubepods/"))
                    {
                        Log.Information("Docker detected via /proc/1/cgroup");
                        return true;
                    }
                }
                else
                {
                    Log.Debug("Docker detection - /proc/1/cgroup does not exist");
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Docker detection - Error reading /proc/1/cgroup");
            }

            Log.Debug("Docker detection - Not running in container");
            return false;
        }

        private string ExpandPath(string path, string home)
        {
            if (path.StartsWith("~/"))
            {
                return path.Replace("~/", home + Path.DirectorySeparatorChar);
            }
            return path;
        }

        public void EnsureDirectories()
        {
            var dirs = new[]
            {
                Paths.ReportDir,
                Path.GetDirectoryName(Paths.Database),
                Path.GetDirectoryName(Paths.LogFile),
                Paths.ConsentProofsDir
            };

            foreach (var dir in dirs)
            {
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                    Log.Debug("Created directory: {Directory}", dir);
                }
            }
        }
    }

    // ======================
    // CONFIGURATION CLASSES
    // ======================
    
    public class GeneralConfig
    {
        public string Version { get; set; } = string.Empty;
        public string Author { get; set; } = string.Empty;
        public string Github { get; set; } = string.Empty;
        public string Contact { get; set; } = string.Empty;
    }

    public class PathsConfig
    {
        public string ReportDir { get; set; } = string.Empty;
        public string Database { get; set; } = string.Empty;
        public string LogFile { get; set; } = string.Empty;
        public string ConsentProofsDir { get; set; } = string.Empty;
    }

    public class ScanConfig
    {
        public string DefaultMode { get; set; } = string.Empty;
        public RateLimitConfig RateLimit { get; set; } = new();
        public TimeoutConfig Timeout { get; set; } = new();
        public string UserAgent { get; set; } = string.Empty;
        public bool FollowRedirects { get; set; }
        public int MaxRedirects { get; set; }
        public bool VerifySsl { get; set; }
    }

    public class RateLimitConfig
    {
        public double SafeMode { get; set; }
        public double AggressiveMode { get; set; }
    }

    public class TimeoutConfig
    {
        public int Connect { get; set; }
        public int Read { get; set; }
    }

    public class NetworkConfig
    {
        public List<int> DefaultPorts { get; set; } = new();
        public PortScanConfig PortScan { get; set; } = new();
        public DiscoveryConfig Discovery { get; set; } = new();
    }

    public class PortScanConfig
    {
        public string Method { get; set; } = string.Empty;
        public int TimeoutMs { get; set; }
        public int RetryCount { get; set; }
    }

    public class DiscoveryConfig
    {
        public int PingTimeoutMs { get; set; }
        public bool SkipPing { get; set; }
    }

    public class SmbConfig
    {
        public bool CheckGuestAccess { get; set; }
        public bool CheckSigning { get; set; }
        public bool CheckSmbVersions { get; set; }
        public bool CheckShares { get; set; }
        public int MaxSharesToEnumerate { get; set; }
    }

    public class RdpConfig
    {
        public bool CheckNla { get; set; }
        public bool CheckEncryption { get; set; }
        public bool CheckCertificate { get; set; }
    }

    public class LdapConfig
    {
        public bool CheckAnonymousBind { get; set; }
        public bool CheckSigning { get; set; }
        public bool CheckChannelBinding { get; set; }
        public int TimeoutSeconds { get; set; }
    }

    public class KerberosConfig
    {
        public bool CheckAsrepRoasting { get; set; }
        public bool CheckTicketLifetime { get; set; }
        public string? RealmDefault { get; set; }
    }

    public class SnmpConfig
    {
        public bool CheckDefaultCommunities { get; set; }
        public List<string> DefaultCommunities { get; set; } = new();
        public int TimeoutSeconds { get; set; }
        public int Retries { get; set; }
    }

    public class DnsConfig
    {
        public bool CheckZoneTransfer { get; set; }
        public bool CheckLlmnr { get; set; }
        public bool CheckMdns { get; set; }
        public List<string> DnsServers { get; set; } = new();
    }

    public class SshConfig
    {
        public bool CheckRootLogin { get; set; }
        public bool CheckPasswordAuth { get; set; }
        public bool CheckWeakCiphers { get; set; }
        public int TimeoutSeconds { get; set; }
    }

    public class NfsConfig
    {
        public bool CheckExports { get; set; }
        public bool CheckNoRootSquash { get; set; }
    }

    public class ConsentConfig
    {
        public int TokenExpiryHours { get; set; }
        public int TokenHexLength { get; set; }
        public string HttpVerificationPath { get; set; } = string.Empty;
        public string DnsTxtPrefix { get; set; } = string.Empty;
        public int VerificationRetries { get; set; }
        public int VerificationRetryDelay { get; set; }
    }

    public class ReportingConfig
    {
        public FormatConfig Format { get; set; } = new();
        public int JsonIndent { get; set; }
        public HtmlConfig Html { get; set; } = new();
    }

    public class FormatConfig
    {
        public bool Json { get; set; }
        public bool Html { get; set; }
    }

    public class HtmlConfig
    {
        public bool IncludeEvidence { get; set; }
        public bool IncludeRawRequests { get; set; }
        public bool CssInline { get; set; }
    }

    public class LoggingConfig
    {
        public string Level { get; set; } = string.Empty;
        public string Format { get; set; } = string.Empty;
        public string DateFormat { get; set; } = string.Empty;
        public bool JsonFormat { get; set; }
        public RedactConfig Redact { get; set; } = new();
        public bool Colors { get; set; }
    }

    public class RedactConfig
    {
        public bool Enabled { get; set; }
        public List<string> Patterns { get; set; } = new();
    }

    public class AiConfig
    {
        public bool Enabled { get; set; }

        [YamlMember(Alias = "langchain")]
        public LangChainConfig LangChain { get; set; } = new();

        public string ApiKeyEnv { get; set; } = string.Empty;
        public string PromptsDir { get; set; } = string.Empty;
        public SanitizationConfig Sanitization { get; set; } = new();
    }

    public class LangChainConfig
    {
        public string Provider { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public double Temperature { get; set; }
        public int MaxTokens { get; set; }
        public string AgentType { get; set; } = string.Empty;
        public string OllamaBaseUrl { get; set; } = string.Empty;
        public MemoryConfig Memory { get; set; } = new();
    }

    public class MemoryConfig
    {
        public bool Enabled { get; set; }
        public string Type { get; set; } = string.Empty;
        public int MaxHistory { get; set; }
    }

    public class SanitizationConfig
    {
        public bool RemoveUrls { get; set; }
        public bool RemoveTokens { get; set; }
        public bool RemoveCredentials { get; set; }
        public int MaxEvidenceLength { get; set; }
    }

    public class AdvancedConfig
    {
        public int MaxWorkers { get; set; }
        public bool CacheResponses { get; set; }
        public int CacheTtlSeconds { get; set; }
        public Dictionary<string, string> CustomHeaders { get; set; } = new();
        public ProxyConfig Proxy { get; set; } = new();
    }

    public class ProxyConfig
    {
        public string? Http { get; set; }
        public string? Https { get; set; }
    }

    public class WindowsConfig
    {
        public bool CheckFirewall { get; set; }
        public bool CheckRegistry { get; set; }
        public bool CheckAdPolicies { get; set; }
        public bool CheckServices { get; set; }
        public bool CheckWmi { get; set; }
    }

    public class LinuxConfig
    {
        public bool CheckFirewall { get; set; }
        public bool CheckSambaConfig { get; set; }
        public bool CheckNfsExports { get; set; }
        public bool CheckSshConfig { get; set; }
        public bool CheckSuidBinaries { get; set; }
    }

    public class DockerConfig
    {
        public bool InContainer { get; set; }
        public string ContainerReportDir { get; set; } = string.Empty;
        public string ContainerDbPath { get; set; } = string.Empty;
    }
}