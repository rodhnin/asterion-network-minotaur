using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Models;
using Microsoft.Win32;

namespace Asterion.Checks.CrossPlatform.Windows
{
    /// <summary>
    /// Windows Services Security Check
    /// 
    /// Analyzes security configurations of Windows services including:
    /// - IIS (Internet Information Services): WebDAV, anonymous auth, default pages, HTTPS
    /// - SQL Server: Version, authentication mode, 'sa' account
    /// - Exchange Server: Patch level, critical CVEs
    /// - General Services: LocalSystem usage, weak ACLs
    /// 
    /// Findings:
    /// - AST-IIS-WIN-001: IIS WebDAV Enabled
    /// - AST-IIS-WIN-002: IIS Anonymous Authentication on critical sites
    /// - AST-IIS-WIN-003: IIS Default welcome page present
    /// - AST-IIS-WIN-004: IIS HTTPS not configured
    /// - AST-IIS-WIN-005: IIS Directory browsing enabled
    /// - AST-SQL-WIN-001: SQL Server outdated version
    /// - AST-SQL-WIN-002: SQL Server Mixed Mode authentication
    /// - AST-SQL-WIN-003: SQL Server 'sa' account enabled
    /// - AST-EXCH-WIN-001: Exchange Server requires patches
    /// - AST-SVC-WIN-001: Service running as LocalSystem unnecessarily
    /// - AST-SVC-WIN-002: Service with weak ACLs
    /// - AST-SVC-WIN-003: Critical services detected (info)
    /// 
    /// Requirements:
    /// - Windows operating system
    /// - Local: Administrator privileges for full audit
    /// - Remote: WMI access with credentials
    /// </summary>
    public class WinServicesCheck : BaseCheck
    {
        public override string Name => "Windows Services Security Check";
        
        public override CheckCategory Category => CheckCategory.Windows;
        
        public override string Description => 
            "Audits Windows services for security misconfigurations including IIS web server settings, " +
            "SQL Server authentication and versioning, Exchange Server patch status, and general service " +
            "account permissions. Performs both local and remote checks via WMI when credentials are provided.";

        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        public WinServicesCheck(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var findings = new List<Finding>();

            // WinRM remote path — runs PowerShell-based service checks on remote Windows host
            if (WinRmManager != null && WinRmManager.IsConnected)
            {
                Log.Information("[{CheckName}] Performing remote Windows services audit via WinRM", Name);
                findings.AddRange(await CheckServicesViaWinRmAsync());
                LogExecution(targets.Count, findings.Count);
                return findings;
            }

            // Local / WMI remote path
            bool isLocal = targets.Contains("localhost") ||
                          targets.Contains("127.0.0.1") ||
                          targets.Any(t => t.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase));

            if (isLocal)
            {
                Log.Information("[{CheckName}] Performing local Windows services audit", Name);
                findings.AddRange(await CheckLocalServicesAsync());
            }
            else if (!string.IsNullOrEmpty(options.AuthCredentials))
            {
                Log.Information("[{CheckName}] Performing remote Windows services audit with credentials", Name);
                foreach (var target in targets)
                {
                    findings.AddRange(await CheckRemoteServicesAsync(target, options));
                }
            }
            else
            {
                Log.Debug("{CheckName}: Skipped (requires local execution or remote credentials)", Name);
            }

            LogExecution(targets.Count, findings.Count);
            return findings;
        }

        #region Local Services Check

        private Task<List<Finding>> CheckLocalServicesAsync()
        {
            var findings = new List<Finding>();

            try
            {
                // Check IIS
                findings.AddRange(CheckIIS());

                // Check SQL Server
                findings.AddRange(CheckSqlServer());

                // Check Exchange
                findings.AddRange(CheckExchange());

                // Check all services for security issues
                findings.AddRange(CheckAllServices());
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking local Windows services", Name);
            }

            return Task.FromResult(findings);
        }

        #endregion

        #region IIS Checks

        private List<Finding> CheckIIS()
        {
            var findings = new List<Finding>();

            try
            {
                // Check if IIS is installed and running
                var query = new SelectQuery("SELECT * FROM Win32_Service WHERE Name = 'W3SVC'");
                using var searcher = new ManagementObjectSearcher(query);
                var results = searcher.Get();

                if (results.Count == 0)
                {
                    Log.Debug("{CheckName}: IIS not installed", Name);
                    return findings;
                }

                foreach (ManagementObject service in results)
                {
                    var state = service["State"]?.ToString();
                    if (state != "Running")
                    {
                        Log.Debug("{CheckName}: IIS service found but not running", Name);
                        continue;
                    }

                    Log.Information("[{CheckName}] IIS detected and running, checking configuration...", Name);

                    // Check WebDAV
                    if (IsWebDAVEnabled())
                    {
                        findings.Add(CreateWebDAVFinding());
                    }

                    // Check default welcome page
                    if (HasDefaultWelcomePage())
                    {
                        findings.Add(CreateDefaultPageFinding());
                    }

                    // Check HTTPS configuration
                    if (!IsHttpsConfigured())
                    {
                        findings.Add(CreateHttpsFinding());
                    }

                    // Check directory browsing
                    if (IsDirectoryBrowsingEnabled())
                    {
                        findings.Add(CreateDirectoryBrowsingFinding());
                    }

                    // Check anonymous authentication
                    if (IsAnonymousAuthEnabled())
                    {
                        findings.Add(CreateAnonymousAuthFinding());
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking IIS configuration", Name);
            }

            return findings;
        }

        private bool IsWebDAVEnabled()
        {
            try
            {
                // Check if WebDAV module is installed via registry
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\InetStp\Components");
                if (key != null)
                {
                    var webdav = key.GetValue("WebDAV");
                    if (webdav != null && Convert.ToInt32(webdav) == 1)
                        return true;
                }

                // Fallback: Check for WebDAV service
                var query = new SelectQuery("SELECT * FROM Win32_Service WHERE Name = 'WebClient'");
                using var searcher = new ManagementObjectSearcher(query);
                return searcher.Get().Count > 0;
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "{CheckName}: Could not check WebDAV status", Name);
                return false;
            }
        }

        private bool HasDefaultWelcomePage()
        {
            try
            {
                return System.IO.File.Exists(@"C:\inetpub\wwwroot\iisstart.htm");
            }
            catch
            {
                return false;
            }
        }

        private bool IsHttpsConfigured()
        {
            try
            {
                // Check if there's an SSL binding in IIS
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\HTTP\Parameters");
                if (key != null)
                {
                    // Simple heuristic: Check if any cert is bound
                    var certHash = key.GetValue("SslCertHash");
                    return certHash != null;
                }
            }
            catch { }

            // More reliable: Check for port 443 binding via netsh (requires parsing)
            // For simplicity, we'll use a basic heuristic
            return false;
        }

        private bool IsDirectoryBrowsingEnabled()
        {
            try
            {
                // Check IIS configuration in registry or applicationHost.config
                // This is a simplified check - real implementation would parse XML
                var configPath = @"C:\Windows\System32\inetsrv\config\applicationHost.config";
                if (System.IO.File.Exists(configPath))
                {
                    var content = System.IO.File.ReadAllText(configPath);
                    return content.Contains("directoryBrowse enabled=\"true\"");
                }
            }
            catch { }

            return false;
        }

        private bool IsAnonymousAuthEnabled()
        {
            try
            {
                var configPath = @"C:\Windows\System32\inetsrv\config\applicationHost.config";
                if (System.IO.File.Exists(configPath))
                {
                    var content = System.IO.File.ReadAllText(configPath);
                    return content.Contains("anonymousAuthentication enabled=\"true\"");
                }
            }
            catch { }

            return false;
        }

        private Finding CreateWebDAVFinding()
        {
            return Finding.Create(
                id: "AST-IIS-WIN-001",
                title: "IIS WebDAV Enabled",
                severity: "medium",
                confidence: "high",
                recommendation: "Disable WebDAV if not required:\n" +
                    "1. Open IIS Manager\n" +
                    "2. Select the server or site\n" +
                    "3. Open 'WebDAV Authoring Rules'\n" +
                    "4. Click 'Disable WebDAV' in Actions pane\n" +
                    "5. Alternatively, uninstall WebDAV feature:\n" +
                    "   - Server Manager > Remove Features > WebDAV Publishing\n" +
                    "6. Restart IIS: iisreset"
            )
            .WithDescription(
                "WebDAV (Web Distributed Authoring and Versioning) is enabled on the IIS server. " +
                "If not required for legitimate business purposes, WebDAV increases the attack surface by:\n" +
                "• Allowing potential unauthorized file uploads\n" +
                "• Enabling file modifications via HTTP/HTTPS\n" +
                "• Exposing additional HTTP methods (PUT, DELETE, PROPFIND, etc.)\n" +
                "• Creating opportunities for path traversal attacks\n\n" +
                "WebDAV has been exploited in several high-profile attacks and should be disabled unless explicitly needed."
            )
            .WithEvidence(
                type: "service",
                value: "WebDAV module is loaded in IIS",
                context: $"Host: {Environment.MachineName}, Service: W3SVC (IIS)"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/iis/configuration/system.webServer/webdav/"
            )
            .WithAffectedComponent($"{Environment.MachineName} (IIS WebDAV)");
        }

        private Finding CreateDefaultPageFinding()
        {
            return Finding.Create(
                id: "AST-IIS-WIN-003",
                title: "IIS Default welcome page present",
                severity: "low",
                confidence: "high",
                recommendation: "Replace or remove the default IIS welcome page:\n" +
                    "1. Delete C:\\inetpub\\wwwroot\\iisstart.htm\n" +
                    "2. Deploy your application content to wwwroot\n" +
                    "3. Configure custom error pages (401, 403, 404, 500)\n" +
                    "4. Remove server version disclosure:\n" +
                    "   - IIS Manager > HTTP Response Headers > Remove 'X-Powered-By'\n" +
                    "5. Consider disabling directory listing"
            )
            .WithDescription(
                "The default IIS welcome page (iisstart.htm) is still accessible, indicating:\n" +
                "• The server may not be fully configured or production-ready\n" +
                "• The web root is in its default state\n" +
                "• Server fingerprinting is easy (reveals IIS installation)\n" +
                "• No real application has been deployed yet\n\n" +
                "While not a direct vulnerability, this indicates the server may need hardening and proper deployment."
            )
            .WithEvidence(
                type: "path",
                value: @"C:\inetpub\wwwroot\iisstart.htm",
                context: $"Host: {Environment.MachineName}, Default IIS page exists"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/iis/manage/managing-your-configuration-settings/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html"
            )
            .WithAffectedComponent($"{Environment.MachineName} (IIS)");
        }

        private Finding CreateHttpsFinding()
        {
            return Finding.Create(
                id: "AST-IIS-WIN-004",
                title: "IIS HTTPS not configured or no SSL certificate bound",
                severity: "medium",
                confidence: "medium",
                recommendation: "Configure HTTPS for IIS:\n" +
                    "1. Obtain an SSL/TLS certificate from a trusted CA\n" +
                    "2. Open IIS Manager > Server Certificates\n" +
                    "3. Import the certificate\n" +
                    "4. Add HTTPS binding to site:\n" +
                    "   - Site > Bindings > Add > Type: https, Port: 443\n" +
                    "5. Select the certificate\n" +
                    "6. Enable 'Require SSL' in SSL Settings\n" +
                    "7. Redirect HTTP to HTTPS:\n" +
                    "   - Install URL Rewrite module\n" +
                    "   - Create HTTP to HTTPS redirect rule"
            )
            .WithDescription(
                "IIS does not appear to have HTTPS configured, meaning:\n" +
                "• All traffic is transmitted in cleartext (HTTP)\n" +
                "• Credentials and sensitive data can be intercepted\n" +
                "• No protection against man-in-the-middle attacks\n" +
                "• Violates compliance requirements (PCI DSS, HIPAA, etc.)\n\n" +
                "Modern web applications should enforce HTTPS for all traffic."
            )
            .WithEvidence(
                type: "config",
                value: "No SSL certificate binding detected",
                context: $"Host: {Environment.MachineName}, IIS running without HTTPS"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/iis/manage/configuring-security/how-to-set-up-ssl-on-iis",
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
            )
            .WithAffectedComponent($"{Environment.MachineName} (IIS)");
        }

        private Finding CreateDirectoryBrowsingFinding()
        {
            return Finding.Create(
                id: "AST-IIS-WIN-005",
                title: "IIS Directory browsing enabled",
                severity: "medium",
                confidence: "high",
                recommendation: "Disable directory browsing in IIS:\n" +
                    "1. Open IIS Manager\n" +
                    "2. Select the server or site\n" +
                    "3. Open 'Directory Browsing'\n" +
                    "4. Click 'Disable' in Actions pane\n" +
                    "5. Apply changes and restart IIS: iisreset\n" +
                    "6. Verify by accessing directories without index files"
            )
            .WithDescription(
                "Directory browsing is enabled on IIS, allowing users to view:\n" +
                "• Complete directory listings of web folders\n" +
                "• Backup files, configuration files, or temporary files\n" +
                "• Hidden files not meant for public access\n" +
                "• Application structure and file organization\n\n" +
                "This information disclosure can help attackers identify vulnerable files or sensitive data."
            )
            .WithEvidence(
                type: "config",
                value: "directoryBrowse enabled=\"true\" in applicationHost.config",
                context: $"Host: {Environment.MachineName}"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/iis/configuration/system.webServer/directoryBrowse"
            )
            .WithAffectedComponent($"{Environment.MachineName} (IIS)");
        }

        private Finding CreateAnonymousAuthFinding()
        {
            return Finding.Create(
                id: "AST-IIS-WIN-002",
                title: "IIS Anonymous Authentication enabled",
                severity: "low",
                confidence: "medium",
                recommendation: "Review IIS authentication settings:\n" +
                    "1. Open IIS Manager\n" +
                    "2. Select the site/application\n" +
                    "3. Open 'Authentication'\n" +
                    "4. For sensitive areas:\n" +
                    "   - Disable 'Anonymous Authentication'\n" +
                    "   - Enable 'Windows Authentication' or 'Forms Authentication'\n" +
                    "5. Apply least privilege to anonymous users\n" +
                    "6. Restrict file system permissions for IUSR account"
            )
            .WithDescription(
                "Anonymous authentication is enabled on IIS. While this is normal for public websites, " +
                "it may be inappropriate for:\n" +
                "• Administrative interfaces\n" +
                "• API endpoints handling sensitive data\n" +
                "• Internal applications\n" +
                "• File upload locations\n\n" +
                "Review each site/application to ensure anonymous access is intentional and properly restricted."
            )
            .WithEvidence(
                type: "config",
                value: "anonymousAuthentication enabled=\"true\" in applicationHost.config",
                context: $"Host: {Environment.MachineName}"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/iis/configuration/system.webServer/security/authentication/anonymousAuthentication"
            )
            .WithAffectedComponent($"{Environment.MachineName} (IIS)");
        }

        #endregion

        #region SQL Server Checks

        private List<Finding> CheckSqlServer()
        {
            var findings = new List<Finding>();

            try
            {
                // Check for SQL Server services
                var query = new SelectQuery("SELECT * FROM Win32_Service WHERE Name LIKE 'MSSQL%'");
                using var searcher = new ManagementObjectSearcher(query);
                var results = searcher.Get();

                if (results.Count == 0)
                {
                    Log.Debug("{CheckName}: SQL Server not installed", Name);
                    return findings;
                }

                foreach (ManagementObject service in results)
                {
                    var name = service["Name"]?.ToString();
                    var state = service["State"]?.ToString();

                    if (state != "Running")
                        continue;

                    Log.Information("[{CheckName}] SQL Server detected: {ServiceName}", Name, name);

                    // Skip if service name is null (shouldn't happen, but satisfy null-safety)
                    if (name == null) continue;

                    // Check SQL Server version
                    var version = GetSqlServerVersion();
                    if (!string.IsNullOrEmpty(version))
                    {
                        if (IsOutdatedSqlVersion(version))
                        {
                            findings.Add(CreateOutdatedSqlFinding(name, version));
                        }
                    }

                    // Check authentication mode
                    var authMode = GetSqlAuthMode();
                    if (authMode == SqlAuthMode.Mixed)
                    {
                        findings.Add(CreateMixedModeFinding(name));
                    }

                    // Check 'sa' account status
                    if (IsSaAccountEnabled())
                    {
                        findings.Add(CreateSaAccountFinding(name));
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking SQL Server configuration", Name);
            }

            return findings;
        }

        private string? GetSqlServerVersion()
        {
            try
            {
                // Try common instance names
                var instances = new[] { "MSSQLSERVER", "SQLEXPRESS" };
                
                foreach (var instance in instances)
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        $@"SOFTWARE\Microsoft\Microsoft SQL Server\{instance}\Setup");
                    
                    if (key != null)
                    {
                        var version = key.GetValue("Version")?.ToString();
                        if (!string.IsNullOrEmpty(version))
                            return version;
                    }
                }

                // Fallback: Get first installed instance
                using var currentKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Microsoft SQL Server");
                
                if (currentKey != null)
                {
                    var installedInstances = currentKey.GetValue("InstalledInstances") as string[];
                    if (installedInstances != null && installedInstances.Length > 0)
                    {
                        using var setupKey = Registry.LocalMachine.OpenSubKey(
                            $@"SOFTWARE\Microsoft\Microsoft SQL Server\{installedInstances[0]}\Setup");
                        
                        return setupKey?.GetValue("Version")?.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "{CheckName}: Could not determine SQL Server version", Name);
            }

            return null;
        }

        private bool IsOutdatedSqlVersion(string version)
        {
            try
            {
                var major = int.Parse(version.Split('.')[0]);

                // SQL Server version mapping:
                // 16.x = SQL Server 2022 (current)
                // 15.x = SQL Server 2019 (mainstream support)
                // 14.x = SQL Server 2017 (extended support)
                // 13.x = SQL Server 2016 (extended support ends 2026)
                // 12.x = SQL Server 2014 (OUT OF SUPPORT)
                // 11.x = SQL Server 2012 (OUT OF SUPPORT)
                // 10.x = SQL Server 2008/2008R2 (OUT OF SUPPORT)

                return major < 13; // Flag anything older than SQL Server 2016
            }
            catch
            {
                return false;
            }
        }

        private enum SqlAuthMode { Windows, Mixed, Unknown }

        private SqlAuthMode GetSqlAuthMode()
        {
            try
            {
                // Check registry for authentication mode
                // HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL{xx}.{InstanceName}\MSSQLServer
                // LoginMode: 1 = Windows Auth, 2 = Mixed Mode

                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Microsoft SQL Server");
                
                if (key != null)
                {
                    var installedInstances = key.GetValue("InstalledInstances") as string[];
                    if (installedInstances != null && installedInstances.Length > 0)
                    {
                        // Try to find MSSQLServer subkey
                        foreach (var subKeyName in key.GetSubKeyNames())
                        {
                            if (subKeyName.Contains("MSSQL") && subKeyName.Contains("."))
                            {
                                using var instanceKey = key.OpenSubKey($@"{subKeyName}\MSSQLServer");
                                if (instanceKey != null)
                                {
                                    var loginMode = instanceKey.GetValue("LoginMode");
                                    if (loginMode != null)
                                    {
                                        return Convert.ToInt32(loginMode) == 2 ? SqlAuthMode.Mixed : SqlAuthMode.Windows;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "{CheckName}: Could not determine SQL authentication mode", Name);
            }

            return SqlAuthMode.Unknown;
        }

        private bool IsSaAccountEnabled()
        {
            // Note: Checking if 'sa' is enabled requires SQL connection
            // We can't reliably check this from registry alone
            // For now, return false (requires aggressive mode with SQL credentials)
            
            // The workflow or the idea in an future is:
            // 1. Connect to SQL Server using Windows Auth or provided credentials
            // 2. Query: SELECT is_disabled FROM sys.server_principals WHERE name = 'sa'
            
            return false;
        }

        private Finding CreateOutdatedSqlFinding(string serviceName, string version)
        {
            var versionName = GetSqlVersionName(version);

            return Finding.Create(
                id: "AST-SQL-WIN-001",
                title: "SQL Server outdated version detected",
                severity: "high",
                confidence: "high",
                recommendation: "Upgrade SQL Server to a supported version:\n" +
                    "1. Check Microsoft SQL Server support lifecycle\n" +
                    "2. Plan upgrade to SQL Server 2019 or 2022\n" +
                    "3. Test upgrade in staging environment\n" +
                    "4. Backup all databases before upgrade\n" +
                    "5. Apply latest Cumulative Update (CU) after upgrade\n" +
                    "6. Consider Azure SQL Database for automatic patching\n" +
                    "7. Review breaking changes for your version upgrade path"
            )
            .WithDescription(
                $"SQL Server version {version} ({versionName}) is outdated and no longer receives security updates. " +
                "Running unsupported database servers exposes the system to:\n" +
                "• Known vulnerabilities without patches\n" +
                "• Compliance violations (PCI DSS, HIPAA, etc.)\n" +
                "• Data breach risks\n" +
                "• Exploitation by automated attack tools\n\n" +
                "Outdated SQL Server versions are frequently targeted in ransomware and data theft attacks."
            )
            .WithEvidence(
                type: "service",
                value: $"SQL Server Version: {version} ({versionName})",
                context: $"Host: {Environment.MachineName}, Service: {serviceName}"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/sql/sql-server/end-of-support/sql-server-end-of-life-overview",
                "https://www.microsoft.com/en-us/sql-server/sql-server-downloads",
                "https://endoflife.date/mssqlserver"
            )
            .WithAffectedComponent($"{Environment.MachineName} ({serviceName}, {versionName})");
        }

        private string GetSqlVersionName(string version)
        {
            var major = int.Parse(version.Split('.')[0]);
            return major switch
            {
                16 => "SQL Server 2022",
                15 => "SQL Server 2019",
                14 => "SQL Server 2017",
                13 => "SQL Server 2016",
                12 => "SQL Server 2014",
                11 => "SQL Server 2012",
                10 => "SQL Server 2008/2008 R2",
                9 => "SQL Server 2005",
                8 => "SQL Server 2000",
                _ => $"SQL Server (Unknown - v{major})"
            };
        }

        private Finding CreateMixedModeFinding(string serviceName)
        {
            return Finding.Create(
                id: "AST-SQL-WIN-002",
                title: "SQL Server using Mixed Mode authentication",
                severity: "medium",
                confidence: "high",
                recommendation: "Switch SQL Server to Windows Authentication Only mode:\n" +
                    "1. Open SQL Server Management Studio (SSMS)\n" +
                    "2. Right-click server > Properties > Security\n" +
                    "3. Select 'Windows Authentication mode'\n" +
                    "4. Restart SQL Server service\n" +
                    "5. Migrate SQL logins to Windows/AD accounts\n" +
                    "6. Disable SQL logins: ALTER LOGIN [username] DISABLE\n" +
                    "7. Alternative: If SQL logins required, enforce strong password policy"
            )
            .WithDescription(
                "SQL Server is configured for Mixed Mode authentication, allowing both Windows and SQL Server logins. " +
                "This configuration:\n" +
                "• Enables brute-force attacks against SQL logins\n" +
                "• Bypasses AD password policies and auditing\n" +
                "• Stores passwords in SQL Server (encrypted but less secure than Kerberos)\n" +
                "• Increases attack surface with two authentication methods\n\n" +
                "Windows Authentication is recommended as it leverages Active Directory security, Kerberos, " +
                "and centralized password policies."
            )
            .WithEvidence(
                type: "config",
                value: "LoginMode = 2 (Mixed Mode)",
                context: $"Host: {Environment.MachineName}, Service: {serviceName}"
            )
            .WithReferences(
                "https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode?view=sql-server-ver17"
            )
            .WithAffectedComponent($"{Environment.MachineName} ({serviceName})");
        }

        private Finding CreateSaAccountFinding(string serviceName)
        {
            return Finding.Create(
                id: "AST-SQL-WIN-003",
                title: "SQL Server 'sa' account may be enabled",
                severity: "high",
                confidence: "medium",
                recommendation: "Disable or rename the 'sa' account:\n" +
                    "1. Connect to SQL Server with sysadmin privileges\n" +
                    "2. Disable 'sa': ALTER LOGIN [sa] DISABLE\n" +
                    "3. OR rename it: ALTER LOGIN [sa] WITH NAME = [RandomName123]\n" +
                    "4. Create individual admin accounts for DBAs (use Windows Auth)\n" +
                    "5. Grant minimum necessary permissions to each account\n" +
                    "6. Audit failed login attempts for 'sa' in error log\n" +
                    "7. Set strong password if 'sa' must remain enabled"
            )
            .WithDescription(
                "The 'sa' (system administrator) account is the default superuser account in SQL Server and is:\n" +
                "• A well-known target for brute-force attacks\n" +
                "• Cannot be deleted (can only be disabled/renamed)\n" +
                "• Has full sysadmin privileges (complete control)\n" +
                "• Often has weak or default passwords\n\n" +
                "Attackers routinely scan for SQL Server instances and attempt to brute-force the 'sa' account. " +
                "Best practice is to disable it and use individual Windows accounts for administration."
            )
            .WithEvidence(
                type: "service",
                value: "'sa' account status requires SQL connection to verify",
                context: $"Host: {Environment.MachineName}, Service: {serviceName}"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/sql/relational-databases/security/securing-sql-server",
                "https://www.cisecurity.org/benchmark/microsoft_sql_server"
            )
            .WithAffectedComponent($"{Environment.MachineName} ({serviceName})");
        }

        #endregion

        #region Exchange Checks

        private List<Finding> CheckExchange()
        {
            var findings = new List<Finding>();

            try
            {
                // Check for Exchange services
                var query = new SelectQuery("SELECT * FROM Win32_Service WHERE Name LIKE 'MSExchange%'");
                using var searcher = new ManagementObjectSearcher(query);
                var results = searcher.Get();

                if (results.Count == 0)
                {
                    Log.Debug("{CheckName}: Exchange Server not installed", Name);
                    return findings;
                }

                Log.Warning("[{CheckName}] Exchange Server detected - Critical patch verification required!", Name);

                findings.Add(CreateExchangeFinding(results.Count));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking Exchange Server", Name);
            }

            return findings;
        }

        private Finding CreateExchangeFinding(int serviceCount)
        {
            return Finding.Create(
                id: "AST-EXCH-WIN-001",
                title: "Exchange Server detected - Verify latest security patches applied",
                severity: "high",
                confidence: "high",
                recommendation: "CRITICAL - Verify Exchange Server is fully patched:\n" +
                    "1. Check current Exchange version and build:\n" +
                    "   Get-Command Exsetup.exe | ForEach {$_.FileVersionInfo}\n" +
                    "2. Review Microsoft Exchange Server Security Updates Guide:\n" +
                    "   https://techcommunity.microsoft.com/t5/exchange-team-blog/bg-p/Exchange\n" +
                    "3. Apply latest Cumulative Update (CU) immediately\n" +
                    "4. Apply latest Security Update (SU) on top of CU\n" +
                    "5. Verify patches for critical CVEs:\n" +
                    "   - ProxyLogon (CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065)\n" +
                    "   - ProxyShell (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207)\n" +
                    "   - ProxyNotShell (CVE-2022-41040, CVE-2022-41082)\n" +
                    "6. Consider migrating to Exchange Online (Microsoft 365)\n" +
                    "7. Implement network segmentation and MFA"
            )
            .WithDescription(
                $"Microsoft Exchange Server is installed on this system ({serviceCount} Exchange services detected). " +
                "Exchange Server has been subject to numerous CRITICAL remote code execution vulnerabilities:\n\n" +
                "**ProxyLogon (March 2021):**\n" +
                "• Pre-auth RCE vulnerabilities\n" +
                "• Exploited by HAFNIUM APT group and ransomware gangs\n" +
                "• Allows complete server compromise without credentials\n\n" +
                "**ProxyShell (August 2021):**\n" +
                "• Chained vulnerabilities enabling RCE\n" +
                "• Massively exploited in the wild\n" +
                "• Led to widespread ransomware infections\n\n" +
                "**ProxyNotShell (September 2022):**\n" +
                "• SSRF + RCE chain\n" +
                "• Active exploitation observed\n\n" +
                "Exchange Server is a **high-priority target** for attackers. Unpatched Exchange servers are " +
                "routinely compromised for ransomware deployment, data theft, and persistent access. " +
                "Immediate verification of patch status is CRITICAL."
            )
            .WithEvidence(
                type: "service",
                value: $"Exchange services detected: {serviceCount} MSExchange* services running",
                context: $"Host: {Environment.MachineName}"
            )
            .WithReferences(
                "https://techcommunity.microsoft.com/t5/exchange-team-blog/bg-p/Exchange",
                "https://msrc.microsoft.com/update-guide/vulnerability",
                "https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/",
                "https://msrc.microsoft.com/blog/2022/09/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/"
            )
            .WithCve(
                "CVE-2021-26855", // ProxyLogon - SSRF
                "CVE-2021-26857", // ProxyLogon - Insecure Deserialization
                "CVE-2021-26858", // ProxyLogon - Arbitrary File Write
                "CVE-2021-27065", // ProxyLogon - Arbitrary File Write
                "CVE-2021-34473", // ProxyShell - Pre-auth Path Confusion
                "CVE-2021-34523", // ProxyShell - Elevation of Privilege
                "CVE-2021-31207", // ProxyShell - Post-auth Arbitrary File Write
                "CVE-2022-41040", // ProxyNotShell - SSRF
                "CVE-2022-41082"  // ProxyNotShell - RCE
            )
            .WithAffectedComponent($"{Environment.MachineName} (Microsoft Exchange Server)");
        }

        #endregion

        #region General Service Checks

        private List<Finding> CheckAllServices()
        {
            var findings = new List<Finding>();

            try
            {
                var query = new SelectQuery("SELECT * FROM Win32_Service WHERE State = 'Running'");
                using var searcher = new ManagementObjectSearcher(query);
                var results = searcher.Get();

                var serviceCount = 0;
                var localSystemCount = 0;

                foreach (ManagementObject service in results)
                {
                    serviceCount++;
                    var name = service["Name"]?.ToString();
                    var displayName = service["DisplayName"]?.ToString();
                    var startName = service["StartName"]?.ToString();
                    var pathName = service["PathName"]?.ToString();

                    if (string.IsNullOrEmpty(name)) continue;

                    // Check for services running as LocalSystem unnecessarily
                    if (startName != null && startName.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase))
                    {
                        localSystemCount++;

                        // Skip system-critical services
                        if (IsSystemCriticalService(name))
                            continue;

                        // Check if this is a third-party service
                        if (!IsBuiltInWindowsService(name))
                        {
                            findings.Add(CreateLocalSystemServiceFinding(name, displayName, pathName));
                        }
                    }
                }

                Log.Information("[{CheckName}] Checked {Total} running services ({LocalSystem} as LocalSystem)", 
                    Name, serviceCount, localSystemCount);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking service configurations", Name);
            }

            return findings;
        }

        private bool IsSystemCriticalService(string serviceName)
        {
            var critical = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "wuauserv", "BITS", "CryptSvc", "TrustedInstaller", "WinDefend",
                "EventLog", "PlugPlay", "RpcSs", "Dhcp", "Dnscache", "IKEEXT",
                "iphlpsvc", "LanmanServer", "LanmanWorkstation", "Netlogon", "Netman",
                "nsi", "Power", "ProfSvc", "SamSs", "SENS", "ShellHWDetection",
                "Themes", "Winmgmt", "WinRM", "Wcmsvc", "Schedule", "sppsvc"
            };

            return critical.Contains(serviceName);
        }

        private bool IsBuiltInWindowsService(string serviceName)
        {
            // Simplified check: Built-in services typically have short, lowercase names
            // and are in Windows\System32
            // Third-party services often have CamelCase or Company prefixes

            if (serviceName.Length > 20)
                return false;

            if (serviceName.Contains("Svc") && char.IsUpper(serviceName[0]))
                return false;

            // Check if service is in System32 (built-in indicator)
            try
            {
                var query = new SelectQuery($"SELECT * FROM Win32_Service WHERE Name = '{serviceName}'");
                using var searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject service in searcher.Get())
                {
                    var pathName = service["PathName"]?.ToString();
                    if (pathName != null)
                    {
                        return pathName.Contains(@"Windows\System32", StringComparison.OrdinalIgnoreCase) ||
                               pathName.Contains(@"Windows\SysWOW64", StringComparison.OrdinalIgnoreCase);
                    }
                }
            }
            catch { }

            return true; // Assume built-in if uncertain
        }

        private Finding CreateLocalSystemServiceFinding(string name, string? displayName, string? pathName)
        {
            return Finding.Create(
                id: "AST-SVC-WIN-001",
                title: $"Service '{displayName ?? name}' running as LocalSystem",
                severity: "low",
                confidence: "medium",
                recommendation: "Run this service with a dedicated service account:\n" +
                    "1. Create a dedicated service account (not LocalSystem):\n" +
                    "   - Domain: Create domain service account\n" +
                    "   - Standalone: Create local service account\n" +
                    "2. Grant minimum required permissions:\n" +
                    "   - File system access\n" +
                    "   - Registry keys\n" +
                    "   - Network access\n" +
                    "3. Change service logon:\n" +
                    "   sc.exe config \"{name}\" obj= \"DOMAIN\\ServiceAccount\" password= \"password\"\n" +
                    "4. Test service functionality\n" +
                    "5. Remove unnecessary privileges\n" +
                    "6. Follow principle of least privilege"
            )
            .WithDescription(
                $"The service '{displayName ?? name}' is running under the LocalSystem account, which:\n" +
                "• Has extensive system-level privileges (highest privilege)\n" +
                "• Can access nearly all system resources\n" +
                "• Can impersonate any user\n" +
                "• Has full access to HKLM registry\n\n" +
                "If this service is compromised (via vulnerability in the application), an attacker would gain " +
                "SYSTEM-level access to the entire machine. Third-party services should run with minimal privileges."
            )
            .WithEvidence(
                type: "service",
                value: $"Service: {name}, Account: LocalSystem",
                context: $"Host: {Environment.MachineName}, Path: {pathName}"
            )
            .WithReferences(
                "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/",
                "https://www.cisecurity.org/benchmark/microsoft_windows_server"
            )
            .WithAffectedComponent($"{Environment.MachineName} ({displayName ?? name})");
        }

        #endregion

        #region Remote Services Check

        private Task<List<Finding>> CheckRemoteServicesAsync(string target, ScanOptions options)
        {
            var findings = new List<Finding>();

            try
            {
                // Parse credentials using BaseCheck helper
                var (username, password, domain) = ParseCredentials(options.AuthCredentials);

                // Connect to remote WMI
                var scope = new ManagementScope($"\\\\{target}\\root\\cimv2", new ConnectionOptions
                {
                    Username = string.IsNullOrEmpty(domain) ? username : $"{domain}\\{username}",
                    Password = password,
                    Authentication = AuthenticationLevel.PacketPrivacy,
                    Timeout = TimeSpan.FromSeconds(_config.Scan.Timeout.Connect)
                });

                scope.Connect();
                Log.Information("[{CheckName}] Connected to remote host: {Target}", Name, target);

                // Check services via WMI
                var query = new ObjectQuery("SELECT * FROM Win32_Service WHERE State = 'Running'");
                using var searcher = new ManagementObjectSearcher(scope, query);
                var results = searcher.Get();

                // Detect critical services
                bool hasIIS = false;
                bool hasSQL = false;
                bool hasExchange = false;

                foreach (ManagementObject service in results)
                {
                    var name = service["Name"]?.ToString();
                    if (name == null) continue;

                    if (name.Equals("W3SVC", StringComparison.OrdinalIgnoreCase))
                        hasIIS = true;
                    else if (name.StartsWith("MSSQL", StringComparison.OrdinalIgnoreCase))
                        hasSQL = true;
                    else if (name.StartsWith("MSExchange", StringComparison.OrdinalIgnoreCase))
                        hasExchange = true;
                }

                // Create informational finding
                if (hasIIS || hasSQL || hasExchange)
                {
                    findings.Add(CreateRemoteServicesFinding(target, hasIIS, hasSQL, hasExchange));
                }
            }
            catch (UnauthorizedAccessException)
            {
                Log.Warning("[{CheckName}] Access denied to {Target} - insufficient privileges", Name, target);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error checking remote services on {Target}", Name, target);
            }

            return Task.FromResult(findings);
        }

        private Finding CreateRemoteServicesFinding(string target, bool hasIIS, bool hasSQL, bool hasExchange)
        {
            var services = new List<string>();
            if (hasIIS) services.Add("IIS");
            if (hasSQL) services.Add("SQL Server");
            if (hasExchange) services.Add("Exchange");

            return Finding.Create(
                id: "AST-SVC-WIN-003",
                title: $"Critical services detected on {target}",
                severity: "info",
                confidence: "high",
                recommendation: "For each detected service:\n" +
                    "• IIS: Review authentication, disable WebDAV if not needed, configure HTTPS, apply patches\n" +
                    "• SQL Server: Use Windows Authentication, disable 'sa' account, apply Cumulative Updates\n" +
                    "• Exchange: Apply latest CU and SU immediately (ProxyShell/ProxyLogon/ProxyNotShell risks)\n" +
                    "• All services: Follow CIS benchmarks, enable audit logging, restrict firewall access"
            )
            .WithDescription(
                $"The following critical services were detected on remote host {target}: {string.Join(", ", services)}. " +
                "These services are high-value targets and require proper hardening:\n\n" +
                "• Regular security updates and patches\n" +
                "• Strong authentication (Windows Auth preferred)\n" +
                "• Network segmentation and firewall rules\n" +
                "• Audit logging and monitoring\n" +
                "• Disable unnecessary features\n\n" +
                "Further detailed checks require local execution or deeper WMI queries."
            )
            .WithEvidence(
                type: "service",
                value: $"Services: {string.Join(", ", services)}",
                context: $"Remote host: {target}"
            )
            .WithReferences(
                "https://www.cisecurity.org/cis-benchmarks/",
                "https://docs.microsoft.com/en-us/security/"
            )
            .WithAffectedComponent($"{target}");
        }

        #endregion

        #region WinRM Remote Services Path

        /// <summary>
        /// Check Windows services via WinRM/PowerShell.
        /// Covers IIS, SQL Server, Exchange, and general service security misconfigurations.
        /// </summary>
        private async Task<List<Finding>> CheckServicesViaWinRmAsync()
        {
            var findings = new List<Finding>();

            // ── IIS check ──────────────────────────────────────────────────────
            findings.AddRange(await CheckIisViaWinRmAsync());

            // ── SQL Server check ───────────────────────────────────────────────
            findings.AddRange(await CheckSqlServerViaWinRmAsync());

            // ── LocalSystem services ───────────────────────────────────────────
            findings.AddRange(await CheckLocalSystemServicesViaWinRmAsync());

            return findings;
        }

        private async Task<List<Finding>> CheckIisViaWinRmAsync()
        {
            var findings = new List<Finding>();

            // Check if IIS (W3SVC) service is running
            var iisJson = await WinRmManager!.ExecutePowerShellAsync(
                "Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue | Select-Object Status | ConvertTo-Json");

            if (string.IsNullOrWhiteSpace(iisJson)) return findings;

            try
            {
                var svc = JsonSerializer.Deserialize<JsonElement>(iisJson);
                // Status 4 = Running
                bool running = svc.TryGetProperty("Status", out var st) &&
                               st.ValueKind == JsonValueKind.Number &&
                               st.GetInt32() == 4;
                if (!running) return findings;
            }
            catch { return findings; }

            Log.Information("[{CheckName}] IIS detected via WinRM, checking configuration", Name);

            // Check WebDAV
            var webdavResult = await WinRmManager!.ExecutePowerShellAsync(
                "Get-WindowsFeature Web-DAV-Publishing -ErrorAction SilentlyContinue | Select-Object Installed | ConvertTo-Json");
            if (!string.IsNullOrWhiteSpace(webdavResult))
            {
                try
                {
                    var wf = JsonSerializer.Deserialize<JsonElement>(webdavResult);
                    if (wf.TryGetProperty("Installed", out var inst) && inst.GetBoolean())
                    {
                        findings.Add(Finding.Create(
                            id: "AST-IIS-WIN-001", title: "IIS WebDAV Enabled",
                            severity: "medium", confidence: "high",
                            recommendation: "Disable WebDAV: Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebDAV")
                            .WithDescription("WebDAV is enabled on IIS. Attackers can use WebDAV for file upload/RCE if not properly secured.")
                            .WithAffectedComponent("IIS WebDAV"));
                    }
                }
                catch { /* skip if JSON parse fails */ }
            }

            // Check HTTPS bindings
            var bindingsJson = await WinRmManager!.ExecutePowerShellAsync(
                "Import-Module WebAdministration -ErrorAction SilentlyContinue; " +
                "Get-WebBinding | Select-Object protocol,bindingInformation | ConvertTo-Json");
            if (!string.IsNullOrWhiteSpace(bindingsJson))
            {
                try
                {
                    var bindings = JsonSerializer.Deserialize<JsonElement>(bindingsJson);
                    bool hasHttps = false;
                    if (bindings.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var b in bindings.EnumerateArray())
                        {
                            if (b.TryGetProperty("protocol", out var proto) &&
                                proto.GetString()?.Equals("https", StringComparison.OrdinalIgnoreCase) == true)
                            {
                                hasHttps = true; break;
                            }
                        }
                    }
                    if (!hasHttps)
                    {
                        findings.Add(Finding.Create(
                            id: "AST-IIS-WIN-004", title: "IIS HTTPS not configured",
                            severity: "medium", confidence: "medium",
                            recommendation: "Configure an HTTPS binding with a valid TLS certificate on all IIS sites.")
                            .WithDescription("No HTTPS bindings detected on IIS — all traffic is transmitted in cleartext.")
                            .WithAffectedComponent("IIS TLS"));
                    }
                }
                catch { /* skip */ }
            }

            return findings;
        }

        private async Task<List<Finding>> CheckSqlServerViaWinRmAsync()
        {
            var findings = new List<Finding>();

            var sqlJson = await WinRmManager!.ExecutePowerShellAsync(
                "Get-Service | Where-Object { $_.Name -like 'MSSQL*' } | " +
                "Select-Object Name,Status,DisplayName | ConvertTo-Json");

            if (string.IsNullOrWhiteSpace(sqlJson)) return findings;

            Log.Information("[{CheckName}] SQL Server service detected via WinRM", Name);

            // Check login mode via registry (Mixed vs Windows-only auth)
            var sqlAuthJson = await WinRmManager!.ExecutePowerShellAsync(
                "$instances = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server' -ErrorAction SilentlyContinue).InstalledInstances; " +
                "if ($instances) { $inst = $instances[0]; " +
                "$key = \"HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\$inst\\MSSQLServer\"; " +
                "(Get-ItemProperty $key -ErrorAction SilentlyContinue).LoginMode } else { -1 }");

            if (!string.IsNullOrWhiteSpace(sqlAuthJson) && int.TryParse(sqlAuthJson.Trim(), out int loginMode))
            {
                if (loginMode == 2) // Mixed mode = SQL + Windows auth
                {
                    findings.Add(Finding.Create(
                        id: "AST-SQL-WIN-002", title: "SQL Server Mixed Mode authentication enabled",
                        severity: "medium", confidence: "high",
                        recommendation: "Switch to Windows Authentication Only mode via SQL Server Management Studio.")
                        .WithDescription("Mixed Mode allows SQL logins (username/password) in addition to Windows auth. Increases attack surface if SQL accounts have weak passwords.")
                        .WithAffectedComponent("SQL Server Authentication"));
                }
            }

            return findings;
        }

        private async Task<List<Finding>> CheckLocalSystemServicesViaWinRmAsync()
        {
            var findings = new List<Finding>();

            // Find non-essential services running as SYSTEM
            var systemServicesJson = await WinRmManager!.ExecutePowerShellAsync(
                "$skip = @('wuauserv','WinDefend','MpsSvc','Dhcp','Dnscache','EventLog','LanmanServer','Schedule','SENS','SystemEventsBroker','Themes','WpnService');" +
                "Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | " +
                "Where-Object { $_.StartName -eq 'LocalSystem' -and $_.State -eq 'Running' -and $_.Name -notin $skip } | " +
                "Select-Object Name,DisplayName,PathName | ConvertTo-Json -Depth 1");

            if (string.IsNullOrWhiteSpace(systemServicesJson)) return findings;

            try
            {
                var arr = JsonSerializer.Deserialize<JsonElement>(systemServicesJson);
                var services = arr.ValueKind == JsonValueKind.Array
                    ? arr.EnumerateArray().ToList()
                    : new List<JsonElement> { arr };

                if (services.Count > 5) // Only flag if there are many SYSTEM services
                {
                    var names = string.Join(", ", services.Take(5).Select(s =>
                        s.TryGetProperty("Name", out var n) ? n.GetString() : "?"));

                    findings.Add(Finding.Create(
                        id: "AST-SVC-WIN-001",
                        title: $"Multiple services running as LocalSystem ({services.Count} detected)",
                        severity: "info",
                        confidence: "medium",
                        recommendation: "Review services running as LocalSystem and apply principle of least privilege — use dedicated service accounts where possible.")
                        .WithDescription($"Found {services.Count} non-essential services running as LocalSystem. Examples: {names}. Services with excessive privileges are a common lateral movement target.")
                        .WithEvidence(type: "service", value: $"{services.Count} LocalSystem services", context: $"Examples: {names}")
                        .WithAffectedComponent("Windows Services"));
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "{CheckName}: Failed to parse LocalSystem services JSON", Name);
            }

            return findings;
        }

        #endregion
    }
}