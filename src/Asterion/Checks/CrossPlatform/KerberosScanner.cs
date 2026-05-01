using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Core.Utils;
using Asterion.Models;

namespace Asterion.Checks.CrossPlatform
{
    /// <summary>
    /// Kerberos Security Scanner
    /// 
    /// Detects:
    /// - AST-KRB-001: Kerberos account without preauthentication (AS-REP roastable)
    /// - AST-KRB-002: Weak ticket lifetime configuration
    /// - AST-KRB-003: Service accounts with SPNs vulnerable to Kerberoasting
    /// 
    /// Note: This scanner assumes LdapScanner has already handled authentication.
    /// It reuses LDAP connections to perform Kerberos-specific checks.
    /// </summary>
    public class KerberosScanner : BaseCheck
    {
        private const int KERBEROS_PORT = 88;
        private const int UF_DONT_REQUIRE_PREAUTH = 0x400000;
        
        public override string Name => "Kerberos Security Scanner";
        public override CheckCategory Category => CheckCategory.CrossPlatform;
        public override string Description => "Detects Kerberos misconfigurations including AS-REP roasting, weak ticket lifetimes, and Kerberoastable SPNs";
        
        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;
        
        public KerberosScanner(Config config) : base(config) { }
        
        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            var findings = new List<Finding>();
            
            if (!CanExecute() || !ShouldExecute(options))
                return findings;
            
            if (!_config.Kerberos.CheckAsrepRoasting)
            {
                Log.Debug("Kerberos AS-REP roasting check disabled in config");
                return findings;
            }
            
            Log.Information("Starting Kerberos security scan on {Count} target(s)", targets.Count);
            
            foreach (var target in targets)
            {
                try
                {
                    if (!await NetworkUtils.IsPortOpenAsync(target, KERBEROS_PORT, _config.Scan.Timeout.Connect * 1000))
                    {
                        Log.Debug("Kerberos port {Port} not open on {Target}", KERBEROS_PORT, target);
                        continue;
                    }
                    
                    Log.Debug("Kerberos port {Port} open on {Target}, analyzing...", KERBEROS_PORT, target);
                    
                    var kerberosInfo = await AnalyzeKerberosAsync(target, options);
                    
                    if (kerberosInfo != null)
                    {
                        if (kerberosInfo.AsRepRoastableAccounts.Count > 0)
                            findings.Add(CreateAsRepRoastingFinding(target, kerberosInfo));
                        
                        if (kerberosInfo.WeakTicketLifetime)
                            findings.Add(CreateWeakTicketLifetimeFinding(target, kerberosInfo));
                        
                        if (kerberosInfo.KerberoastableAccounts.Count > 0 && options.Mode.ToLower() == "aggressive")
                            findings.Add(CreateKerberoastingFinding(target, kerberosInfo));
                    }
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "Failed to scan Kerberos on {Target}", target);
                }
            }
            
            LogExecution(targets.Count, findings.Count);
            return findings;
        }
        
        private async Task<KerberosInfo?> AnalyzeKerberosAsync(string host, ScanOptions options)
        {
            var info = new KerberosInfo { Host = host };
            
            try
            {
                using (var connection = new LdapConnection(new LdapDirectoryIdentifier(host, 389)))
                {
                    connection.Timeout = TimeSpan.FromSeconds(_config.Ldap.TimeoutSeconds);
                    connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                    
                    bool authenticated = await TryBindAsync(connection, options);
                    
                    if (authenticated)
                    {
                        var domainContext = await GetDomainContextAsync(connection);
                        
                        if (!string.IsNullOrEmpty(domainContext))
                        {
                            info.DomainContext = domainContext;
                            Log.Debug("[{CheckName}] Domain context: {Context}", Name, domainContext);
                            
                            await EnumerateAsRepRoastableAccountsAsync(connection, domainContext, info, options);
                            await CheckKerberosPolicyAsync(connection, domainContext, info);
                            
                            if (options.Mode.ToLower() == "aggressive" && !string.IsNullOrEmpty(options.AuthCredentials))
                            {
                                await EnumerateSpnsAsync(connection, domainContext, info);
                            }
                        }
                    }
                }
                
                return info;
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] Kerberos analysis failed on {Host}", Name, host);
                return null;
            }
        }
        
        private async Task<bool> TryBindAsync(LdapConnection connection, ScanOptions options)
        {
            return await Task.Run(() =>
            {
                try
                {
                    // Try authenticated bind
                    if (!string.IsNullOrEmpty(options.AuthCredentials))
                    {
                        var (username, password, domain) = ParseCredentials(options.AuthCredentials);
                        
                        if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                        {
                            connection.AuthType = AuthType.Basic;
                            var credentials = new NetworkCredential(username, password, domain);
                            connection.Credential = credentials;
                            connection.Bind();
                            Log.Debug("[{CheckName}] Authenticated LDAP bind succeeded", Name);
                            return true;
                        }
                    }
                    
                    // Fallback to anonymous
                    connection.AuthType = AuthType.Anonymous;
                    connection.Bind();
                    Log.Debug("[{CheckName}] Anonymous LDAP bind succeeded", Name);
                    return true;
                }
                catch (LdapException ex)
                {
                    if (ex.ErrorCode == 49)
                    {
                        Log.Debug("[{CheckName}] LDAP bind failed: Invalid credentials", Name);
                    }
                    return false;
                }
            });
        }
        
        private Task<string?> GetDomainContextAsync(LdapConnection connection)
        {
            return Task.Run(() =>
            {
                try
                {
                    var searchRequest = new SearchRequest(
                        null,
                        "(objectClass=*)",
                        SearchScope.Base,
                        new[] { "defaultNamingContext" }
                    );
                    
                    var response = (SearchResponse)connection.SendRequest(searchRequest);
                    
                    if (response.Entries.Count > 0 && response.Entries[0].Attributes.Contains("defaultNamingContext"))
                    {
                        return response.Entries[0].Attributes["defaultNamingContext"][0].ToString();
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug(ex, "[{CheckName}] Failed to get domain context", Name);
                }
                
                return null;
            });
        }
        
        private Task EnumerateAsRepRoastableAccountsAsync(
            LdapConnection connection, 
            string domainContext, 
            KerberosInfo info,
            ScanOptions options)
        {
            return Task.Run(() =>
            {
                try
                {
                    Log.Debug("[{CheckName}] Searching for AS-REP roastable accounts in {Domain}", Name, domainContext);
                    
                    var filter = $"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={UF_DONT_REQUIRE_PREAUTH}))";
                    
                    var searchRequest = new SearchRequest(
                        domainContext,
                        filter,
                        SearchScope.Subtree,
                        new[] { "sAMAccountName" }
                    );
                    
                    if (options.Mode.ToLower() == "safe")
                    {
                        searchRequest.SizeLimit = 10;
                    }
                    
                    var response = (SearchResponse)connection.SendRequest(searchRequest);
                    
                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        if (entry.Attributes.Contains("sAMAccountName"))
                        {
                            var username = entry.Attributes["sAMAccountName"][0].ToString();
                            info.AsRepRoastableAccounts.Add(username!);
                        }
                    }
                    
                    if (info.AsRepRoastableAccounts.Count > 0)
                    {
                        Log.Warning("[{CheckName}] Found {Count} AS-REP roastable account(s)", Name, info.AsRepRoastableAccounts.Count);
                    }
                    else
                    {
                        Log.Debug("[{CheckName}] No AS-REP roastable accounts found", Name);
                    }
                }
                catch (DirectoryOperationException ex) when (
                    ex.Message.Contains("000004DC") || 
                    ex.Message.Contains("successful bind must be completed"))
                {
                    // Expected error when authentication is not provided
                    Log.Debug("[{CheckName}] AS-REP roasting check requires authentication", Name);
                }
                catch (LdapException ex) when (ex.ErrorCode == 1)
                {
                    // Operations error - typically means authentication required
                    Log.Debug("[{CheckName}] AS-REP roasting check requires authentication", Name);
                }
                catch (Exception ex)
                {
                    // Unexpected errors
                    Log.Debug(ex, "[{CheckName}] Unexpected error enumerating AS-REP roastable accounts", Name);
                }
            });
        }
        
        private Task CheckKerberosPolicyAsync(LdapConnection connection, string domainContext, KerberosInfo info)
        {
            return Task.Run(() =>
            {
                try
                {
                    Log.Debug("[{CheckName}] Checking Kerberos policy for {Domain}", Name, domainContext);
                    
                    var searchRequest = new SearchRequest(
                        domainContext,
                        "(objectClass=domainDNS)",
                        SearchScope.Base,
                        new[] { "maxTicketAge" }
                    );
                    
                    var response = (SearchResponse)connection.SendRequest(searchRequest);
                    
                    if (response.Entries.Count > 0)
                    {
                        var entry = response.Entries[0];
                        
                        if (entry.Attributes.Contains("maxTicketAge"))
                        {
                            var maxTicketAge = long.Parse(entry.Attributes["maxTicketAge"][0].ToString()!);
                            var hours = Math.Abs(maxTicketAge) / 10000000 / 3600;
                            info.MaxTicketAgeHours = hours;
                            
                            Log.Debug("[{CheckName}] Max ticket age: {Hours} hours", Name, hours);
                            
                            if (hours > 10)
                            {
                                info.WeakTicketLifetime = true;
                                info.TicketLifetimeIssue = $"Maximum ticket age is {hours} hours (default: 10, recommended: ≤10)";
                            }
                        }
                    }
                }
                catch (DirectoryOperationException ex) when (
                    ex.Message.Contains("000004DC") || 
                    ex.Message.Contains("successful bind must be completed"))
                {
                    // Expected error when authentication is not provided
                    Log.Debug("[{CheckName}] Kerberos policy check requires authentication", Name);
                }
                catch (LdapException ex) when (ex.ErrorCode == 1)
                {
                    // Operations error - typically means authentication required
                    Log.Debug("[{CheckName}] Kerberos policy check requires authentication", Name);
                }
                catch (Exception ex)
                {
                    // Unexpected errors should be logged with details
                    Log.Debug(ex, "[{CheckName}] Unexpected error checking Kerberos policy", Name);
                }
            });
        }
        
        private Task EnumerateSpnsAsync(LdapConnection connection, string domainContext, KerberosInfo info)
        {
            return Task.Run(() =>
            {
                try
                {
                    var filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))";
                    
                    var searchRequest = new SearchRequest(
                        domainContext,
                        filter,
                        SearchScope.Subtree,
                        new[] { "sAMAccountName" }
                    );
                    
                    searchRequest.SizeLimit = 50;
                    
                    var response = (SearchResponse)connection.SendRequest(searchRequest);
                    
                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        if (entry.Attributes.Contains("sAMAccountName"))
                        {
                            var username = entry.Attributes["sAMAccountName"][0].ToString();
                            
                            if (!username!.EndsWith("$") && username.ToLower() != "krbtgt")
                            {
                                info.KerberoastableAccounts.Add(username);
                            }
                        }
                    }
                    
                    if (info.KerberoastableAccounts.Count > 0)
                    {
                        Log.Warning("[{CheckName}] Found {Count} Kerberoastable account(s)", Name, info.KerberoastableAccounts.Count);
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug(ex, "[{CheckName}] Failed to enumerate SPNs", Name);
                }
            });
        }
        
        private Finding CreateAsRepRoastingFinding(string target, KerberosInfo info)
        {
            var accountList = string.Join(", ", info.AsRepRoastableAccounts.Take(10));
            if (info.AsRepRoastableAccounts.Count > 10)
            {
                accountList += $" ... and {info.AsRepRoastableAccounts.Count - 10} more";
            }
            
            return CreateFinding(
                id: "AST-KRB-001",
                title: "Kerberos account without preauthentication (AS-REP roastable)",
                severity: "high",
                recommendation: $"Remediate AS-REP roastable accounts:\n" +
                    "1. Enable Kerberos preauthentication: Uncheck 'Do not require Kerberos preauthentication' in AD.\n" +
                    "2. PowerShell: Set-ADUser -Identity <username> -DoesNotRequirePreAuth $false\n" +
                    "3. If preauthentication must remain disabled, enforce very strong passwords (20+ characters).\n" +
                    $"4. Accounts to remediate: {accountList}",
                description: $"The Active Directory domain has {info.AsRepRoastableAccounts.Count} user account(s) without preauthentication. " +
                    "This allows attackers to request AS-REP messages and crack passwords offline (AS-REP Roasting attack).",
                evidence: new Evidence
                {
                    Type = "ldap",
                    Value = $"Domain: {info.DomainContext}",
                    Context = $"AS-REP roastable accounts: {accountList}"
                },
                affectedComponent: $"Active Directory Domain: {info.DomainContext}"
            )
            .WithReferences(
                "https://attack.mitre.org/techniques/T1558/004/"
            );
        }
        
        private Finding CreateWeakTicketLifetimeFinding(string target, KerberosInfo info)
        {
            return CreateFinding(
                id: "AST-KRB-002",
                title: "Weak Kerberos ticket lifetime configuration",
                severity: "low",
                recommendation: $"Reduce Kerberos ticket lifetime:\n" +
                    "1. Via Group Policy: Set 'Maximum lifetime for user ticket' to 10 hours or less.\n" +
                    "2. Set 'Maximum lifetime for user ticket renewal' to 7 days or less.\n" +
                    "3. Balance security with user convenience.",
                description: $"The Active Directory domain has a Kerberos ticket lifetime that exceeds recommended values: {info.TicketLifetimeIssue}. " +
                    "Longer ticket lifetimes increase the window for ticket theft and replay attacks.",
                evidence: new Evidence
                {
                    Type = "ldap",
                    Value = $"Domain: {info.DomainContext}",
                    Context = $"Max ticket age: {info.MaxTicketAgeHours} hours"
                },
                affectedComponent: $"Active Directory Domain: {info.DomainContext}"
            )
            .WithReferences(
                "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-lifetime-for-user-ticket"
            );
        }
        
        private Finding CreateKerberoastingFinding(string target, KerberosInfo info)
        {
            var accountList = string.Join(", ", info.KerberoastableAccounts.Take(10));
            if (info.KerberoastableAccounts.Count > 10)
            {
                accountList += $" ... and {info.KerberoastableAccounts.Count - 10} more";
            }
            
            return CreateFinding(
                id: "AST-KRB-003",
                title: "Service accounts with SPNs vulnerable to Kerberoasting",
                severity: "high",
                recommendation: $"Mitigate Kerberoasting risk:\n" +
                    "1. Use Group Managed Service Accounts (gMSAs) with 120-character random passwords.\n" +
                    "2. For service accounts that must remain users, enforce very strong passwords (25+ characters).\n" +
                    "3. Regularly rotate service account passwords.\n" +
                    $"4. Accounts to review: {accountList}",
                description: $"The Active Directory domain has {info.KerberoastableAccounts.Count} user account(s) with Service Principal Names (SPNs). " +
                    "Any authenticated user can request Kerberos service tickets for these accounts and crack passwords offline (Kerberoasting attack).",
                evidence: new Evidence
                {
                    Type = "ldap",
                    Value = $"Domain: {info.DomainContext}",
                    Context = $"Service accounts with SPNs: {accountList}"
                },
                affectedComponent: $"Active Directory Domain: {info.DomainContext}"
            )
            .WithReferences(
                "https://attack.mitre.org/techniques/T1558/003/",
                "https://adsecurity.org/?p=2293"
            );
        }
    }
    
    internal class KerberosInfo
    {
        public string Host { get; set; } = string.Empty;
        public string? DomainContext { get; set; }
        public List<string> AsRepRoastableAccounts { get; set; } = new();
        public List<string> KerberoastableAccounts { get; set; } = new();
        public bool WeakTicketLifetime { get; set; }
        public string? TicketLifetimeIssue { get; set; }
        public long MaxTicketAgeHours { get; set; }
    }
}