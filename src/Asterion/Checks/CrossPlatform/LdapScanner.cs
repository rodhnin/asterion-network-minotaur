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
using AuthMgr = Asterion.Core.Utils.AuthenticationManager;

namespace Asterion.Checks.CrossPlatform
{
    /// <summary>
    /// LDAP / Active Directory Security Scanner
    /// 
    /// Detects:
    /// - AST-LDAP-001: LDAP anonymous bind allowed
    /// - AST-AD-001: LDAP signing not required by Domain Controller
    /// - AST-LDAP-002: LDAPS not available
    /// - AST-AD-002: Weak domain password policy
    /// - AST-AD-003: NTLMv1/LM authentication allowed
    /// - AST-AD-004: Accounts with password never expires
    /// - AST-AD-005: Account lockout policy disabled
    /// 
    /// Note: This scanner handles ALL authentication. KerberosScanner reuses auth state.
    /// </summary>
    public class LdapScanner : BaseCheck
    {
        private const int LDAP_PORT = 389;
        private const int LDAPS_PORT = 636;
        
        public override string Name => "LDAP/AD Scanner";
        public override CheckCategory Category => CheckCategory.CrossPlatform;
        public override string Description => 
            "Detects LDAP and Active Directory security issues including anonymous bind, missing LDAP signing, " +
            "LDAPS availability, and weak password policies";
        
        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;
        
        public LdapScanner(Config config) : base(config) { }
        
        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();
            
            var findings = new List<Finding>();
            
            if (!_config.Ldap.CheckAnonymousBind)
            {
                Log.Debug("LDAP anonymous bind check disabled in config");
                return findings;
            }
            
            Log.Information("Starting LDAP/AD security scan on {Count} target(s)", targets.Count);
            
            foreach (var target in targets)
            {
                try
                {
                    if (!await NetworkUtils.IsPortOpenAsync(target, LDAP_PORT, _config.Scan.Timeout.Connect * 1000))
                    {
                        Log.Debug("LDAP port {Port} not open on {Target}", LDAP_PORT, target);
                        continue;
                    }
                    
                    Log.Debug("LDAP port {Port} open on {Target}, probing...", LDAP_PORT, target);
                    
                    var ldapInfo = await AnalyzeLdapAsync(target, options);
                    
                    if (ldapInfo != null)
                    {
                        if (ldapInfo.AnonymousBindAllowed)
                            findings.Add(CreateAnonymousBindFinding(target, ldapInfo));
                        
                        if (!ldapInfo.LdapSigningRequired)
                            findings.Add(CreateNoSigningFinding(target, ldapInfo));
                        
                        if (!ldapInfo.LdapsAvailable && ldapInfo.IsDomainController)
                            findings.Add(CreateNoLdapsFinding(target, ldapInfo));
                        
                        if (ldapInfo.WeakPasswordPolicy)
                            findings.Add(CreateWeakPasswordPolicyFinding(target, ldapInfo));
                        
                        if (ldapInfo.LockoutDisabled)
                            findings.Add(CreateLockoutDisabledFinding(target, ldapInfo));
                        
                        if (ldapInfo.PasswordNeverExpiresAccounts.Any())
                            findings.Add(CreatePasswordNeverExpiresFinding(target, ldapInfo));
                        
                        if (ldapInfo.NTLMv1Allowed)
                            findings.Add(CreateNTLMv1AllowedFinding(target, ldapInfo));
                    }
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "Failed to scan LDAP on {Target}", target);
                }
            }
            
            LogExecution(targets.Count, findings.Count);
            return findings;
        }
        
        private async Task<LdapInfo?> AnalyzeLdapAsync(string host, ScanOptions options)
        {
            var info = new LdapInfo { Host = host };
            var authManager = new AuthMgr();
            
            try
            {
                // Phase 1: Anonymous bind test (always run)
                using (var anonConnection = new LdapConnection(new LdapDirectoryIdentifier(host, LDAP_PORT)))
                {
                    anonConnection.Timeout = TimeSpan.FromSeconds(_config.Ldap.TimeoutSeconds);
                    anonConnection.AuthType = AuthType.Anonymous;
                    
                    try
                    {
                        anonConnection.Bind();
                        Log.Debug("Anonymous LDAP bind succeeded on {Host}", host);
                        
                        bool canQueryAnonymously = false;
                        try
                        {
                            var testRequest = new SearchRequest(
                                null,
                                "(objectClass=*)",
                                SearchScope.Base,
                                new[] { "defaultNamingContext" }
                            );
                            
                            var testResponse = (SearchResponse)anonConnection.SendRequest(testRequest);
                            
                            if (testResponse != null && testResponse.Entries.Count > 0)
                            {
                                canQueryAnonymously = true;
                                Log.Debug("Anonymous LDAP query succeeded on {Host} - anonymous bind is TRULY allowed", host);
                            }
                        }
                        catch (DirectoryOperationException ex) when (
                            ex.Message.Contains("000004DC") || 
                            ex.Message.Contains("successful bind must be completed") ||
                            ex.Message.Contains("Operations error"))
                        {
                            canQueryAnonymously = false;
                            Log.Debug("Anonymous LDAP bind succeeded but queries are BLOCKED on {Host}", host);
                        }
                        catch (LdapException ex) when (ex.ErrorCode == 1)
                        {
                            canQueryAnonymously = false;
                            Log.Debug("Anonymous LDAP queries blocked on {Host}", host);
                        }
                        
                        info.AnonymousBindAllowed = canQueryAnonymously;
                        
                        if (canQueryAnonymously)
                        {
                            ReadRootDse(anonConnection, info);
                        }
                    }
                    catch (LdapException ex)
                    {
                        if (ex.ErrorCode == 49)
                        {
                            info.AnonymousBindAllowed = false;
                            Log.Debug("Anonymous LDAP bind denied on {Host}", host);
                        }
                        else
                        {
                            Log.Debug(ex, "LDAP bind failed on {Host}: {Error}", host, ex.Message);
                        }
                    }
                }
                
                // Phase 2: Authenticated bind
                bool authenticated = await TryAuthenticatedBindAsync(host, options, authManager, info);
                
                // Phase 3: Check LDAP signing and LDAPS
                info.LdapSigningRequired = await CheckLdapSigningAsync(host, options);
                info.LdapsAvailable = await NetworkUtils.IsPortOpenAsync(host, LDAPS_PORT, _config.Scan.Timeout.Connect * 1000);
                
                return info;
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "LDAP analysis failed on {Host}", host);
                return null;
            }
        }
        
        private async Task<bool> TryAuthenticatedBindAsync(string host, ScanOptions options, AuthMgr authManager, LdapInfo info)
        {
            // Option 1: Kerberos credentials
            if (!string.IsNullOrEmpty(options.KerberosCredentials))
            {
                var (username, password, realm) = authManager.ParseKerberosCredentials(options.KerberosCredentials);
                
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password) && !string.IsNullOrEmpty(realm))
                {
                    return await TryKerberosBindAsync(host, username, password, realm, info);
                }
            }
            
            // Option 2: Standard credentials
            if (!string.IsNullOrEmpty(options.AuthCredentials))
            {
                var (username, password, domain) = authManager.ParseCredentials(options.AuthCredentials);
                
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    return await TryBasicBindAsync(host, username, password, domain, info);
                }
            }
            
            // Option 3: NTLM hash (not supported for LDAP)
            if (!string.IsNullOrEmpty(options.AuthNtlm))
            {
                var (ntlmUser, _) = authManager.ParseNtlmCredentials(options.AuthNtlm);
                
                Log.Information("[{CheckName}] NTLM authentication mode detected", Name);
                Log.Information("[{CheckName}] NTLM pass-the-hash works for SMB but NOT for LDAP/Kerberos protocols", Name);
                Log.Information("[{CheckName}] LDAP Scanner will run in anonymous/unauthenticated mode", Name);
                Log.Information("[{CheckName}] For full AD enumeration, use: --auth \"{User}:PASSWORD\"", 
                    Name, ntlmUser ?? "DOMAIN\\user");
                
                Log.Debug("[{CheckName}] Technical: LDAP protocol requires plaintext password or Kerberos ticket, not NTLM hash", Name);
            }
            
            return false;
        }
        
        private async Task<bool> TryKerberosBindAsync(string host, string username, string password, string realm, LdapInfo info)
        {
            return await Task.Run(() =>
            {
                try
                {
                    using (var connection = new LdapConnection(new LdapDirectoryIdentifier(host, LDAP_PORT)))
                    {
                        connection.Timeout = TimeSpan.FromSeconds(_config.Ldap.TimeoutSeconds);
                        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                        
                        bool isLinux = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                            System.Runtime.InteropServices.OSPlatform.Linux);
                        
                        if (isLinux)
                        {
                            // Linux cross-platform authentication limitations
                            Log.Warning("[{CheckName}] ⚠️  Linux to Windows AD: Kerberos requires system configuration", Name);
                            Log.Information("[{CheckName}] Recommended: Use --auth \"{User}:{Password}\" for cross-platform authentication", 
                                Name, username, password);
                            Log.Information("[{CheckName}] Auto-fallback: Using Basic authentication (username/password)", Name);
                            Log.Debug("[{CheckName}] Technical: .NET on Linux lacks native GSSAPI for cross-platform Kerberos", Name);
                            
                            connection.AuthType = AuthType.Basic;
                        }
                        else
                        {
                            connection.AuthType = AuthType.Kerberos;
                        }
                        
                        var credentials = new NetworkCredential(username, password, realm);
                        connection.Credential = credentials;
                        
                        connection.Bind();
                        
                        Log.Information("[{CheckName}] Authentication successful: {Realm}\\{User}", Name, realm, username);
                        
                        if (string.IsNullOrEmpty(info.DefaultNamingContext))
                        {
                            ReadRootDse(connection, info);
                        }
                        
                        if (info.IsDomainController && !string.IsNullOrEmpty(info.DefaultNamingContext))
                        {
                            ReadPasswordPolicy(connection, info);
                            CheckPasswordNeverExpires(connection, info);
                        }
                        
                        return true;
                    }
                }
                catch (LdapException ex)
                {
                    if (ex.ErrorCode == 49)
                    {
                        Log.Warning("[{CheckName}] Authentication failed on {Host}: Invalid credentials", Name, host);
                    }
                    else
                    {
                        Log.Debug(ex, "[{CheckName}] Authentication failed on {Host}", Name, host);
                    }
                    return false;
                }
            });
        }
        
        private async Task<bool> TryBasicBindAsync(string host, string username, string password, string? domain, LdapInfo info)
        {
            return await Task.Run(() =>
            {
                try
                {
                    using (var connection = new LdapConnection(new LdapDirectoryIdentifier(host, LDAP_PORT)))
                    {
                        connection.Timeout = TimeSpan.FromSeconds(_config.Ldap.TimeoutSeconds);
                        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                        connection.AuthType = AuthType.Basic;
                        
                        var credentials = new NetworkCredential(username, password, domain);
                        connection.Credential = credentials;
                        
                        connection.Bind();
                        
                        Log.Debug("[{CheckName}] Authenticated LDAP bind succeeded on {Host}", Name, host);
                        
                        if (string.IsNullOrEmpty(info.DefaultNamingContext))
                        {
                            ReadRootDse(connection, info);
                        }
                        
                        if (info.IsDomainController && !string.IsNullOrEmpty(info.DefaultNamingContext))
                        {
                            ReadPasswordPolicy(connection, info);
                            CheckPasswordNeverExpires(connection, info);
                        }
                        
                        return true;
                    }
                }
                catch (LdapException ex)
                {
                    if (ex.ErrorCode == 49)
                    {
                        Log.Warning("[{CheckName}] Authenticated LDAP bind failed on {Host}: Invalid credentials", Name, host);
                    }
                    return false;
                }
            });
        }
        
        private void ReadRootDse(LdapConnection connection, LdapInfo info)
        {
            try
            {
                var searchRequest = new SearchRequest(
                    null,
                    "(objectClass=*)",
                    SearchScope.Base,
                    new[] { "defaultNamingContext", "dnsHostName", "rootDomainNamingContext" }
                );
                
                var response = (SearchResponse)connection.SendRequest(searchRequest);
                
                if (response.Entries.Count > 0)
                {
                    var entry = response.Entries[0];
                    
                    if (entry.Attributes.Contains("defaultNamingContext"))
                    {
                        info.IsDomainController = true;
                        info.DefaultNamingContext = entry.Attributes["defaultNamingContext"][0].ToString();
                        Log.Debug("Detected Domain Controller: {Context}", info.DefaultNamingContext);
                    }
                    
                    if (entry.Attributes.Contains("dnsHostName"))
                    {
                        info.DnsHostName = entry.Attributes["dnsHostName"][0].ToString();
                    }
                    
                    if (entry.Attributes.Contains("rootDomainNamingContext"))
                    {
                        info.RootDomainNamingContext = entry.Attributes["rootDomainNamingContext"][0].ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Failed to read RootDSE");
            }
        }
        
        private void ReadPasswordPolicy(LdapConnection connection, LdapInfo info)
        {
            try
            {
                var searchRequest = new SearchRequest(
                    info.DefaultNamingContext,
                    "(objectClass=domainDNS)",
                    SearchScope.Base,
                    new[] { "minPwdLength", "pwdProperties", "maxPwdAge", "minPwdAge", 
                            "lockoutThreshold", "msDS-SupportedEncryptionTypes" }
                );
                
                var response = (SearchResponse)connection.SendRequest(searchRequest);
                
                if (response.Entries.Count > 0)
                {
                    var entry = response.Entries[0];
                    
                    // Min password length
                    if (entry.Attributes.Contains("minPwdLength"))
                    {
                        var raw = entry.Attributes["minPwdLength"][0]?.ToString();
                        if (int.TryParse(raw, out var minLength))
                        {
                            info.MinPasswordLength = minLength;
                            if (minLength < 8)
                            {
                                info.WeakPasswordPolicy = true;
                                info.PasswordPolicyIssue = $"Minimum password length is {minLength} (recommended: 8+)";
                            }
                        }
                    }
                    
                    // Password complexity
                    if (entry.Attributes.Contains("pwdProperties"))
                    {
                        var rawProps = entry.Attributes["pwdProperties"][0]?.ToString();
                        if (int.TryParse(rawProps, out var pwdProps))
                        {
                            if ((pwdProps & 0x01) == 0)
                            {
                                info.WeakPasswordPolicy = true;
                                info.PasswordPolicyIssue = "Password complexity requirements disabled";
                            }
                        }
                    }
                    
                    // Lockout threshold
                    if (entry.Attributes.Contains("lockoutThreshold"))
                    {
                        var rawLockout = entry.Attributes["lockoutThreshold"][0]?.ToString();
                        if (int.TryParse(rawLockout, out var lockoutThreshold))
                        {
                            info.LockoutThreshold = lockoutThreshold;
                            if (lockoutThreshold == 0)
                            {
                                info.LockoutDisabled = true;
                                Log.Debug("[{CheckName}] Account lockout policy is DISABLED", Name);
                            }
                        }
                    }
                    
                    // NTLMv1 check
                    if (entry.Attributes.Contains("msDS-SupportedEncryptionTypes"))
                    {
                        var rawEncTypes = entry.Attributes["msDS-SupportedEncryptionTypes"][0]?.ToString();
                        if (int.TryParse(rawEncTypes, out var encTypes))
                        {
                            // 0x04 = RC4_HMAC (NTLMv1/LM)
                            // 0x18 = AES128 + AES256
                            if ((encTypes & 0x04) != 0 || (encTypes & 0x18) == 0)
                            {
                                info.NTLMv1Allowed = true;
                                Log.Debug("[{CheckName}] NTLMv1/RC4 encryption may be allowed", Name);
                            }
                        }
                    }
                }
            }
            catch (DirectoryOperationException ex) when (
                ex.Message.Contains("000004DC") || 
                ex.Message.Contains("successful bind must be completed"))
            {
                Log.Debug("[{CheckName}] Password policy check requires authentication", Name);
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] Error reading password policy", Name);
            }
        }
        
        private void CheckPasswordNeverExpires(LdapConnection connection, LdapInfo info)
        {
            try
            {
                var filter = "(userAccountControl:1.2.840.113556.1.4.803:=65536)";
                
                var searchRequest = new SearchRequest(
                    info.DefaultNamingContext,
                    filter,
                    SearchScope.Subtree,
                    new[] { "sAMAccountName" }
                );
                
                searchRequest.SizeLimit = 100;
                
                var response = (SearchResponse)connection.SendRequest(searchRequest);
                
                foreach (SearchResultEntry entry in response.Entries)
                {
                    if (entry.Attributes.Contains("sAMAccountName"))
                    {
                        var username = entry.Attributes["sAMAccountName"][0]?.ToString();
                        if (!string.IsNullOrEmpty(username))
                        {
                            info.PasswordNeverExpiresAccounts.Add(username);
                        }
                    }
                }
                
                if (info.PasswordNeverExpiresAccounts.Count > 0)
                {
                    Log.Information("[{CheckName}] Found {Count} accounts with password never expires", 
                        Name, info.PasswordNeverExpiresAccounts.Count);
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] Error checking password never expires", Name);
            }
        }
        
        private Task<bool> CheckLdapSigningAsync(string host, ScanOptions options)
        {
            try
            {
                using (var connection = new LdapConnection(new LdapDirectoryIdentifier(host, LDAP_PORT)))
                {
                    connection.Timeout = TimeSpan.FromSeconds(_config.Ldap.TimeoutSeconds);
                    connection.AuthType = AuthType.Basic;
                    
                    if (!string.IsNullOrEmpty(options.AuthCredentials))
                    {
                        var (username, password, domain) = ParseCredentials(options.AuthCredentials);
                        
                        if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                        {
                            var credentials = new NetworkCredential(username, password, domain);
                            connection.Credential = credentials;
                            
                            try
                            {
                                connection.Bind();
                                Log.Debug("LDAP bind without signing succeeded on {Host}", host);
                                return Task.FromResult(false);
                            }
                            catch (LdapException ex)
                            {
                                if (ex.Message.Contains("signing"))
                                {
                                    return Task.FromResult(true);
                                }
                            }
                        }
                    }
                    
                    return Task.FromResult(false);
                }
            }
            catch
            {
                return Task.FromResult(true);
            }
        }
        
        // Finding creation methods (unchanged)
        private Finding CreateAnonymousBindFinding(string target, LdapInfo info)
        {
            var context = info.IsDomainController 
                ? $"Domain Controller: {info.DnsHostName ?? target}, Domain: {info.DefaultNamingContext}"
                : $"LDAP Server: {target}";
            
            return CreateFinding(
                id: "AST-LDAP-001",
                title: "LDAP anonymous bind and queries allowed",
                severity: "high",
                recommendation: $"Disable anonymous LDAP bind on {target}:\n" +
                    "1. Via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options\n" +
                    "2. Set 'Network access: Allow anonymous SID/Name translation' to Disabled.\n" +
                    "3. Set LDAP server option: dsHeuristics to enable anonymous bind restrictions.\n" +
                    "4. Restart LDAP service after changes.",
                description: $"The LDAP server on {target} allows anonymous (unauthenticated) bind operations AND permits directory queries without credentials. " +
                    "This configuration allows attackers to query the directory and enumerate users, groups, computers, and other objects without credentials.",
                evidence: new Evidence
                {
                    Type = "service",
                    Value = $"Host {target} - Anonymous bind succeeded AND queries allowed",
                    Context = context
                },
                affectedComponent: info.IsDomainController ? $"Domain Controller: {target}" : $"LDAP Server: {target}"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-allow-anonymous-sidname-translation"
            );
        }
        
        private Finding CreateNoSigningFinding(string target, LdapInfo info)
        {
            var dcName = info.DnsHostName ?? target;
            return CreateFinding(
                id: "AST-AD-001",
                title: "LDAP signing not required by Domain Controller",
                severity: "high",
                recommendation: $"Enable LDAP signing on all domain controllers:\n" +
                    "1. Via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options\n" +
                    "2. Set 'Domain controller: LDAP server signing requirements' to 'Require signature'.\n" +
                    "3. Ensure LDAP clients are configured to use signing or LDAPS.",
                description: $"The Active Directory domain controller '{dcName}' ({target}) does not require LDAP signing. " +
                    "This allows unsigned LDAP queries which are vulnerable to man-in-the-middle tampering.",
                evidence: new Evidence
                {
                    Type = "config",
                    Value = $"Domain Controller LDAP Signing: Not required",
                    Context = $"LDAP bind without signing succeeded on {dcName}"
                },
                affectedComponent: $"Domain Controller {dcName}"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements",
                "https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a"
            )
            .WithCve("CVE-2017-8563");
        }
        
        private Finding CreateNoLdapsFinding(string target, LdapInfo info)
        {
            return CreateFinding(
                id: "AST-LDAP-002",
                title: "LDAPS (LDAP over SSL) not available",
                severity: "medium",
                recommendation: $"Enable LDAPS on domain controller {target}:\n" +
                    "1. Install a certificate on the domain controller (from trusted CA or internal PKI).\n" +
                    "2. The certificate must have 'Server Authentication' EKU and include the DC's hostname in SAN.\n" +
                    "3. LDAPS will automatically enable once a valid certificate is installed.",
                description: $"The domain controller on {target} does not have LDAPS (port {LDAPS_PORT}) enabled. " +
                    "While LDAP signing can protect integrity, LDAPS (LDAP over TLS/SSL) provides both confidentiality and integrity.",
                evidence: new Evidence
                {
                    Type = "port",
                    Value = $"Host {target} - LDAPS port {LDAPS_PORT} not open",
                    Context = "LDAP (389) is available but LDAPS (636) is not"
                },
                affectedComponent: $"Domain Controller {target}"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority"
            );
        }
        
        private Finding CreateWeakPasswordPolicyFinding(string target, LdapInfo info)
        {
            return CreateFinding(
                id: "AST-AD-002",
                title: "Weak domain password policy",
                severity: "medium",
                recommendation: $"Strengthen domain password policy:\n" +
                    "1. Set minimum password length to at least 8 characters (12+ recommended).\n" +
                    "2. Enable password complexity requirements.\n" +
                    "3. Configure account lockout policy (5 failed attempts, 30-minute lockout).",
                description: $"The Active Directory domain has a weak password policy: {info.PasswordPolicyIssue}. " +
                    "Weak password policies make it easier for attackers to compromise user accounts.",
                evidence: new Evidence
                {
                    Type = "config",
                    Value = $"Domain: {info.DefaultNamingContext}",
                    Context = $"Password policy issue: {info.PasswordPolicyIssue}"
                },
                affectedComponent: $"Domain: {info.DefaultNamingContext}"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy"
            );
        }
        
        private Finding CreateLockoutDisabledFinding(string target, LdapInfo info)
        {
            return CreateFinding(
                id: "AST-AD-005",
                title: "Account lockout policy disabled",
                severity: "medium",
                recommendation: $"Enable account lockout policy:\n" +
                    "1. Set 'Account lockout threshold' to 5-10 invalid logon attempts.\n" +
                    "2. Set 'Account lockout duration' to 30 minutes.\n" +
                    "3. Set 'Reset account lockout counter after' to 30 minutes.",
                description: $"The Active Directory domain has account lockout policy disabled (threshold: {info.LockoutThreshold}). " +
                    "This allows unlimited password guessing attempts, making brute force attacks trivial.",
                evidence: new Evidence
                {
                    Type = "config",
                    Value = $"Domain: {info.DefaultNamingContext}",
                    Context = $"Lockout threshold: {info.LockoutThreshold} (0 = unlimited)"
                },
                affectedComponent: $"Domain: {info.DefaultNamingContext}"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold"
            );
        }
        
        private Finding CreatePasswordNeverExpiresFinding(string target, LdapInfo info)
        {
            var accountList = string.Join(", ", info.PasswordNeverExpiresAccounts.Take(10));
            if (info.PasswordNeverExpiresAccounts.Count > 10)
            {
                accountList += $", ... and {info.PasswordNeverExpiresAccounts.Count - 10} more";
            }
            
            return CreateFinding(
                id: "AST-AD-004",
                title: $"Accounts with password set to never expire ({info.PasswordNeverExpiresAccounts.Count} found)",
                severity: "medium",
                recommendation: $"Remove 'Password never expires' flag:\n" +
                    "1. Review each account: Get-ADUser -Filter 'PasswordNeverExpires -eq $true'\n" +
                    "2. For service accounts: Use Group Managed Service Accounts (gMSAs).\n" +
                    "3. For user accounts: Set-ADUser -Identity <username> -PasswordNeverExpires $false",
                description: $"Found {info.PasswordNeverExpiresAccounts.Count} Active Directory accounts with 'Password never expires' flag set. " +
                    "This violates security best practices and creates long-term credential risks. " +
                    "Affected accounts include: " + accountList,
                evidence: new Evidence
                {
                    Type = "config",
                    Value = $"Domain: {info.DefaultNamingContext}",
                    Context = $"{info.PasswordNeverExpiresAccounts.Count} accounts: {accountList}"
                },
                affectedComponent: $"Domain: {info.DefaultNamingContext}"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age"
            );
        }
        
        private Finding CreateNTLMv1AllowedFinding(string target, LdapInfo info)
        {
            return CreateFinding(
                id: "AST-AD-003",
                title: "NTLMv1/LM authentication may be allowed",
                severity: "high",
                recommendation: $"Disable NTLMv1 and LM authentication:\n" +
                    "1. Via Group Policy: Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only'.\n" +
                    "2. Set 'Minimum session security for NTLM SSP' to 'Require NTLMv2 session security'.\n" +
                    "3. Test with applications before enforcing.",
                description: $"The Active Directory domain appears to allow NTLMv1 or LM authentication. " +
                    "NTLMv1 and LM are legacy authentication protocols with critical security flaws including pass-the-hash and relay attacks.",
                evidence: new Evidence
                {
                    Type = "config",
                    Value = $"Domain: {info.DefaultNamingContext}",
                    Context = "Encryption types suggest NTLMv1/RC4 may be allowed"
                },
                affectedComponent: $"Domain: {info.DefaultNamingContext}"
            )
            .WithReferences(
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"
            )
            .WithCve("CVE-2019-1040");
        }
    }
    
    internal class LdapInfo
    {
        public string Host { get; set; } = string.Empty;
        public bool AnonymousBindAllowed { get; set; }
        public bool LdapSigningRequired { get; set; }
        public bool LdapsAvailable { get; set; }
        public bool IsDomainController { get; set; }
        public string? DnsHostName { get; set; }
        public string? DefaultNamingContext { get; set; }
        public string? RootDomainNamingContext { get; set; }
        public bool WeakPasswordPolicy { get; set; }
        public string? PasswordPolicyIssue { get; set; }
        public int MinPasswordLength { get; set; }
        public int LockoutThreshold { get; set; } = -1;
        public bool LockoutDisabled { get; set; }
        public List<string> PasswordNeverExpiresAccounts { get; set; } = new List<string>();
        public bool NTLMv1Allowed { get; set; }
    }
}