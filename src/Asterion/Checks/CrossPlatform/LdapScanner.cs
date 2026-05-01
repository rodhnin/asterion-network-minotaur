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

                        // LDAP-ADV findings
                        if (ldapInfo.UnconstrainedDelegationAccounts.Any())
                            findings.Add(CreateUnconstrainedDelegationFinding(target, ldapInfo));

                        if (ldapInfo.AdminCountAccounts.Any())
                            findings.Add(CreateAdminCountFinding(target, ldapInfo));

                        if (ldapInfo.LapsNotDeployed && ldapInfo.IsDomainController)
                            findings.Add(CreateLapsNotDeployedFinding(target, ldapInfo));

                        if (ldapInfo.DomainTrusts.Any())
                            findings.Add(CreateDomainTrustsFinding(target, ldapInfo));
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
                            
                            connection.AuthType = AuthType.Negotiate;
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
                            CheckUnconstrainedDelegation(connection, info);
                            CheckAdminCountAccounts(connection, info);
                            CheckLapsDeployment(connection, info);
                            CheckDomainTrusts(connection, info);
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
                        connection.AuthType = AuthType.Negotiate;
                        
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

        // ─── LDAP-ADV checks (v0.2.0) ────────────────────────────────────────

        /// <summary>
        /// Enumerate accounts/computers with unconstrained Kerberos delegation.
        /// UAC flag TRUSTED_FOR_DELEGATION (0x80000 = 524288).
        /// Domain Controllers are expected to have this flag — excluded.
        /// </summary>
        private void CheckUnconstrainedDelegation(LdapConnection connection, LdapInfo info)
        {
            try
            {
                // Exclude DCs (primaryGroupID=516) and KRBTGT
                var filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)" +
                             "(!(primaryGroupID=516))(!(sAMAccountName=krbtgt)))";
                var req = new SearchRequest(
                    info.DefaultNamingContext,
                    filter,
                    SearchScope.Subtree,
                    new[] { "sAMAccountName", "objectClass" }
                );
                req.SizeLimit = 200;

                var resp = (SearchResponse)connection.SendRequest(req);
                foreach (SearchResultEntry entry in resp.Entries)
                {
                    var sam = entry.Attributes.Contains("sAMAccountName")
                        ? entry.Attributes["sAMAccountName"][0]?.ToString()
                        : null;
                    if (!string.IsNullOrEmpty(sam))
                        info.UnconstrainedDelegationAccounts.Add(sam);
                }

                if (info.UnconstrainedDelegationAccounts.Any())
                    Log.Warning("[{CheckName}] {Count} account(s) with unconstrained delegation",
                        Name, info.UnconstrainedDelegationAccounts.Count);
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] CheckUnconstrainedDelegation failed", Name);
            }
        }

        /// <summary>
        /// Enumerate accounts protected by AdminSDHolder (adminCount=1).
        /// Includes user accounts only (groups and built-ins excluded for brevity).
        /// </summary>
        private void CheckAdminCountAccounts(LdapConnection connection, LdapInfo info)
        {
            try
            {
                var filter = "(&(adminCount=1)(objectCategory=person)(objectClass=user))";
                var req = new SearchRequest(
                    info.DefaultNamingContext,
                    filter,
                    SearchScope.Subtree,
                    new[] { "sAMAccountName" }
                );
                req.SizeLimit = 300;

                var resp = (SearchResponse)connection.SendRequest(req);
                foreach (SearchResultEntry entry in resp.Entries)
                {
                    var sam = entry.Attributes.Contains("sAMAccountName")
                        ? entry.Attributes["sAMAccountName"][0]?.ToString()
                        : null;
                    if (!string.IsNullOrEmpty(sam))
                        info.AdminCountAccounts.Add(sam);
                }

                Log.Debug("[{CheckName}] adminCount=1 accounts: {Count}", Name, info.AdminCountAccounts.Count);
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] CheckAdminCountAccounts failed", Name);
            }
        }

        /// <summary>
        /// Check if LAPS (Local Administrator Password Solution) is deployed.
        /// Detection: search for computers that have the ms-Mcs-AdmPwd attribute schema entry.
        /// If the attribute doesn't exist in schema, LAPS is not deployed at all.
        /// If it exists but no computers have it, LAPS may be partially deployed.
        /// </summary>
        private void CheckLapsDeployment(LdapConnection connection, LdapInfo info)
        {
            try
            {
                // Check if LAPS attribute exists in schema
                var schemaReq = new SearchRequest(
                    $"CN=Schema,CN=Configuration,{info.RootDomainNamingContext ?? info.DefaultNamingContext}",
                    "(lDAPDisplayName=ms-Mcs-AdmPwd)",
                    SearchScope.OneLevel,
                    new[] { "lDAPDisplayName" }
                );
                schemaReq.SizeLimit = 1;

                var schemaResp = (SearchResponse)connection.SendRequest(schemaReq);
                if (schemaResp.Entries.Count == 0)
                {
                    // LAPS schema extension not present
                    info.LapsNotDeployed = true;
                    Log.Warning("[{CheckName}] LAPS schema attribute ms-Mcs-AdmPwd not found — LAPS not deployed", Name);
                    return;
                }

                // Schema present — check if any computers have the password set
                var compReq = new SearchRequest(
                    info.DefaultNamingContext,
                    "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))",
                    SearchScope.Subtree,
                    new[] { "sAMAccountName" }
                );
                compReq.SizeLimit = 1;
                var compResp = (SearchResponse)connection.SendRequest(compReq);
                if (compResp.Entries.Count == 0)
                {
                    // Schema present but no machines managed — effectively not deployed
                    info.LapsNotDeployed = true;
                    Log.Warning("[{CheckName}] LAPS schema present but no computers managed by LAPS", Name);
                }
            }
            catch (DirectoryOperationException ex) when (ex.Message.Contains("noSuchAttribute") ||
                                                          ex.Message.Contains("0000208D"))
            {
                // Schema path not accessible or attribute unknown — assume not deployed
                info.LapsNotDeployed = true;
                Log.Debug("[{CheckName}] LAPS schema query returned noSuchAttribute — not deployed", Name);
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] CheckLapsDeployment failed", Name);
            }
        }

        /// <summary>
        /// Enumerate domain trusts via LDAP (CN=System container).
        /// </summary>
        private void CheckDomainTrusts(LdapConnection connection, LdapInfo info)
        {
            try
            {
                var systemDn = $"CN=System,{info.DefaultNamingContext}";
                var req = new SearchRequest(
                    systemDn,
                    "(objectClass=trustedDomain)",
                    SearchScope.OneLevel,
                    new[] { "name", "trustDirection", "trustType" }
                );
                req.SizeLimit = 100;

                var resp = (SearchResponse)connection.SendRequest(req);
                foreach (SearchResultEntry entry in resp.Entries)
                {
                    var name = entry.Attributes.Contains("name")
                        ? entry.Attributes["name"][0]?.ToString() ?? "unknown"
                        : "unknown";

                    var dirRaw = entry.Attributes.Contains("trustDirection")
                        ? entry.Attributes["trustDirection"][0]?.ToString()
                        : null;
                    var direction = int.TryParse(dirRaw, out var d) ? d switch
                    {
                        1 => "Inbound",
                        2 => "Outbound",
                        3 => "Bidirectional",
                        _ => "Unknown"
                    } : "Unknown";

                    var typeRaw = entry.Attributes.Contains("trustType")
                        ? entry.Attributes["trustType"][0]?.ToString()
                        : null;
                    var trustType = int.TryParse(typeRaw, out var t) ? t switch
                    {
                        1 => "Windows Non-Active Directory",
                        2 => "Active Directory",
                        3 => "MIT Kerberos",
                        4 => "DCE",
                        _ => "Unknown"
                    } : "Unknown";

                    info.DomainTrusts.Add((name, direction, trustType));
                    Log.Information("[{CheckName}] Domain trust: {Name} ({Type}, {Dir})", Name, name, trustType, direction);
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] CheckDomainTrusts failed", Name);
            }
        }

        // ─── LDAP-ADV findings ────────────────────────────────────────────────

        private Finding CreateUnconstrainedDelegationFinding(string target, LdapInfo info)
        {
            var accounts = string.Join(", ", info.UnconstrainedDelegationAccounts.Take(15));
            if (info.UnconstrainedDelegationAccounts.Count > 15)
                accounts += $" (+{info.UnconstrainedDelegationAccounts.Count - 15} more)";

            return CreateFinding(
                id: "AST-AD-011",
                title: $"Unconstrained Kerberos delegation enabled ({info.UnconstrainedDelegationAccounts.Count} account(s))",
                severity: "high",
                recommendation:
                    "Migrate from unconstrained to constrained delegation (KCD) or resource-based constrained delegation (RBCD):\n" +
                    "1. Identify accounts: Get-ADComputer -Filter {TrustedForDelegation -eq $true}\n" +
                    "2. For service accounts: set msDS-AllowedToDelegateTo instead of full trust.\n" +
                    "3. Enable Protected Users group for sensitive accounts.\n" +
                    "4. Consider 'Account is sensitive and cannot be delegated' flag on admin accounts.",
                description:
                    $"Found {info.UnconstrainedDelegationAccounts.Count} account(s) with unconstrained Kerberos delegation (TRUSTED_FOR_DELEGATION). " +
                    "If any of these services is compromised, an attacker can extract Kerberos TGTs cached by the service for ANY domain user, " +
                    "enabling full domain compromise (printer bug / SpoolSample attack).",
                evidence: new Evidence
                {
                    Type = "ldap",
                    Value = $"Accounts with TRUSTED_FOR_DELEGATION: {accounts}",
                    Context = $"Domain: {info.DefaultNamingContext} | LDAP filter: userAccountControl:TRUSTED_FOR_DELEGATION"
                },
                affectedComponent: $"Domain: {info.DefaultNamingContext}"
            )
            .WithReferences(
                "https://attack.mitre.org/techniques/T1558/",
                "https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
            );
        }

        private Finding CreateAdminCountFinding(string target, LdapInfo info)
        {
            var accounts = string.Join(", ", info.AdminCountAccounts.Take(20));
            if (info.AdminCountAccounts.Count > 20)
                accounts += $" (+{info.AdminCountAccounts.Count - 20} more)";

            return CreateFinding(
                id: "AST-AD-013",
                title: $"AdminSDHolder-protected accounts ({info.AdminCountAccounts.Count}) — ACL inheritance disabled",
                severity: "medium",
                recommendation:
                    "Review the list of privileged accounts and reduce attack surface:\n" +
                    "1. List: Get-ADUser -Filter {adminCount -eq 1} | Select sAMAccountName\n" +
                    "2. Remove from privileged groups any account that no longer needs access.\n" +
                    "3. For service accounts: use Group Managed Service Accounts (gMSA).\n" +
                    "4. Reset adminCount to 0 for removed accounts: Set-ADUser -Identity X -Replace @{adminCount=0}",
                description:
                    $"Found {info.AdminCountAccounts.Count} user accounts with adminCount=1, indicating they are or were members of privileged groups " +
                    "(Domain Admins, Enterprise Admins, etc.). AdminSDHolder disables ACL inheritance for these accounts, which can hide " +
                    "malicious permission grants and complicates security auditing.",
                evidence: new Evidence
                {
                    Type = "ldap",
                    Value = $"adminCount=1 user accounts: {accounts}",
                    Context = $"Domain: {info.DefaultNamingContext} | LDAP filter: (adminCount=1)(objectCategory=person)"
                },
                affectedComponent: $"Domain: {info.DefaultNamingContext}"
            )
            .WithReferences(
                "https://attack.mitre.org/techniques/T1078/002/",
                "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"
            );
        }

        private Finding CreateLapsNotDeployedFinding(string target, LdapInfo info)
        {
            return CreateFinding(
                id: "AST-AD-015",
                title: "LAPS (Local Administrator Password Solution) not deployed",
                severity: "medium",
                recommendation:
                    "Deploy Microsoft LAPS or Windows LAPS (built-in since Windows Server 2022/Windows 11):\n" +
                    "1. Download LAPS from Microsoft and extend the AD schema.\n" +
                    "2. Install the LAPS GPO on all workstations and servers.\n" +
                    "3. Set password complexity, length and expiration via GPO.\n" +
                    "4. Restrict ms-Mcs-AdmPwd read permissions to IT admins only.\n" +
                    "5. Windows LAPS (KB5025175): Configure via 'Local Administrator Password Solution' GPO.",
                description:
                    "LAPS is not deployed in this domain. Without LAPS, local administrator accounts typically " +
                    "share the same password across all workstations, enabling lateral movement (pass-the-hash) " +
                    "once a single machine is compromised. LAPS enforces unique, rotated local admin passwords.",
                evidence: new Evidence
                {
                    Type = "ldap",
                    Value = "LAPS schema attribute ms-Mcs-AdmPwd not found or no computers managed by LAPS",
                    Context = $"Domain: {info.DefaultNamingContext}"
                },
                affectedComponent: $"Domain: {info.DefaultNamingContext}"
            )
            .WithReferences(
                "https://attack.mitre.org/techniques/T1021/002/",
                "https://docs.microsoft.com/en-us/windows-server/identity/laps/laps-overview"
            );
        }

        private Finding CreateDomainTrustsFinding(string target, LdapInfo info)
        {
            var trustList = string.Join("\n", info.DomainTrusts.Select(t =>
                $"  • {t.Name} — {t.TrustType}, {t.Direction}"));

            return CreateFinding(
                id: "AST-LDAP-003",
                title: $"Domain trust relationships detected ({info.DomainTrusts.Count})",
                severity: "info",
                recommendation:
                    "Review domain trust relationships and ensure they follow the principle of least privilege:\n" +
                    "1. Audit trusts: Get-ADTrust -Filter * | Select Name,TrustType,Direction,IntraForest\n" +
                    "2. Remove unnecessary trusts (external trusts increase attack surface).\n" +
                    "3. For required trusts: enable Selective Authentication to limit exposure.\n" +
                    "4. Enable SID Filtering (Quarantine) on external trusts to prevent SID history attacks.",
                description:
                    $"Found {info.DomainTrusts.Count} domain trust relationship(s). " +
                    "Trust relationships extend the authentication boundary — a compromise in a trusted domain " +
                    "can lead to lateral movement into this domain. Bidirectional trusts are particularly risky.",
                evidence: new Evidence
                {
                    Type = "ldap",
                    Value = $"Domain trust relationships:\n{trustList}",
                    Context = $"Domain: {info.DefaultNamingContext}"
                },
                affectedComponent: $"Domain: {info.DefaultNamingContext}"
            )
            .WithReferences(
                "https://attack.mitre.org/techniques/T1482/",
                "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc736874(v=ws.10)"
            );
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
        // LDAP-ADV (v0.2.0)
        public List<string> UnconstrainedDelegationAccounts { get; set; } = new List<string>();
        public List<string> AdminCountAccounts { get; set; } = new List<string>();
        public bool LapsNotDeployed { get; set; }
        public List<(string Name, string Direction, string TrustType)> DomainTrusts { get; set; } = new();
    }
}