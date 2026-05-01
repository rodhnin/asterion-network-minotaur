using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Models;

namespace Asterion.Checks.CrossPlatform.Windows
{
    /// <summary>
    /// Active Directory Policy Security Check
    /// 
    /// Analyzes Active Directory security configuration including:
    /// - LDAP signing requirements
    /// - Domain password policies (length, complexity, history, lockout)
    /// - Privileged group membership (Domain Admins, Enterprise Admins, etc.)
    /// - Domain trust relationships
    /// 
    /// Findings:
    /// - AST-AD-WIN-001: LDAP signing not required
    /// - AST-AD-WIN-002: Weak password policy or excessive privileged users
    /// - AST-AD-WIN-003: Insecure domain trusts
    /// 
    /// 
    /// Technical Details:
    /// - Uses System.DirectoryServices.Protocols (cross-platform LDAP)
    /// - Queries rootDSE for domain information
    /// - Reads password policy from domain object attributes
    /// - Enumerates privileged groups via member attribute
    /// </summary>
    public class AdPolicyCheck : BaseCheck
    {
        public override string Name => "Active Directory Policy Check";
        
        public override CheckCategory Category => CheckCategory.Windows;
        
        public override string Description => 
            "Audits Active Directory security policies including LDAP signing, password requirements, " +
            "privileged group membership, and domain trusts. Uses cross-platform LDAP queries to assess " +
            "domain controller configuration against Microsoft and CIS security benchmarks.";

        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        public AdPolicyCheck(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var findings = new List<Finding>();

            if (!_config.Windows.CheckAdPolicies)
            {
                Log.Debug("{CheckName}: AD Policy checks disabled in configuration", Name);
                return findings;
            }

            Log.Information("[{CheckName}] Running Active Directory policy security check", Name);

            try
            {
                // Try to find domain controller(s) from targets
                var dcTargets = targets.Where(t => 
                    t.Contains("dc", StringComparison.OrdinalIgnoreCase) || 
                    t.Contains("domain", StringComparison.OrdinalIgnoreCase) ||
                    t.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ||
                    t.EndsWith(".com", StringComparison.OrdinalIgnoreCase)
                ).ToList();

                if (!dcTargets.Any())
                {
                    // Try to detect domain controller from current environment
                    string? dcHost = await DetectDomainControllerAsync();
                    if (dcHost != null)
                    {
                        dcTargets.Add(dcHost);
                    }
                }

                if (!dcTargets.Any())
                {
                    Log.Warning("{CheckName}: No domain controller found in targets (skipping AD checks)", Name);
                    Log.Information("To scan AD, provide domain controller hostname or domain name in targets");
                    LogExecution(0, 0);
                    return findings;
                }

                foreach (var dcTarget in dcTargets)
                {
                    Log.Information("[{CheckName}] Checking Active Directory policies on: {DC}", Name, dcTarget);

                    // Check LDAP signing requirement
                    var ldapSigningFinding = await CheckLdapSigningAsync(dcTarget, options);
                    if (ldapSigningFinding != null)
                        findings.Add(ldapSigningFinding);

                    // Check password policy
                    var passwordPolicyFindings = await CheckPasswordPolicyAsync(dcTarget, options);
                    findings.AddRange(passwordPolicyFindings);

                    // Check for privileged accounts
                    var privilegedAccountsFindings = await CheckPrivilegedAccountsAsync(dcTarget, options);
                    findings.AddRange(privilegedAccountsFindings);

                    // Check domain trusts (requires credentials)
                    if (!string.IsNullOrEmpty(options.AuthCredentials))
                    {
                        var trustFindings = await CheckDomainTrustsAsync(dcTarget, options);
                        findings.AddRange(trustFindings);
                    }
                    else
                    {
                        Log.Debug("{CheckName}: Skipping domain trust checks (no credentials provided)", Name);
                    }
                }

                LogExecution(dcTargets.Count, findings.Count);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{CheckName}: AD Policy check failed", Name);
            }

            return findings;
        }

        /// <summary>
        /// Try to detect domain controller from environment
        /// </summary>
        private async Task<string?> DetectDomainControllerAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    // Try to get domain from environment
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        var domain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
                        if (!string.IsNullOrEmpty(domain))
                        {
                            Log.Debug("Detected domain from environment: {Domain}", domain);
                            return domain;
                        }

                        // Also try LOGONSERVER
                        var logonServer = Environment.GetEnvironmentVariable("LOGONSERVER");
                        if (!string.IsNullOrEmpty(logonServer))
                        {
                            // Remove leading \\ if present
                            logonServer = logonServer.TrimStart('\\');
                            Log.Debug("Detected logon server from environment: {Server}", logonServer);
                            return logonServer;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug(ex, "Failed to detect domain controller from environment");
                }

                return null;
            });
        }

        /// <summary>
        /// Check if LDAP signing is required by domain controller
        /// AST-AD-WIN-001
        /// </summary>
        private async Task<Finding?> CheckLdapSigningAsync(string dcHost, ScanOptions options)
        {
            return await Task.Run(() =>
            {
                try
                {
                    // Connect to LDAP port 389
                    var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(dcHost, 389));
                    ldapConnection.SessionOptions.ProtocolVersion = 3;
                    ldapConnection.Timeout = TimeSpan.FromSeconds(_config.Ldap.TimeoutSeconds);

                    // Try anonymous bind first
                    try
                    {
                        ldapConnection.Bind();
                        Log.Debug("Anonymous LDAP bind successful on {DC}", dcHost);
                    }
                    catch
                    {
                        // If anonymous fails, try with credentials if provided
                        if (!string.IsNullOrEmpty(options.AuthCredentials))
                        {
                            var (username, password, domain) = ParseCredentials(options.AuthCredentials);
                            if (username != null && password != null)
                            {
                                var credential = new NetworkCredential(username, password, domain);
                                ldapConnection.Credential = credential;
                                ldapConnection.AuthType = AuthType.Negotiate;
                                ldapConnection.Bind();
                                Log.Debug("Authenticated LDAP bind successful on {DC}", dcHost);
                            }
                        }
                        else
                        {
                            Log.Warning("LDAP bind failed on {DC} and no credentials provided", dcHost);
                            return null;
                        }
                    }

                    // Query rootDSE for default naming context
                    var searchRequest = new SearchRequest(
                        null, // rootDSE
                        "(objectClass=*)",
                        SearchScope.Base,
                        "defaultNamingContext", "ldapServiceName", "supportedControl"
                    );

                    var searchResponse = (SearchResponse)ldapConnection.SendRequest(searchRequest);

                    if (searchResponse.Entries.Count > 0)
                    {
                        var rootDse = searchResponse.Entries[0];
                        var defaultNamingContext = rootDse.Attributes["defaultNamingContext"]?[0]?.ToString();

                        Log.Debug("Default Naming Context: {Context}", defaultNamingContext);

                        // Check if we were able to perform unsigned LDAP bind
                        // If we're here and SessionOptions.Signing is false, signing is not required
                        bool signingRequired = ldapConnection.SessionOptions.Signing;

                        if (!signingRequired)
                        {
                            var finding = Finding.Create(
                                id: "AST-AD-WIN-001",
                                title: "LDAP signing not required by domain controller",
                                severity: "high",
                                confidence: "high",
                                recommendation: "Enable LDAP signing requirement on all domain controllers:\n\n" +
                                    "Via Group Policy:\n" +
                                    "1. Open 'Group Policy Management Console' (gpmc.msc)\n" +
                                    "2. Edit 'Default Domain Controllers Policy'\n" +
                                    "3. Navigate to: Computer Configuration > Policies > Windows Settings > " +
                                    "Security Settings > Local Policies > Security Options\n" +
                                    "4. Find: 'Domain controller: LDAP server signing requirements'\n" +
                                    "5. Set to: 'Require signing'\n" +
                                    "6. Click 'OK'\n" +
                                    "7. Run 'gpupdate /force' on all DCs\n\n" +
                                    "Via Registry (requires DC reboot):\n" +
                                    "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\" " +
                                    "/v LDAPServerIntegrity /t REG_DWORD /d 2 /f\n\n" +
                                    "Also consider:\n" +
                                    "- Enable LDAPS (LDAP over SSL/TLS on port 636) for encrypted communication\n" +
                                    "- Install valid certificates on domain controllers\n" +
                                    "- Test with legacy applications before enforcing\n\n" +
                                    "WARNING: Test this change carefully. Some legacy LDAP clients may not support signing."
                            )
                            .WithDescription(
                                $"The domain controller '{dcHost}' does not require LDAP signing for authentication. " +
                                "LDAP signing provides data integrity by digitally signing LDAP packets. Without it:\n" +
                                "• Man-in-the-middle (MITM) attackers can intercept and modify LDAP traffic\n" +
                                "• Attackers can tamper with directory queries and responses\n" +
                                "• Password changes can be intercepted or modified\n" +
                                "• Group membership modifications can be altered in transit\n" +
                                "• Kerberos ticket requests can be manipulated\n\n" +
                                "LDAP signing ensures that all LDAP communication is signed and cannot be tampered with. " +
                                "This is especially critical for domain controllers handling authentication and authorization."
                            )
                            .WithEvidence(
                                type: "service",
                                value: $"Successfully performed unsigned LDAP bind to {dcHost}:389",
                                context: $"Domain: {defaultNamingContext ?? "Unknown"}\nLDAP Signing: Not Required"
                            )
                            .WithReferences(
                                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements",
                                "https://www.cisecurity.org/benchmark/microsoft_windows_server",
                                "https://support.microsoft.com/en-us/help/4520412/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows"
                            )
                            .WithAffectedComponent($"{dcHost}:389 (LDAP)");

                            ldapConnection.Dispose();
                            return finding;
                        }

                        Log.Information("{CheckName}: LDAP signing is required on {DC} ✓", Name, dcHost);
                    }

                    ldapConnection.Dispose();
                }
                catch (LdapException ex)
                {
                    Log.Debug(ex, "LDAP connection failed to {DC}", dcHost);
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error checking LDAP signing on {DC}", dcHost);
                }

                return null;
            });
        }

        /// <summary>
        /// Check domain password policy
        /// AST-AD-WIN-002
        /// </summary>
        private async Task<List<Finding>> CheckPasswordPolicyAsync(string dcHost, ScanOptions options)
        {
            var findings = new List<Finding>();

            await Task.Run(() =>
            {
                try
                {
                    var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(dcHost, 389));
                    ldapConnection.SessionOptions.ProtocolVersion = 3;
                    ldapConnection.Timeout = TimeSpan.FromSeconds(_config.Ldap.TimeoutSeconds);

                    // Bind with credentials if available
                    if (!string.IsNullOrEmpty(options.AuthCredentials))
                    {
                        var (username, password, domain) = ParseCredentials(options.AuthCredentials);
                        if (username != null && password != null)
                        {
                            var credential = new NetworkCredential(username, password, domain);
                            ldapConnection.Credential = credential;
                            ldapConnection.AuthType = AuthType.Negotiate;
                        }
                    }

                    ldapConnection.Bind();

                    // Query default naming context
                    var rootDseRequest = new SearchRequest(null, "(objectClass=*)", SearchScope.Base, "defaultNamingContext");
                    var rootDseResponse = (SearchResponse)ldapConnection.SendRequest(rootDseRequest);
                    
                    if (rootDseResponse.Entries.Count == 0)
                        return;

                    var defaultNamingContext = rootDseResponse.Entries[0].Attributes["defaultNamingContext"]?[0]?.ToString();
                    if (string.IsNullOrEmpty(defaultNamingContext))
                        return;

                    // Query domain object for password policy attributes
                    var policyRequest = new SearchRequest(
                        defaultNamingContext,
                        "(objectClass=domain)",
                        SearchScope.Base,
                        "minPwdLength", "pwdProperties", "minPwdAge", "maxPwdAge", "pwdHistoryLength", "lockoutThreshold"
                    );

                    var policyResponse = (SearchResponse)ldapConnection.SendRequest(policyRequest);

                    if (policyResponse.Entries.Count > 0)
                    {
                        var domainObj = policyResponse.Entries[0];

                        // Extract password policy values
                        int minPwdLength = GetIntAttribute(domainObj, "minPwdLength", 0);
                        int pwdProperties = GetIntAttribute(domainObj, "pwdProperties", 0);
                        int pwdHistoryLength = GetIntAttribute(domainObj, "pwdHistoryLength", 0);
                        int lockoutThreshold = GetIntAttribute(domainObj, "lockoutThreshold", 0);

                        Log.Debug("{CheckName}: Password Policy - MinLength={Min}, Properties=0x{Props:X}, " +
                                  "History={Hist}, Lockout={Lock}", 
                            Name, minPwdLength, pwdProperties, pwdHistoryLength, lockoutThreshold);

                        // Check minimum password length
                        CheckMinPasswordLength(minPwdLength, defaultNamingContext, findings);

                        // Check password complexity
                        CheckPasswordComplexity(pwdProperties, defaultNamingContext, findings);

                        // Check password history
                        CheckPasswordHistory(pwdHistoryLength, defaultNamingContext, findings);

                        // Check account lockout
                        CheckAccountLockout(lockoutThreshold, defaultNamingContext, findings);
                    }

                    ldapConnection.Dispose();
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error checking password policy on {DC}", dcHost);
                }
            });

            return findings;
        }

        /// <summary>
        /// Check minimum password length
        /// </summary>
        private void CheckMinPasswordLength(int minPwdLength, string domainDN, List<Finding> findings)
        {
            if (minPwdLength < 8)
            {
                findings.Add(Finding.Create(
                    id: "AST-AD-WIN-002",
                    title: $"Weak domain password policy: minimum length is {minPwdLength} characters",
                    severity: minPwdLength < 6 ? "high" : "medium",
                    confidence: "high",
                    recommendation: "Increase minimum password length:\n\n" +
                        "Via Group Policy:\n" +
                        "1. Open 'Group Policy Management Console' (gpmc.msc)\n" +
                        "2. Edit 'Default Domain Policy'\n" +
                        "3. Navigate to: Computer Configuration > Policies > Windows Settings > " +
                        "Security Settings > Account Policies > Password Policy\n" +
                        "4. Set 'Minimum password length' to at least 12 characters (14 recommended)\n" +
                        "5. Click 'OK'\n" +
                        "6. Run 'gpupdate /force'\n\n" +
                        "NIST SP 800-63B recommends:\n" +
                        "- Minimum 8 characters for user-chosen passwords\n" +
                        "- Minimum 12-14 characters for administrator accounts\n" +
                        "- Focus on password complexity and multi-factor authentication\n" +
                        "- Consider passphrases (e.g., 'correct-horse-battery-staple')"
                )
                .WithDescription(
                    $"The domain password policy requires a minimum password length of only {minPwdLength} characters. " +
                    "Short passwords are significantly easier to crack:\n" +
                    $"• {minPwdLength}-character password can be brute-forced relatively quickly\n" +
                    "• Dictionary attacks are highly effective against short passwords\n" +
                    "• Insufficient entropy for modern security requirements\n\n" +
                    "Industry best practices recommend:\n" +
                    "• Minimum 12-14 characters for general users\n" +
                    "• Minimum 15+ characters for privileged accounts\n" +
                    "• Encourage passphrases over complex short passwords"
                )
                .WithEvidence(
                    type: "config",
                    value: $"minPwdLength = {minPwdLength}",
                    context: $"Domain: {domainDN}"
                )
                .WithReferences(
                    "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length",
                    "https://pages.nist.gov/800-63-3/sp800-63b.html",
                    "https://www.cisecurity.org/benchmark/microsoft_windows_server"
                )
                .WithAffectedComponent($"AD Password Policy: {domainDN}"));

                Log.Warning("{CheckName}: Weak minimum password length: {Length}", Name, minPwdLength);
            }
        }

        /// <summary>
        /// Check password complexity requirements
        /// </summary>
        private void CheckPasswordComplexity(int pwdProperties, string domainDN, List<Finding> findings)
        {
            // Bit 0 of pwdProperties = DOMAIN_PASSWORD_COMPLEX (complexity enabled)
            bool complexityEnabled = (pwdProperties & 0x01) != 0;

            if (!complexityEnabled)
            {
                findings.Add(Finding.Create(
                    id: "AST-AD-WIN-002",
                    title: "Domain password complexity requirements are disabled",
                    severity: "high",
                    confidence: "high",
                    recommendation: "Enable password complexity requirements:\n\n" +
                        "Via Group Policy:\n" +
                        "1. Open 'Group Policy Management Console' (gpmc.msc)\n" +
                        "2. Edit 'Default Domain Policy'\n" +
                        "3. Navigate to: Computer Configuration > Policies > Windows Settings > " +
                        "Security Settings > Account Policies > Password Policy\n" +
                        "4. Set 'Password must meet complexity requirements' to 'Enabled'\n" +
                        "5. Click 'OK'\n" +
                        "6. Run 'gpupdate /force'\n\n" +
                        "Complexity requirements enforce:\n" +
                        "• Passwords contain characters from three of four categories:\n" +
                        "  - Uppercase letters (A-Z)\n" +
                        "  - Lowercase letters (a-z)\n" +
                        "  - Digits (0-9)\n" +
                        "  - Special characters (!@#$%^&*...)\n" +
                        "• Passwords don't contain username or display name\n\n" +
                        "Alternative: Consider passphrases (longer, memorable phrases) instead of complex short passwords."
                )
                .WithDescription(
                    "The domain password policy does not enforce password complexity requirements. " +
                    "Without complexity requirements:\n" +
                    "• Users can set simple, predictable passwords (e.g., 'password123', 'Summer2024')\n" +
                    "• Dictionary attacks become highly effective\n" +
                    "• Password guessing is easier for attackers\n" +
                    "• Single-character-type passwords (e.g., all lowercase) are vulnerable\n\n" +
                    "Enabling complexity ensures passwords are harder to guess and more resistant to brute-force attacks."
                )
                .WithEvidence(
                    type: "config",
                    value: $"pwdProperties = 0x{pwdProperties:X} (complexity disabled)",
                    context: $"Domain: {domainDN}"
                )
                .WithReferences(
                    "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements",
                    "https://www.cisecurity.org/benchmark/microsoft_windows_server"
                )
                .WithAffectedComponent($"AD Password Policy: {domainDN}"));

                Log.Warning("{CheckName}: Password complexity is disabled", Name);
            }
        }

        /// <summary>
        /// Check password history length
        /// </summary>
        private void CheckPasswordHistory(int pwdHistoryLength, string domainDN, List<Finding> findings)
        {
            if (pwdHistoryLength < 12)
            {
                findings.Add(Finding.Create(
                    id: "AST-AD-WIN-002",
                    title: $"Weak password history: only {pwdHistoryLength} passwords remembered",
                    severity: "medium",
                    confidence: "high",
                    recommendation: "Increase password history:\n\n" +
                        "Via Group Policy:\n" +
                        "1. Open 'Group Policy Management Console' (gpmc.msc)\n" +
                        "2. Edit 'Default Domain Policy'\n" +
                        "3. Navigate to: Computer Configuration > Policies > Windows Settings > " +
                        "Security Settings > Account Policies > Password Policy\n" +
                        "4. Set 'Enforce password history' to at least 12 passwords (24 recommended)\n" +
                        "5. Click 'OK'\n" +
                        "6. Run 'gpupdate /force'\n\n" +
                        "Note: Higher history values prevent password reuse but may require user education."
                )
                .WithDescription(
                    $"The domain password policy remembers only {pwdHistoryLength} previous passwords. " +
                    "This allows users to cycle through a small set of favorite passwords:\n" +
                    $"• With {pwdHistoryLength} passwords remembered, users can reuse passwords quickly\n" +
                    "• Compromised passwords can be reused after brief period\n" +
                    "• Does not enforce true password diversity\n\n" +
                    "Best practice is to remember at least 12-24 previous passwords to prevent reuse patterns."
                )
                .WithEvidence(
                    type: "config",
                    value: $"pwdHistoryLength = {pwdHistoryLength}",
                    context: $"Domain: {domainDN}"
                )
                .WithReferences(
                    "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-password-history",
                    "https://www.cisecurity.org/benchmark/microsoft_windows_server"
                )
                .WithAffectedComponent($"AD Password Policy: {domainDN}"));

                Log.Warning("{CheckName}: Password history length is {Length}", Name, pwdHistoryLength);
            }
        }

        /// <summary>
        /// Check account lockout threshold
        /// </summary>
        private void CheckAccountLockout(int lockoutThreshold, string domainDN, List<Finding> findings)
        {
            if (lockoutThreshold == 0)
            {
                findings.Add(Finding.Create(
                    id: "AST-AD-WIN-002",
                    title: "Account lockout policy is disabled",
                    severity: "medium",
                    confidence: "high",
                    recommendation: "Enable account lockout policy:\n\n" +
                        "Via Group Policy:\n" +
                        "1. Open 'Group Policy Management Console' (gpmc.msc)\n" +
                        "2. Edit 'Default Domain Policy'\n" +
                        "3. Navigate to: Computer Configuration > Policies > Windows Settings > " +
                        "Security Settings > Account Policies > Account Lockout Policy\n" +
                        "4. Set 'Account lockout threshold' to 5-10 invalid attempts (5 recommended)\n" +
                        "5. Set 'Account lockout duration' to 15-30 minutes\n" +
                        "6. Set 'Reset account lockout counter after' to 15-30 minutes\n" +
                        "7. Click 'OK'\n" +
                        "8. Run 'gpupdate /force'\n\n" +
                        "WARNING: Balance security with usability:\n" +
                        "• Too low (1-3 attempts): Legitimate users get locked out frequently\n" +
                        "• Too high (>20 attempts): Allows password guessing attacks\n" +
                        "• Consider Azure AD Smart Lockout for intelligent protection"
                )
                .WithDescription(
                    "The domain has no account lockout threshold configured. This allows unlimited password guessing attempts:\n" +
                    "• Attackers can perform brute-force attacks without being locked out\n" +
                    "• Password spraying attacks (trying common passwords across many accounts) are feasible\n" +
                    "• No automatic protection against credential stuffing\n" +
                    "• Increases risk of successful password guessing\n\n" +
                    "An account lockout policy temporarily locks accounts after a number of failed login attempts, " +
                    "significantly reducing the effectiveness of brute-force attacks."
                )
                .WithEvidence(
                    type: "config",
                    value: "lockoutThreshold = 0 (disabled)",
                    context: $"Domain: {domainDN}"
                )
                .WithReferences(
                    "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold",
                    "https://www.cisecurity.org/benchmark/microsoft_windows_server"
                )
                .WithAffectedComponent($"AD Account Lockout Policy: {domainDN}"));

                Log.Warning("{CheckName}: Account lockout is disabled", Name);
            }
        }

        /// <summary>
        /// Check for privileged accounts with weak configurations
        /// </summary>
        private async Task<List<Finding>> CheckPrivilegedAccountsAsync(string dcHost, ScanOptions options)
        {
            var findings = new List<Finding>();

            await Task.Run(() =>
            {
                try
                {
                    // Requires authentication
                    if (string.IsNullOrEmpty(options.AuthCredentials))
                    {
                        Log.Debug("{CheckName}: Skipping privileged accounts check (no credentials provided)", Name);
                        return;
                    }

                    var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(dcHost, 389));
                    ldapConnection.SessionOptions.ProtocolVersion = 3;
                    
                    var (username, password, domain) = ParseCredentials(options.AuthCredentials);
                    if (username != null && password != null)
                    {
                        var credential = new NetworkCredential(username, password, domain);
                        ldapConnection.Credential = credential;
                        ldapConnection.AuthType = AuthType.Negotiate;
                    }

                    ldapConnection.Bind();

                    // Get default naming context
                    var rootDseRequest = new SearchRequest(null, "(objectClass=*)", SearchScope.Base, "defaultNamingContext");
                    var rootDseResponse = (SearchResponse)ldapConnection.SendRequest(rootDseRequest);
                    
                    if (rootDseResponse.Entries.Count == 0)
                        return;

                    var defaultNamingContext = rootDseResponse.Entries[0].Attributes["defaultNamingContext"]?[0]?.ToString();
                    if (string.IsNullOrEmpty(defaultNamingContext))
                        return;

                    // Query privileged groups
                    var privilegedGroups = new Dictionary<string, int>
                    {
                        { "Domain Admins", 5 },        // Max recommended members
                        { "Enterprise Admins", 3 },
                        { "Schema Admins", 2 },
                        { "Administrators", 10 }
                    };

                    foreach (var (groupName, maxRecommended) in privilegedGroups)
                    {
                        try
                        {
                            var groupSearchRequest = new SearchRequest(
                                defaultNamingContext,
                                $"(&(objectClass=group)(cn={groupName}))",
                                SearchScope.Subtree,
                                "member", "cn"
                            );

                            var groupSearchResponse = (SearchResponse)ldapConnection.SendRequest(groupSearchRequest);

                            if (groupSearchResponse.Entries.Count > 0)
                            {
                                var group = groupSearchResponse.Entries[0];
                                var members = group.Attributes["member"];
                                
                                if (members != null)
                                {
                                    int memberCount = members.Count;
                                    
                                    Log.Debug("{CheckName}: Group '{Group}' has {Count} members", Name, groupName, memberCount);

                                    // Flag if too many members
                                    if (memberCount > maxRecommended)
                                    {
                                        findings.Add(Finding.Create(
                                            id: "AST-AD-WIN-002",
                                            title: $"Excessive number of users in '{groupName}' group ({memberCount} members)",
                                            severity: "medium",
                                            confidence: "high",
                                            recommendation: "Review and reduce privileged group membership:\n\n" +
                                                $"1. Audit all {memberCount} members of '{groupName}' group\n" +
                                                "2. Remove users who don't need these privileges\n" +
                                                "3. Use delegated administration where possible\n" +
                                                "4. Implement Just-In-Time (JIT) administration via Azure PIM\n" +
                                                "5. Use separate admin accounts (not daily-use accounts)\n" +
                                                "6. Monitor privileged group changes with audit logs\n" +
                                                "7. Implement Privileged Access Workstations (PAWs)\n\n" +
                                                "Recommended maximum members:\n" +
                                                "• Domain Admins: 2-5 accounts\n" +
                                                "• Enterprise Admins: 2-3 accounts (forest-level tasks only)\n" +
                                                "• Schema Admins: 1-2 accounts (schema changes only)\n" +
                                                "• Administrators: 5-10 accounts"
                                        )
                                        .WithDescription(
                                            $"The '{groupName}' group contains {memberCount} members, which exceeds the recommended maximum of {maxRecommended}. " +
                                            "Having too many privileged users:\n" +
                                            "• Increases the attack surface (more accounts to compromise)\n" +
                                            "• Makes privilege management and auditing difficult\n" +
                                            "• Violates the principle of least privilege\n" +
                                            "• Increases risk of insider threats\n" +
                                            "• Makes it harder to track administrative actions\n\n" +
                                            "Each additional privileged account is a potential target for attackers."
                                        )
                                        .WithEvidence(
                                            type: "service",
                                            value: $"Group: {groupName}, Members: {memberCount}, Recommended Max: {maxRecommended}",
                                            context: $"Domain: {defaultNamingContext}"
                                        )
                                        .WithReferences(
                                            "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models",
                                            "https://www.cisecurity.org/benchmark/microsoft_windows_server"
                                        )
                                        .WithAffectedComponent($"AD Group: {groupName}"));

                                        Log.Warning("{CheckName}: Excessive members in {Group}: {Count} (max recommended: {Max})", 
                                            Name, groupName, memberCount, maxRecommended);
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.Debug(ex, "Failed to query group {Group}", groupName);
                        }
                    }

                    ldapConnection.Dispose();
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error checking privileged accounts on {DC}", dcHost);
                }
            });

            return findings;
        }

        /// <summary>
        /// Check domain trusts (informational)
        /// AST-AD-WIN-003
        /// </summary>
        private async Task<List<Finding>> CheckDomainTrustsAsync(string dcHost, ScanOptions options)
        {
            var findings = new List<Finding>();

            await Task.Run(() =>
            {
                try
                {
                    var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(dcHost, 389));
                    ldapConnection.SessionOptions.ProtocolVersion = 3;
                    
                    var (username, password, domain) = ParseCredentials(options.AuthCredentials);
                    if (username != null && password != null)
                    {
                        var credential = new NetworkCredential(username, password, domain);
                        ldapConnection.Credential = credential;
                        ldapConnection.AuthType = AuthType.Negotiate;
                    }

                    ldapConnection.Bind();

                    // Query for domain naming context (trustedDomain objects live in CN=System,<domainNC>)
                    var rootDseRequest = new SearchRequest(null, "(objectClass=*)", SearchScope.Base, "defaultNamingContext");
                    var rootDseResponse = (SearchResponse)ldapConnection.SendRequest(rootDseRequest);

                    if (rootDseResponse.Entries.Count == 0)
                        return;

                    var defaultNamingContext = rootDseResponse.Entries[0].Attributes["defaultNamingContext"]?[0]?.ToString();
                    if (string.IsNullOrEmpty(defaultNamingContext))
                        return;

                    // Query for trusted domain objects
                    var trustSearchRequest = new SearchRequest(
                        $"CN=System,{defaultNamingContext}",
                        "(objectClass=trustedDomain)",
                        SearchScope.Subtree,
                        "cn", "trustDirection", "trustType"
                    );

                    var trustSearchResponse = (SearchResponse)ldapConnection.SendRequest(trustSearchRequest);

                    if (trustSearchResponse.Entries.Count > 0)
                    {
                        Log.Information("{CheckName}: Found {Count} domain trust(s)", Name, trustSearchResponse.Entries.Count);

                        var trustNames = new List<string>();
                        foreach (SearchResultEntry entry in trustSearchResponse.Entries)
                        {
                            var trustName = entry.Attributes["cn"]?[0]?.ToString();
                            if (!string.IsNullOrEmpty(trustName))
                            {
                                trustNames.Add(trustName);
                            }
                        }

                        findings.Add(Finding.Create(
                            id: "AST-AD-WIN-003",
                            title: $"Domain has {trustSearchResponse.Entries.Count} trust relationship(s)",
                            severity: "info",
                            confidence: "high",
                            recommendation: "Review all domain trusts:\n\n" +
                                "1. Open 'Active Directory Domains and Trusts' (domain.msc)\n" +
                                "2. Right-click domain > Properties > Trusts tab\n" +
                                "3. For each trust:\n" +
                                "   - Verify it's still needed\n" +
                                "   - Check trust direction (bidirectional vs unidirectional)\n" +
                                "   - Verify authentication scope (forest-wide vs selective)\n" +
                                "   - Enable SID filtering if not already enabled\n" +
                                "4. Remove unnecessary trusts\n" +
                                "5. Document all trusts and their purposes\n" +
                                "6. Monitor for suspicious cross-domain activity\n\n" +
                                "Security best practices:\n" +
                                "• Prefer selective authentication over forest-wide\n" +
                                "• Enable SID filtering to prevent elevation of privilege attacks\n" +
                                "• Regularly audit trust relationships\n" +
                                "• Use quarantine domains for untrusted forests"
                        )
                        .WithDescription(
                            $"The domain has {trustSearchResponse.Entries.Count} trust(s) configured with other domains: {string.Join(", ", trustNames)}. " +
                            "While trusts are often necessary for business operations:\n" +
                            "• They expand the attack surface to include trusted domains\n" +
                            "• Compromised trusted domains can pivot to your domain\n" +
                            "• Require careful management and monitoring\n" +
                            "• Can be exploited for privilege escalation if misconfigured\n\n" +
                            "Ensure all trusts are necessary, properly configured with SID filtering, and regularly audited."
                        )
                        .WithEvidence(
                            type: "service",
                            value: $"Found {trustSearchResponse.Entries.Count} trust(s)",
                            context: $"Trusts: {string.Join(", ", trustNames)}"
                        )
                        .WithReferences(
                            "https://docs.microsoft.com/en-us/azure/active-directory-domain-services/concepts-forest-trust",
                            "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory"
                        )
                        .WithAffectedComponent("AD Domain Trusts"));
                    }

                    ldapConnection.Dispose();
                }
                catch (Exception ex)
                {
                    Log.Debug(ex, "Error checking domain trusts on {DC}", dcHost);
                }
            });

            return findings;
        }

        /// <summary>
        /// Helper to get integer attribute from LDAP entry
        /// </summary>
        private int GetIntAttribute(SearchResultEntry entry, string attributeName, int defaultValue)
        {
            try
            {
                var attribute = entry.Attributes[attributeName];
                if (attribute != null && attribute.Count > 0)
                {
                    var value = attribute[0];
                    
                    if (value is byte[] bytes)
                    {
                        // Some attributes return as byte arrays (little-endian)
                        if (bytes.Length == 4)
                        {
                            return BitConverter.ToInt32(bytes, 0);
                        }
                        else if (bytes.Length == 8)
                        {
                            return (int)BitConverter.ToInt64(bytes, 0);
                        }
                    }
                    else if (value is string strValue)
                    {
                        if (int.TryParse(strValue, out int result))
                        {
                            return result;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Failed to parse attribute {Attribute}", attributeName);
            }

            return defaultValue;
        }
    }
}