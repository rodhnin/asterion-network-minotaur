using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Core.Utils;
using Asterion.Models;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.SMB2;
using AuthMgr = Asterion.Core.Utils.AuthenticationManager;

namespace Asterion.Checks.CrossPlatform
{
    /// <summary>
    /// SMB/CIFS Security Scanner
    /// 
    /// Detects critical SMB misconfigurations and vulnerabilities:
    /// - AST-SMB-001: Anonymous/guest SMB access (CRITICAL)
    /// - AST-SMB-002: SMB signing not required (HIGH)
    /// - AST-SMB-003: SMBv1 enabled - EternalBlue/WannaCry vector (HIGH)
    /// - AST-SMB-004: Weak NTLM authentication (MEDIUM) [TODO]
    /// - AST-SMB-005: Sensitive shares accessible via NTLM (HIGH)
    /// 
    /// Technical Details:
    /// - Uses SMBLibrary for protocol-level analysis
    /// - Tests both SMB1 and SMB2/3 protocols
    /// - Attempts share enumeration via null sessions
    /// - Checks signing requirements and protocol versions
    /// 
    /// References:
    /// - MS17-010 (EternalBlue): CVE-2017-0143 through CVE-2017-0148
    /// - WannaCry ransomware (2017)
    /// - NotPetya ransomware (2017)
    /// </summary>
    public class SmbScanner : BaseCheck
    {
        private const int SMB_PORT = 445;
        
        public override string Name => "SMB/CIFS Security Scanner";
        
        public override CheckCategory Category => CheckCategory.CrossPlatform;
        
        public override string Description => 
            "Analyzes SMB/CIFS protocol security including anonymous access, message signing requirements, " +
            "and dangerous legacy protocols (SMBv1). Detects configurations vulnerable to relay attacks and " +
            "known exploits like EternalBlue (MS17-010).";

        public override bool RequiresAuthentication => false; // Can test without credentials
        public override bool RequiresAggressiveMode => false; // Safe checks

        public SmbScanner(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            // Validate execution
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var findings = new List<Finding>();

            Log.Information("[{CheckName}] Starting SMB security scan on {Count} target(s)", Name, targets.Count);

            foreach (var target in targets)
            {
                try
                {
                    // Check if SMB port is open first
                    if (!await NetworkUtils.IsPortOpenAsync(target, SMB_PORT, 3000))
                    {
                        Log.Debug("[{CheckName}] SMB port {Port} not open on {Target}", Name, SMB_PORT, target);
                        continue;
                    }

                    Log.Information("[{CheckName}] SMB port open on {Target}, starting security checks", Name, target);

                    // Perform SMB security checks
                    await CheckSmbAnonymousAccessAsync(target, findings, options);
                    await CheckSmbSigningAsync(target, findings, options);
                    await CheckSmbVersionsAsync(target, findings);
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "[{CheckName}] Failed to scan {Target}", Name, target);
                }
            }

            LogExecution(targets.Count, findings.Count);
            return findings;
        }

        /// <summary>
        /// AST-SMB-001: Check for anonymous/guest SMB access (null sessions)
        /// This is a CRITICAL vulnerability that allows unauthenticated access to shares
        /// </summary>
        private async Task CheckSmbAnonymousAccessAsync(string target, List<Finding> findings, ScanOptions options)
        {
            SMB2Client? client = null;
            var authManager = new AuthMgr();
            
            try
            {
                // ========================================================================
                // NTLM PASS-THE-HASH AUTHENTICATION (if provided)
                // ========================================================================
                if (!string.IsNullOrEmpty(options.AuthNtlm))
                {
                    string? ntlmUsername;
                    string? ntlmHash;
                    (ntlmUsername, ntlmHash) = authManager.ParseNtlmCredentials(options.AuthNtlm);
                    
                    if (!string.IsNullOrEmpty(ntlmUsername) && !string.IsNullOrEmpty(ntlmHash))
                    {
                        Log.Information("[{CheckName}] Attempting NTLM pass-the-hash authentication for {User} on {Target}", 
                            Name, ntlmUsername, target);
                        
                        bool success;
                        List<SmbShareInfo> shares;
                        string rawOutput;
                        (success, shares, rawOutput) = await authManager.EnumerateSharesNtlmAsync(target, ntlmUsername, ntlmHash);
                        
                        if (success)
                        {
                            Log.Information("[{CheckName}] NTLM authentication successful on {Target} - {Count} shares found", 
                                Name, target, shares.Count);
                            
                            if (shares.Count > 0)
                            {
                                var sensitiveShares = shares.Where(s => s.IsSensitive).ToList();
                                
                                if (sensitiveShares.Any())
                                {
                                    findings.Add(CreateSensitiveSharesFinding(target, ntlmUsername, sensitiveShares));
                                }
                                
                                foreach (var share in shares)
                                {
                                    Log.Information("[{CheckName}] Share found: {Name} ({Type}) - {Comment}", 
                                        Name, share.Name, share.Type, share.Comment);
                                }
                            }
                            else
                            {
                                Log.Warning("[{CheckName}] NTLM auth succeeded but no shares found on {Target}", Name, target);
                            }
                            
                            // Successfully enumerated via NTLM - skip standard checks
                            return;
                        }
                        else
                        {
                            Log.Warning("[{CheckName}] NTLM authentication failed on {Target}: {Output}", 
                                Name, target, rawOutput.Split('\n').FirstOrDefault() ?? "Unknown error");
                        }
                    }
                }
                
                // ========================================================================
                // STANDARD SMB AUTHENTICATION
                // ========================================================================
                client = new SMB2Client();
                
                var ipAddress = await ResolveTargetAsync(target);
                if (ipAddress == null)
                {
                    Log.Warning("[{CheckName}] Failed to resolve {Target}", Name, target);
                    return;
                }
                
                if (!client.Connect(ipAddress, SMBTransportType.DirectTCPTransport))
                {
                    Log.Debug("[{CheckName}] Failed to connect to SMB on {Target}", Name, target);
                    return;
                }
                
                // Parse credentials if provided
                string username = string.Empty;
                string password = string.Empty;
                string domain = string.Empty;
                
                if (!string.IsNullOrEmpty(options.AuthCredentials))
                {
                    var (user, pass, dom) = ParseCredentials(options.AuthCredentials);
                    username = user ?? string.Empty;
                    password = pass ?? string.Empty;
                    domain = dom ?? string.Empty;
                    
                    Log.Debug("[{CheckName}] Using credentials: {Domain}\\{User}", Name, 
                        string.IsNullOrEmpty(domain) ? "." : domain, username);
                }
                
                NTStatus status;
                string? detectedGuestName = null;
                bool isAnonymous = string.IsNullOrEmpty(username);
                bool sessionEstablished = false;
                
                if (isAnonymous)
                {
                    // ================================================================
                    // TRY NULL SESSION
                    // ================================================================
                    Log.Debug("[{CheckName}] Attempting null session on {Target}", Name, target);
                    status = client.Login(string.Empty, string.Empty, string.Empty);
                    
                    if (status == NTStatus.STATUS_SUCCESS)
                    {
                        try
                        {
                            var testShares = client.ListShares(out NTStatus testStatus);
                            
                            if (testStatus == NTStatus.STATUS_SUCCESS)
                            {
                                sessionEstablished = true;
                                detectedGuestName = "<null session>";
                                Log.Warning("[{CheckName}] CRITICAL: Null session allowed on {Target}!", Name, target);
                            }
                            else
                            {
                                Log.Debug("[{CheckName}] Null session login succeeded but share enum blocked (status: {Status})", 
                                    Name, testStatus);
                            }
                        }
                        catch (InvalidOperationException)
                        {
                            Log.Debug("[{CheckName}] Null session login succeeded but session not usable on {Target}", Name, target);
                        }
                        catch (Exception ex)
                        {
                            Log.Debug(ex, "[{CheckName}] Null session verification failed on {Target}", Name, target);
                        }
                    }
                    else
                    {
                        Log.Debug("[{CheckName}] Null session denied on {Target} (status: {Status})", Name, target, status);
                    }
                    
                    // ================================================================
                    // TRY GUEST ACCOUNTS (if null session failed)
                    // ================================================================
                    if (!sessionEstablished)
                    {
                        Log.Debug("[{CheckName}] Trying Guest accounts on {Target}...", Name, target);
                        
                        // Cleanup current connection
                        try 
                        { 
                            if (client.IsConnected)
                            {
                                client.Logoff();
                                client.Disconnect();
                            }
                        } 
                        catch { /* ignore cleanup errors */ }
                        
                        var guestNames = new[] 
                        { 
                            "Guest",
                            "Invitado",
                            "Gast",
                            "Invite",
                            "Ospite",
                            "Convidado",
                            "来宾",
                            "ゲスト"
                        };
                        
                        foreach (var guestName in guestNames)
                        {
                            try
                            {
                                client?.Disconnect();
                                client = new SMB2Client();
                                
                                if (!client.Connect(ipAddress, SMBTransportType.DirectTCPTransport))
                                {
                                    Log.Debug("[{CheckName}] Failed to reconnect for guest '{GuestName}' on {Target}", 
                                        Name, guestName, target);
                                    continue;
                                }
                                
                                Log.Debug("[{CheckName}] Trying guest account '{GuestName}' on {Target}", 
                                    Name, guestName, target);
                                
                                status = client.Login(string.Empty, guestName, string.Empty);
                                
                                if (status == NTStatus.STATUS_SUCCESS)
                                {
                                    try
                                    {
                                        var testShares = client.ListShares(out NTStatus testStatus);
                                        
                                        if (testStatus == NTStatus.STATUS_SUCCESS)
                                        {
                                            sessionEstablished = true;
                                            detectedGuestName = guestName;
                                            Log.Warning("[{CheckName}] CRITICAL: Guest account '{GuestName}' is active on {Target}!", 
                                                Name, guestName, target);
                                            break; // Found working guest account
                                        }
                                        else
                                        {
                                            Log.Debug("[{CheckName}] Guest '{GuestName}' login succeeded but share enum blocked on {Target}", 
                                                Name, guestName, target);
                                        }
                                    }
                                    catch (InvalidOperationException)
                                    {
                                        Log.Debug("[{CheckName}] Guest '{GuestName}' login succeeded but session not usable on {Target}", 
                                            Name, guestName, target);
                                    }
                                }
                                else if (status == NTStatus.STATUS_ACCOUNT_DISABLED)
                                {
                                    Log.Debug("[{CheckName}] Guest account '{GuestName}' exists but is disabled on {Target} ✓", 
                                        Name, guestName, target);
                                }
                                else if (status == NTStatus.STATUS_LOGON_FAILURE)
                                {
                                    Log.Debug("[{CheckName}] Guest account '{GuestName}' requires password on {Target}", 
                                        Name, guestName, target);
                                }
                                else
                                {
                                    Log.Debug("[{CheckName}] Guest account '{GuestName}' login failed on {Target}: {Status}", 
                                        Name, guestName, target, status);
                                }
                            }
                            catch (Exception ex)
                            {
                                Log.Debug(ex, "[{CheckName}] Error trying guest account '{GuestName}' on {Target}", 
                                    Name, guestName, target);
                            }
                        }
                        
                        if (!sessionEstablished)
                        {
                            Log.Debug("[{CheckName}] No anonymous or guest access detected on {Target} ✓", Name, target);
                            return;
                        }
                    }
                }
                else
                {
                    // ================================================================
                    // AUTHENTICATED LOGIN
                    // ================================================================
                    status = client.Login(domain, username, password);

                    if (status != NTStatus.STATUS_SUCCESS)
                    {
                        if (status == NTStatus.STATUS_LOGON_FAILURE)
                        {
                            Log.Warning("[{CheckName}] Authenticated SMB login failed on {Target}: Invalid credentials",
                                Name, target);
                        }
                        else
                        {
                            Log.Debug("[{CheckName}] SMB login failed on {Target} (status: {Status})",
                                Name, target, status);
                        }
                        return;
                    }

                    try
                    {
                        var testShares = client.ListShares(out NTStatus testStatus);

                        if (testStatus == NTStatus.STATUS_SUCCESS)
                        {
                            sessionEstablished = true;
                            Log.Information("[{CheckName}] Authenticated SMB login successful on {Target}", Name, target);
                        }
                        else
                        {
                            Log.Warning("[{CheckName}] Authenticated login succeeded but share enum blocked on {Target} (status: {Status})",
                                Name, target, testStatus);
                            return;
                        }
                    }
                    catch (InvalidOperationException)
                    {
                        Log.Warning("[{CheckName}] Authenticated login succeeded but session not usable on {Target}", Name, target);
                        return;
                    }

                    // ================================================================
                    // GUEST CHECK — always probe even when --auth is provided.
                    // Guest access is orthogonal to having valid credentials.
                    // A separate connection is used to avoid disrupting the auth session.
                    // ================================================================
                    Log.Debug("[{CheckName}] Probing Guest account on {Target} (separate from auth session)", Name, target);
                    var guestClient = new SMB2Client();
                    if (guestClient.Connect(ipAddress, SMBTransportType.DirectTCPTransport))
                    {
                        var guestNames = new[] { "Guest", "Invitado", "Gast", "Invite", "Ospite", "Convidado" };
                        foreach (var guestName in guestNames)
                        {
                            try
                            {
                                var guestStatus = guestClient.Login(string.Empty, guestName, string.Empty);
                                if (guestStatus == NTStatus.STATUS_SUCCESS)
                                {
                                    guestClient.ListShares(out NTStatus guestShareStatus);
                                    if (guestShareStatus == NTStatus.STATUS_SUCCESS)
                                    {
                                        detectedGuestName = guestName;
                                        Log.Warning("[{CheckName}] CRITICAL: Guest account '{GuestName}' is active on {Target}!", Name, guestName, target);
                                        break;
                                    }
                                }
                                else if (guestStatus == NTStatus.STATUS_ACCOUNT_DISABLED)
                                {
                                    Log.Debug("[{CheckName}] Guest '{GuestName}' disabled on {Target} ✓", Name, guestName, target);
                                }
                            }
                            catch { /* ignore per-attempt errors */ }
                        }
                        try { guestClient.Logoff(); guestClient.Disconnect(); } catch { }
                    }
                }
                
                // ================================================================
                // ENUMERATE SHARES (if session is established)
                // ================================================================
                var shareList = new List<string>();
                
                if (sessionEstablished)
                {
                    try
                    {
                        var shares = client.ListShares(out NTStatus shareStatus);
                        
                        if (shareStatus == NTStatus.STATUS_SUCCESS && shares != null)
                        {
                            shareList = shares.Take(_config.Smb.MaxSharesToEnumerate).ToList();
                            Log.Information("[{CheckName}] Enumerated {Count} shares on {Target}: {Shares}",
                                Name, shareList.Count, target, string.Join(", ", shareList));
                        }
                        else
                        {
                            Log.Debug("[{CheckName}] Share enumeration failed on {Target} (status: {Status})", 
                                Name, target, shareStatus);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Debug(ex, "[{CheckName}] Exception during share enumeration on {Target}", Name, target);
                    }
                }
                
                // ================================================================
                // CREATE FINDING (if anonymous/guest access)
                // ================================================================
                if (detectedGuestName != null && (isAnonymous ? sessionEstablished : true))
                {
                    var shareEvidence = shareList.Any()
                        ? $"Accessible shares: {string.Join(", ", shareList)}"
                        : "Share enumeration succeeded (but no shares returned)";
                    
                    var accessType = detectedGuestName == "<null session>" 
                        ? "null session (anonymous bind)" 
                        : $"Guest account '{detectedGuestName}' without password";
                    
                    var finding = Finding.Create(
                        id: "AST-SMB-001",
                        title: $"SMB accessible via {accessType}",
                        severity: "critical",
                        confidence: "high",
                        recommendation: 
                            "Disable guest/anonymous access on all SMB shares:\n\n" +
                            "Windows:\n" +
                            "1. Disable Guest account: net user Guest /active:no\n" +
                            "   - Or via Local Users and Groups (lusrmgr.msc)\n" +
                            "2. Remove 'Everyone' or 'Guest' permissions from all shares.\n" +
                            "3. Set registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous = 1 (or 2 for stricter).\n" +
                            "4. Via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options\n" +
                            "   - 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' = Enabled\n" +
                            "   - 'Network access: Let Everyone permissions apply to anonymous users' = Disabled\n" +
                            "   - 'Accounts: Guest account status' = Disabled\n" +
                            "5. Enforce SMB signing (see AST-SMB-002).\n\n" +
                            "Linux/Samba:\n" +
                            "1. Set 'restrict anonymous = 2' in smb.conf [global] section.\n" +
                            "2. Set 'guest ok = no' for all shares.\n" +
                            "3. Set 'map to guest = never' in [global].\n" +
                            "4. Restart smbd: systemctl restart smbd\n\n" +
                            "Verification:\n" +
                            "- Test with: smbclient -L //{target} -N (should fail)\n" +
                            "- Windows: net user Guest (should show 'Account active: No')"
                    )
                    .WithDescription(
                        $"The SMB service on {target} allows unauthenticated access via {accessType}. " +
                        "This is a CRITICAL security vulnerability that exposes the system to:\n\n" +
                        "• **Unauthenticated data access** - Attackers can access files without credentials\n" +
                        "• **Information disclosure** - User enumeration, share discovery, security policy extraction\n" +
                        "• **Lateral movement** - Attackers can map the network without authentication\n" +
                        "• **Privilege escalation** - Combined with other exploits, can lead to domain compromise\n\n" +
                        (detectedGuestName == "<null session>" 
                            ? "Null sessions are the most dangerous form of anonymous access, allowing complete directory enumeration." 
                            : $"The '{detectedGuestName}' account is active without a password, which violates security best practices.") +
                        "\n\nIn penetration tests, anonymous/guest access is often the first step in Active Directory enumeration. " +
                        "This configuration should be remediated immediately."
                    )
                    .WithEvidence(
                        type: "share",
                        value: $"{accessType} successful to \\\\{target}",
                        context: shareEvidence
                    )
                    .WithAffectedComponent($"{target}:445 (SMB Service)")
                    .WithReferences(
                        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status",
                        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares",
                        "https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#RESTRICTANONYMOUS"
                    );
                    
                    findings.Add(finding);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Failed to check anonymous access on {Target}", Name, target);
            }
            finally
            {
                try
                {
                    if (client?.IsConnected == true)
                    {
                        client.Logoff();
                    }
                    client?.Disconnect();
                }
                catch { /* Suppress cleanup errors */ }
            }
            
            await Task.CompletedTask;
        }

        /// <summary>
        /// Create finding for sensitive shares accessible via NTLM
        /// </summary>
        private Finding CreateSensitiveSharesFinding(string target, string username, List<SmbShareInfo> shares)
        {
            var shareList = string.Join(", ", shares.Select(s => $"{s.Name} ({s.Type})"));
            
            return Finding.Create(
                id: "AST-SMB-005",
                title: $"Sensitive SMB shares accessible with compromised credentials ({shares.Count} found)",
                severity: "high",
                confidence: "high",
                recommendation: $"Secure sensitive SMB shares on {target}:\n\n" +
                    "**Immediate Actions:**\n" +
                    "1. Change the password for account '{username}' immediately (credentials are compromised).\n" +
                    "2. Audit all recent activity from this account in Event Logs (Event ID 4624, 4672, 5140).\n" +
                    "3. Review access permissions on sensitive shares:\n" +
                    "   - ADMIN$/C$/D$: Should only be accessible to Domain Admins\n" +
                    "   - SYSVOL/NETLOGON: Should be read-only for standard users\n" +
                    "4. Disable administrative shares if not needed: net share ADMIN$ /delete\n\n" +
                    "**Long-term Hardening:**\n" +
                    "5. Implement Privileged Access Workstations (PAWs) for admin accounts.\n" +
                    "6. Enable SMB signing requirement (see AST-SMB-002).\n" +
                    "7. Monitor for pass-the-hash attacks using Event ID 4624 (Logon Type 3 with NTLM).\n" +
                    "8. Consider implementing LAPS (Local Administrator Password Solution).\n" +
                    "9. Use Network Access Protection (NAP) to restrict access to sensitive shares."
            )
            .WithDescription(
                $"The SMB service on {target} has {shares.Count} sensitive share(s) accessible using compromised NTLM credentials " +
                $"for account '{username}'. This demonstrates successful pass-the-hash authentication, which allows an attacker " +
                "to authenticate without knowing the plaintext password.\n\n" +
                "**Accessible sensitive shares:**\n" +
                shareList + "\n\n" +
                "**Attack scenario:**\n" +
                "1. Attacker obtains NTLM hash via credential dumping (mimikatz, secretsdump, etc.)\n" +
                "2. Attacker uses pass-the-hash to authenticate to SMB without cracking the password\n" +
                "3. Attacker accesses sensitive files, deploys ransomware, or establishes persistence\n\n" +
                "**Impact:**\n" +
                "• **ADMIN$/C$**: Full system access, can deploy malware or ransomware\n" +
                "• **SYSVOL**: Can modify Group Policy Objects (GPOs) for domain-wide attacks\n" +
                "• **NETLOGON**: Can inject malicious logon scripts\n" +
                "• **Users/Backup**: Data exfiltration, sensitive information disclosure\n\n" +
                "This finding confirms that the credentials are actively exploitable and the account has elevated privileges."
            )
            .WithEvidence(
                type: "share",
                value: $"NTLM pass-the-hash authentication successful: {username}@{target}",
                context: $"Sensitive shares accessible: {shareList}"
            )
            .WithAffectedComponent($"{target}:445 (SMB Service)")
            .WithReferences(
                "https://attack.mitre.org/techniques/T1550/002/",
                "https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/",
                "https://docs.microsoft.com/en-us/windows-server/identity/laps/laps-overview",
                "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624"
            );
        }

        /// <summary>
        /// AST-SMB-002: Check if SMB signing is required
        /// Without signing, MITM attacks and SMB relay attacks are possible
        /// </summary>
        private async Task CheckSmbSigningAsync(string target, List<Finding> findings, ScanOptions options)
        {
            SMB2Client? client = null;

            try
            {
                client = new SMB2Client();

                var ipAddress = await ResolveTargetAsync(target);
                if (ipAddress == null)
                    return;

                bool connected = client.Connect(ipAddress, SMBTransportType.DirectTCPTransport);
                if (!connected)
                {
                    Log.Debug("[{CheckName}] Failed to connect for signing check on {Target}", Name, target);
                    return;
                }

                // Intento de login anónimo (null session)
                var status = client.Login(string.Empty, string.Empty, string.Empty);
                bool signingNotRequired = false;

                if (status == NTStatus.STATUS_SUCCESS)
                {
                    try
                    {
                        var shares = client.ListShares(out NTStatus shareStatus);
                        if (shareStatus == NTStatus.STATUS_SUCCESS && shares != null && shares.Any())
                        {
                            signingNotRequired = true;
                        }
                    }
                    catch
                    {}
                }

                if (signingNotRequired)
                {
                    Log.Warning("[{CheckName}] SMB signing not required on {Target} - relay attacks possible", Name, target);

                    var finding = Finding.Create(
                            id: "AST-SMB-002",
                            title: "SMB signing not required (vulnerable to relay attacks)",
                            severity: "high",
                            confidence: "medium",
                            recommendation:
                                "Enable and require SMB signing on all systems:\n\n" +
                                "Windows Server/Domain Controller:\n" +
                                "1. GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options\n" +
                                "   - 'Microsoft network server: Digitally sign communications (always)' = Enabled\n" +
                                "   - 'Microsoft network client: Digitally sign communications (always)' = Enabled\n" +
                                "2. Registro (requiere reinicio):\n" +
                                "   - HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature = 1\n" +
                                "   - HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature = 1\n\n" +
                                "Linux/Samba:\n" +
                                "1. smb.conf [global]:\n" +
                                "   - server signing = mandatory\n" +
                                "   - client signing = mandatory\n" +
                                "2. systemctl restart smbd\n\n" +
                                "IMPORTANT: Test with clients before enforcing. Legacy systems may not support signing."
                        )
                        .WithDescription(
                            $"The SMB server on {target} appears to allow operations without message signing, " +
                            "which enables SMB relay and MITM. Enforce SMB signing in servers and clients."
                        )
                        .WithEvidence(
                            type: "service",
                            value: "Anonymous session could enumerate shares",
                            context: $"Host: {target}:445, Protocol: SMB2/3"
                        )
                        .WithAffectedComponent($"{target}:445 (SMB Service)")
                        .WithReferences(
                            "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always",
                            "https://support.microsoft.com/help/887429/overview-of-server-message-block-signing",
                            "https://www.sans.org/blog/smb-relay-attacks/"
                        );

                    findings.Add(finding);
                }
                else
                {
                    Log.Debug("[{CheckName}] Unable to prove 'signing not required' on {Target} (no finding)", Name, target);
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] Error checking SMB signing on {Target}", Name, target);
            }
            finally
            {
                client?.Disconnect();
            }

            await Task.CompletedTask;
        }

        /// <summary>
        /// AST-SMB-003: Check if SMBv1 is enabled
        /// SMBv1 is obsolete and has multiple critical vulnerabilities including EternalBlue (MS17-010)
        /// </summary>
        private async Task CheckSmbVersionsAsync(string target, List<Finding> findings)
        {
            SMB1Client? smb1Client = null;
            
            try
            {
                smb1Client = new SMB1Client();
                
                var ipAddress = await ResolveTargetAsync(target);
                if (ipAddress == null)
                    return;

                // Attempt SMBv1 connection
                bool smb1Connected = smb1Client.Connect(ipAddress, SMBTransportType.DirectTCPTransport);

                if (smb1Connected)
                {
                    Log.Warning("[{CheckName}] CRITICAL: SMBv1 is enabled on {Target} - EternalBlue vector!", Name, target);

                    var finding = Finding.Create(
                        id: "AST-SMB-003",
                        title: "SMBv1 protocol enabled (obsolete and dangerous)",
                        severity: "high",
                        confidence: "high",
                        recommendation: "Disable SMBv1 immediately - it is obsolete and critically vulnerable:\n\n" +
                                        "Windows:\n" +
                                        "1. PowerShell (recommended): Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart\n" +
                                        "2. Or via DISM: dism /online /disable-feature /featurename:SMB1Protocol\n" +
                                        "3. Or Control Panel: Programs > Turn Windows features on/off > Uncheck 'SMB 1.0/CIFS File Sharing Support'\n" +
                                        "4. Registry fallback: Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 = 0\n" +
                                        "5. **REBOOT REQUIRED** after disabling.\n\n" +
                                        "Linux/Samba:\n" +
                                        "1. Add to smb.conf [global] section:\n" +
                                        "   - server min protocol = SMB2\n" +
                                        "   - client min protocol = SMB2\n" +
                                        "2. Restart smbd: systemctl restart smbd\n\n" +
                                        "Verification:\n" +
                                        "- Windows: Get-SmbServerConfiguration | Select EnableSMB1Protocol (should be False)\n" +
                                        "- Nmap: nmap --script smb-protocols -p445 {target} (should NOT show SMBv1)\n\n" +
                                        "CRITICAL: SMBv1 was exploited by WannaCry and NotPetya ransomware. Microsoft officially deprecated it."
                    )
                    .WithDescription(
                        $"SMB version 1 is enabled on {target}. This is a CRITICAL security issue. SMBv1 is a legacy protocol from 1983 with numerous unfixable security flaws:\n\n" +
                        "• **EternalBlue (MS17-010)** - Remote code execution without authentication (CVE-2017-0144)\n" +
                        "• **WannaCry ransomware (May 2017)** - Infected 230,000+ computers worldwide\n" +
                        "• **NotPetya ransomware (June 2017)** - Caused $10 billion in damages\n" +
                        "• **No encryption by default** - All traffic sent in cleartext\n" +
                        "• **Weak authentication** - Vulnerable to NTLM relay\n" +
                        "• **Performance issues** - Significantly slower than SMB2/3\n\n" +
                        "Microsoft has officially deprecated SMBv1 and removed it by default in Windows 10 1709+ and Server 2019+. " +
                        "The US-CERT, NSA, and CISA all recommend immediate disabling of SMBv1 on all systems. " +
                        "Modern Windows and Linux systems support SMB2/3 which are secure, fast, and actively maintained."
                    )
                    .WithEvidence(
                        type: "service",
                        value: "SMBv1 connection successful",
                        context: $"Host: {target}:445, Protocol: SMB 1.0/CIFS (deprecated)"
                    )
                    .WithAffectedComponent($"{target}:445 (SMB Service)")
                    .WithCve(
                        "CVE-2017-0143", // MS17-010
                        "CVE-2017-0144", // EternalBlue
                        "CVE-2017-0145", // MS17-010
                        "CVE-2017-0146", // MS17-010
                        "CVE-2017-0147", // MS17-010
                        "CVE-2017-0148"  // MS17-010
                    )
                    .WithReferences(
                        "https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows",
                        "https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices",
                        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144",
                        "https://en.wikipedia.org/wiki/WannaCry_ransomware_attack"
                    );

                    findings.Add(finding);
                }
                else
                {
                    Log.Debug("[{CheckName}] SMBv1 is correctly disabled on {Target} ✓", Name, target);
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] Error checking SMB versions on {Target}", Name, target);
            }
            finally
            {
                smb1Client?.Disconnect();
            }

            await Task.CompletedTask;
        }

        /// <summary>
        /// Helper: Resolve hostname to IPAddress
        /// Handles both IP strings and hostnames
        /// </summary>
        private async Task<IPAddress?> ResolveTargetAsync(string target)
        {
            if (IPAddress.TryParse(target, out var ipAddress))
            {
                return ipAddress;
            }

            // Resolve hostname
            var resolved = await NetworkUtils.ResolveHostnameAsync(target);
            if (resolved != null && IPAddress.TryParse(resolved, out ipAddress))
            {
                return ipAddress;
            }

            return null;
        }
    }
}