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
    /// Active Directory aggressive-mode checks.
    /// Requires domain credentials (--auth) and aggressive mode.
    ///
    /// Findings:
    /// - AST-AD-010: AS-REP Roasting — accounts with DONT_REQ_PREAUTH flag
    /// - AST-AD-012: Weak ACLs — GenericAll / WriteDACL on non-admin objects
    /// </summary>
    public class AdAggressiveCheck : BaseCheck
    {
        private const int LDAP_PORT = 389;

        public override string Name => "AD Aggressive Check";
        public override CheckCategory Category => CheckCategory.CrossPlatform;
        public override string Description =>
            "Aggressive Active Directory enumeration: AS-REP roastable accounts and " +
            "weak ACLs (GenericAll/WriteDACL) on domain objects.";

        public override bool RequiresAuthentication => true;
        public override bool RequiresAggressiveMode => true;

        public AdAggressiveCheck(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            if (string.IsNullOrEmpty(options.AuthCredentials) &&
                string.IsNullOrEmpty(options.KerberosCredentials))
            {
                Log.Debug("[{CheckName}] No credentials provided — skipping AD aggressive checks", Name);
                return new List<Finding>();
            }

            var findings = new List<Finding>();

            foreach (var target in targets)
            {
                try
                {
                    if (!await NetworkUtils.IsPortOpenAsync(target, LDAP_PORT,
                        _config.Scan.Timeout.Connect * 1000))
                    {
                        Log.Debug("[{CheckName}] LDAP not open on {Target}", Name, target);
                        continue;
                    }

                    using var connection = BuildAuthenticatedConnection(target, options);
                    if (connection == null)
                    {
                        Log.Warning("[{CheckName}] Authentication failed on {Target}", Name, target);
                        continue;
                    }

                    // Read naming context
                    var defaultNc = ReadDefaultNamingContext(connection);
                    if (string.IsNullOrEmpty(defaultNc))
                    {
                        Log.Debug("[{CheckName}] Could not read defaultNamingContext on {Target}", Name, target);
                        continue;
                    }

                    Log.Information("[{CheckName}] Connected to {Target}, NC: {NC}", Name, target, defaultNc);

                    // AS-REP Roasting
                    var asrepAccounts = FindAsRepRoastableAccounts(connection, defaultNc);
                    if (asrepAccounts.Any())
                        findings.Add(CreateAsRepFinding(target, defaultNc, asrepAccounts));

                    // Weak ACLs
                    var weakAcls = FindWeakAcls(connection, defaultNc);
                    if (weakAcls.Any())
                        findings.Add(CreateWeakAclFinding(target, defaultNc, weakAcls));
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "[{CheckName}] Failed on {Target}", Name, target);
                }
            }

            LogExecution(targets.Count, findings.Count);
            return findings;
        }

        // ─── Connection ────────────────────────────────────────────────────────

        private LdapConnection? BuildAuthenticatedConnection(string host, ScanOptions options)
        {
            var authMgr = new AuthMgr();
            NetworkCredential? cred = null;

            if (!string.IsNullOrEmpty(options.KerberosCredentials))
            {
                (string? kUser, string? kPass, string? kRealm) = authMgr.ParseKerberosCredentials(options.KerberosCredentials);
                if (!string.IsNullOrEmpty(kUser) && !string.IsNullOrEmpty(kPass))
                    cred = new NetworkCredential(kUser, kPass, kRealm);
            }
            else if (!string.IsNullOrEmpty(options.AuthCredentials))
            {
                (string? aUser, string? aPass, string? aDomain) = ParseCredentials(options.AuthCredentials);
                if (!string.IsNullOrEmpty(aUser) && !string.IsNullOrEmpty(aPass))
                    cred = new NetworkCredential(aUser, aPass, aDomain);
            }

            if (cred == null) return null;

            try
            {
                var conn = new LdapConnection(new LdapDirectoryIdentifier(host, LDAP_PORT))
                {
                    Timeout = TimeSpan.FromSeconds(_config.Ldap.TimeoutSeconds),
                    AuthType = AuthType.Basic,
                    Credential = cred
                };
                conn.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                conn.Bind();
                return conn;
            }
            catch (LdapException ex)
            {
                Log.Warning("[{CheckName}] LDAP bind failed on {Host}: {Msg}", Name, host, ex.Message);
                return null;
            }
        }

        private string? ReadDefaultNamingContext(LdapConnection conn)
        {
            try
            {
                var req = new SearchRequest(null, "(objectClass=*)", SearchScope.Base,
                    new[] { "defaultNamingContext" });
                var resp = (SearchResponse)conn.SendRequest(req);
                if (resp.Entries.Count > 0 && resp.Entries[0].Attributes.Contains("defaultNamingContext"))
                    return resp.Entries[0].Attributes["defaultNamingContext"][0]?.ToString();
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] ReadDefaultNamingContext failed", Name);
            }
            return null;
        }

        // ─── AS-REP Roasting (AST-AD-010) ────────────────────────────────────

        /// <summary>
        /// Find accounts with DONT_REQ_PREAUTH (UAC flag 0x400000 = 4194304).
        /// These accounts can be AS-REP roasted without credentials.
        /// </summary>
        private List<string> FindAsRepRoastableAccounts(LdapConnection conn, string baseDn)
        {
            var accounts = new List<string>();
            try
            {
                // DONT_REQ_PREAUTH = 0x400000 = 4194304
                var filter = "(&(objectClass=user)(objectCategory=person)" +
                             "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" +
                             "(!userAccountControl:1.2.840.113556.1.4.803:=2))"; // exclude disabled
                var req = new SearchRequest(baseDn, filter, SearchScope.Subtree,
                    new[] { "sAMAccountName" });
                req.SizeLimit = 500;

                var resp = (SearchResponse)conn.SendRequest(req);
                foreach (SearchResultEntry entry in resp.Entries)
                {
                    var sam = entry.Attributes.Contains("sAMAccountName")
                        ? entry.Attributes["sAMAccountName"][0]?.ToString()
                        : null;
                    if (!string.IsNullOrEmpty(sam))
                        accounts.Add(sam);
                }

                if (accounts.Any())
                    Log.Warning("[{CheckName}] AS-REP roastable accounts: {Accounts}",
                        Name, string.Join(", ", accounts));
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] FindAsRepRoastableAccounts failed", Name);
            }
            return accounts;
        }

        private Finding CreateAsRepFinding(string target, string baseDn, List<string> accounts)
        {
            var accountList = string.Join(", ", accounts.Take(20));
            if (accounts.Count > 20) accountList += $" (+{accounts.Count - 20} more)";

            return Finding.Create(
                id: "AST-AD-010",
                title: $"AS-REP Roasting — {accounts.Count} account(s) without Kerberos pre-authentication",
                severity: "high",
                confidence: "high",
                recommendation:
                    "Enable Kerberos pre-authentication for all user accounts (it's the default and should be the exception to disable):\n" +
                    "1. Find: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select Name,SamAccountName\n" +
                    "2. Fix: Set-ADUser -Identity <user> -DoesNotRequirePreAuth $false\n" +
                    "3. For service accounts that need this flag: use strong passwords (25+ chars) to slow cracking.\n" +
                    "4. Monitor for AS-REP requests in Event ID 4768."
            )
            .WithDescription(
                $"Found {accounts.Count} Active Directory account(s) with Kerberos pre-authentication disabled " +
                "(DONT_REQ_PREAUTH UAC flag). An attacker can request an encrypted AS-REP message for these accounts " +
                "without knowing the password, then crack the hash offline (AS-REP Roasting)."
            )
            .WithEvidence(
                type: "ldap",
                value: $"AS-REP roastable accounts: {accountList}",
                context: $"Domain: {baseDn} | LDAP filter: userAccountControl:DONT_REQ_PREAUTH (0x400000)"
            )
            .WithAffectedComponent($"Domain: {baseDn}")
            .WithReferences(
                "https://attack.mitre.org/techniques/T1558/004/",
                "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat"
            );
        }

        // ─── Weak ACLs (AST-AD-012) ───────────────────────────────────────────

        /// <summary>
        /// Find users with GenericAll or WriteDACL on high-value objects (non-admin users, computers).
        /// NOTE: Full ACL reading requires DirectoryEntry / Windows ADSI. Via cross-platform LDAP
        /// we can read the nTSecurityDescriptor attribute (raw binary) and parse ACEs.
        /// For non-Windows platforms, we do a best-effort check on a curated set of sensitive targets.
        /// </summary>
        private List<(string Object, string Right, string Trustee)> FindWeakAcls(
            LdapConnection conn, string baseDn)
        {
            var results = new List<(string, string, string)>();

            // Targets to check: Domain root, AdminSDHolder, Domain Admins group
            var sensitiveObjects = new List<string>
            {
                baseDn,
                $"CN=AdminSDHolder,CN=System,{baseDn}",
                $"CN=Domain Admins,CN=Users,{baseDn}",
                $"CN=Enterprise Admins,CN=Users,{baseDn}",
            };

            // Well-known privileged SIDs to exclude from "unexpected" checks
            var privilegedSidPrefixes = new[] { "S-1-5-32-544", "S-1-5-18", "S-1-5-9" }; // Admins, SYSTEM, ENTERPRISE DC

            foreach (var dn in sensitiveObjects)
            {
                try
                {
                    var req = new SearchRequest(dn, "(objectClass=*)", SearchScope.Base,
                        new[] { "nTSecurityDescriptor" });
                    req.Controls.Add(new SecurityDescriptorFlagControl(SecurityMasks.Dacl));
                    req.SizeLimit = 1;

                    var resp = (SearchResponse)conn.SendRequest(req);
                    if (resp.Entries.Count == 0) continue;

                    var entry = resp.Entries[0];
                    if (!entry.Attributes.Contains("nTSecurityDescriptor")) continue;

                    var rawSd = (byte[])entry.Attributes["nTSecurityDescriptor"][0];
                    var parsed = ParseDaclForWeakAces(rawSd, privilegedSidPrefixes);
                    foreach (var (right, trustee) in parsed)
                        results.Add((dn, right, trustee));
                }
                catch (DirectoryOperationException ex) when (
                    ex.Message.Contains("00002098") || // insufficient access rights to read SD
                    ex.Message.Contains("noSuchObject"))
                {
                    Log.Debug("[{CheckName}] SD read denied for {DN}", Name, dn);
                }
                catch (Exception ex)
                {
                    Log.Debug(ex, "[{CheckName}] ACL check failed for {DN}", Name, dn);
                }
            }

            return results;
        }

        /// <summary>
        /// Parse raw Windows Security Descriptor DACL bytes looking for
        /// GenericAll (0x10000000) or WriteDACL (0x00040000) ACEs granted to non-privileged SIDs.
        /// Returns (right, trustee_sid) tuples for suspicious entries.
        /// </summary>
        private List<(string Right, string Trustee)> ParseDaclForWeakAces(
            byte[] rawSd, string[] excludedPrefixes)
        {
            var found = new List<(string, string)>();
            try
            {
                // Windows Security Descriptor binary format (little-endian):
                // Offset 0: Revision (1 byte)
                // Offset 2: Control flags (2 bytes)
                // Offset 4: OwnerOffset (4 bytes)
                // Offset 8: GroupOffset (4 bytes)
                // Offset 12: SaclOffset (4 bytes)
                // Offset 16: DaclOffset (4 bytes)
                if (rawSd.Length < 20) return found;

                int daclOffset = BitConverter.ToInt32(rawSd, 16);
                if (daclOffset == 0 || daclOffset >= rawSd.Length) return found;

                // ACL header: Revision(1), Sbz1(1), AclSize(2), AceCount(2), Sbz2(2)
                int aceCount = BitConverter.ToInt16(rawSd, daclOffset + 4);
                int acePos = daclOffset + 8;

                for (int i = 0; i < aceCount && acePos < rawSd.Length; i++)
                {
                    if (acePos + 4 > rawSd.Length) break;
                    byte aceType = rawSd[acePos];       // 0=Allow, 1=Deny
                    int aceSize = BitConverter.ToInt16(rawSd, acePos + 2);

                    if (aceSize < 8 || acePos + aceSize > rawSd.Length)
                        break;

                    if (aceType == 0) // ACCESS_ALLOWED_ACE
                    {
                        uint accessMask = BitConverter.ToUInt32(rawSd, acePos + 4);
                        bool isGenericAll = (accessMask & 0x10000000u) != 0;
                        bool isWriteDacl  = (accessMask & 0x00040000u) != 0;
                        bool isWriteOwner = (accessMask & 0x00080000u) != 0;

                        if (isGenericAll || isWriteDacl || isWriteOwner)
                        {
                            // SID starts at acePos + 8
                            var sid = ParseSid(rawSd, acePos + 8);
                            if (!string.IsNullOrEmpty(sid) &&
                                !excludedPrefixes.Any(p => sid.StartsWith(p)))
                            {
                                var right = isGenericAll ? "GenericAll"
                                          : isWriteDacl  ? "WriteDACL"
                                          : "WriteOwner";
                                found.Add((right, sid));
                            }
                        }
                    }

                    acePos += aceSize;
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] ParseDaclForWeakAces error", Name);
            }
            return found;
        }

        /// <summary>
        /// Parse a SID from binary representation starting at offset in buffer.
        /// Returns "S-R-A-..." string format.
        /// </summary>
        private static string? ParseSid(byte[] buf, int offset)
        {
            try
            {
                if (offset + 8 > buf.Length) return null;
                byte revision = buf[offset];
                byte subAuthCount = buf[offset + 1];
                if (offset + 8 + subAuthCount * 4 > buf.Length) return null;

                // Identifier authority (6 bytes big-endian)
                long authority = 0;
                for (int j = 0; j < 6; j++)
                    authority = (authority << 8) | buf[offset + 2 + j];

                var sb = new System.Text.StringBuilder($"S-{revision}-{authority}");
                for (int j = 0; j < subAuthCount; j++)
                {
                    uint subAuth = BitConverter.ToUInt32(buf, offset + 8 + j * 4);
                    sb.Append($"-{subAuth}");
                }
                return sb.ToString();
            }
            catch
            {
                return null;
            }
        }

        private Finding CreateWeakAclFinding(string target, string baseDn,
            List<(string Object, string Right, string Trustee)> weakAcls)
        {
            var lines = weakAcls.Take(20).Select(a =>
                $"  • [{a.Right}] on {a.Object.Split(',')[0]} → {a.Trustee}");
            var summary = string.Join("\n", lines);
            if (weakAcls.Count > 20)
                summary += $"\n  ... (+{weakAcls.Count - 20} more)";

            return Finding.Create(
                id: "AST-AD-012",
                title: $"Weak AD ACLs detected — GenericAll/WriteDACL on sensitive objects ({weakAcls.Count})",
                severity: "critical",
                confidence: "medium",
                recommendation:
                    "Remove unnecessary permissions from sensitive AD objects:\n" +
                    "1. Audit ACLs: (Get-Acl 'AD:\\<DN>').Access | Where-Object {$_.AccessControlType -eq 'Allow'}\n" +
                    "2. Remove GenericAll/WriteDACL from non-admin accounts on Domain root, AdminSDHolder, DA group.\n" +
                    "3. Run BloodHound to map full privilege escalation paths.\n" +
                    "4. Use Protected Users group for all privileged accounts.\n" +
                    "5. Enable AD Recycle Bin and audit ACL changes (Event ID 5136)."
            )
            .WithDescription(
                $"Detected {weakAcls.Count} ACE(s) granting powerful rights (GenericAll, WriteDACL, WriteOwner) " +
                "to non-privileged SIDs on sensitive AD objects. These permissions enable full object takeover: " +
                "an account with WriteDACL can grant itself any other right, and GenericAll allows resetting passwords, " +
                "adding group members, or configuring delegation."
            )
            .WithEvidence(
                type: "ldap",
                value: $"Weak ACEs:\n{summary}",
                context: $"Domain: {baseDn} | Check: nTSecurityDescriptor DACL parse"
            )
            .WithAffectedComponent($"Domain: {baseDn}")
            .WithReferences(
                "https://attack.mitre.org/techniques/T1222/001/",
                "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces"
            );
        }
    }
}
