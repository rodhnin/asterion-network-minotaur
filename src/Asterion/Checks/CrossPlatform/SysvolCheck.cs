using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Serilog;
using Asterion.Core;
using Asterion.Core.Utils;
using Asterion.Models;
using SMBLibrary;
using SMBLibrary.Client;
using AuthMgr = Asterion.Core.Utils.AuthenticationManager;

namespace Asterion.Checks.CrossPlatform
{
    /// <summary>
    /// SYSVOL GPP/cpassword Scanner — MS14-025
    ///
    /// Detects Group Policy Preferences (GPP) files on SYSVOL that contain
    /// encrypted credentials (cpassword attribute). The AES-256 key used to
    /// encrypt these passwords was published by Microsoft in MSDN documentation,
    /// making all cpassword values trivially decryptable.
    ///
    /// Finding codes:
    /// - AST-SYSVOL-001: GPP cpassword found in Groups.xml     (CRITICAL)
    /// - AST-SYSVOL-002: GPP cpassword found in other GPP files (CRITICAL)
    /// - AST-SYSVOL-003: SYSVOL accessible anonymously          (HIGH)
    ///
    /// References:
    /// - MS14-025: https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30
    /// - CVE-2014-1812
    /// - PowerSploit Get-GPPPassword
    /// </summary>
    public class SysvolCheck : BaseCheck
    {
        public override string Name => "SYSVOL GPP/cpassword Scanner";
        public override CheckCategory Category => CheckCategory.CrossPlatform;
        public override string Description =>
            "Searches SYSVOL for Group Policy Preferences files (Groups.xml, Services.xml, " +
            "Scheduledtasks.xml, Datasources.xml, Printers.xml) containing encrypted cpassword " +
            "credentials (MS14-025 / CVE-2014-1812). The Microsoft-published AES key makes " +
            "these passwords trivially decryptable.";

        public override bool RequiresAuthentication => false; // Can find with null session, better with creds
        public override bool RequiresAggressiveMode => false; // Reading SYSVOL is not intrusive

        // GPP files that can contain cpassword
        private static readonly string[] GppFiles =
        {
            "Groups.xml",
            "Services.xml",
            "ScheduledTasks.xml",
            "Datasources.xml",
            "Printers.xml"
        };

        // Microsoft's published AES-256 key for GPP encryption (MSDN KB2962486)
        // This is intentionally hardcoded — it IS the key Microsoft documented publicly.
        private static readonly byte[] GppAesKey = Convert.FromBase64String(
            "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b");

        public SysvolCheck(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var findings = new List<Finding>();
            Log.Information("[{CheckName}] Starting SYSVOL GPP scan on {Count} target(s)", Name, targets.Count);

            foreach (var target in targets)
            {
                try
                {
                    // SMB port must be open
                    if (!await NetworkUtils.IsPortOpenAsync(target, 445, 3000))
                    {
                        Log.Debug("[{CheckName}] SMB port not open on {Target}, skipping SYSVOL scan", Name, target);
                        continue;
                    }

                    await ScanSysvolAsync(target, findings, options);
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "[{CheckName}] Failed to scan SYSVOL on {Target}", Name, target);
                }
            }

            LogExecution(targets.Count, findings.Count);
            return findings;
        }

        private async Task ScanSysvolAsync(string target, List<Finding> findings, ScanOptions options)
        {
            var authManager = new AuthMgr();
            SMB2Client? client = null;

            try
            {
                client = new SMB2Client();
                bool connected = client.Connect(target, SMBTransportType.DirectTCPTransport);
                if (!connected)
                {
                    Log.Debug("[{CheckName}] Could not connect to {Target} via SMB2", Name, target);
                    return;
                }

                // Try to authenticate (null session first, then credentials if provided)
                NTStatus authStatus;
                string authUser = "anonymous";

                if (!string.IsNullOrEmpty(options.AuthCredentials))
                {
                    var (user, pass, domain) = authManager.ParseCredentials(options.AuthCredentials);
                    authStatus = client.Login(domain ?? string.Empty, user ?? string.Empty, pass ?? string.Empty);
                    authUser = $"{domain}\\{user}";
                    Log.Debug("[{CheckName}] Attempting auth as {User} on {Target}", Name, authUser, target);
                }
                else if (!string.IsNullOrEmpty(options.AuthNtlm))
                {
                    // NTLM hash pass-the-hash via SMBLibrary is not natively supported.
                    // Fall back to null session for SYSVOL enumeration.
                    Log.Debug("[{CheckName}] NTLM hash auth not supported for SYSVOL scan — using null session", Name);
                    authStatus = client.Login(string.Empty, string.Empty, string.Empty);
                }
                else
                {
                    // Null session
                    authStatus = client.Login(string.Empty, string.Empty, string.Empty);
                }

                bool authenticated = authStatus == NTStatus.STATUS_SUCCESS;

                if (!authenticated && (string.IsNullOrEmpty(options.AuthCredentials) && string.IsNullOrEmpty(options.AuthNtlm)))
                {
                    // Anonymous failed — log anonymous accessibility result
                    Log.Debug("[{CheckName}] Anonymous SYSVOL access denied on {Target}", Name, target);
                    return;
                }

                if (!authenticated)
                {
                    Log.Warning("[{CheckName}] Authentication failed on {Target} (status: {Status})", Name, target, authStatus);
                    return;
                }

                Log.Debug("[{CheckName}] Authenticated as {User} on {Target}", Name, authUser, target);

                // Try to access SYSVOL share
                var share = client.TreeConnect("SYSVOL", out NTStatus connectStatus);
                if (connectStatus != NTStatus.STATUS_SUCCESS || share == null)
                {
                    // Also try NETLOGON
                    share = client.TreeConnect("NETLOGON", out connectStatus);
                    if (connectStatus != NTStatus.STATUS_SUCCESS || share == null)
                    {
                        Log.Debug("[{CheckName}] Could not connect to SYSVOL/NETLOGON on {Target}", Name, target);
                        return;
                    }
                }

                // Check if null session could access SYSVOL
                if (authUser == "anonymous")
                {
                    findings.Add(Building.SysvolAnonymousAccess(target));
                    Log.Warning("[{CheckName}] SYSVOL accessible anonymously on {Target}", Name, target);
                }

                // Recursively search for GPP files containing cpassword
                var gppFindings = new List<(string filePath, string gppType, string decryptedPassword, string userName, string changed)>();
                await SearchSysvolForCpasswordAsync(share, @"\", gppFindings, 0);

                if (gppFindings.Count > 0)
                {
                    Log.Warning("[{CheckName}] Found {Count} GPP cpassword entries on {Target}", Name, gppFindings.Count, target);
                    foreach (var (filePath, gppType, decryptedPw, userName, changed) in gppFindings)
                    {
                        findings.Add(Building.GppCpasswordFinding(target, filePath, gppType, decryptedPw, userName, changed));
                    }
                }
                else
                {
                    Log.Information("[{CheckName}] No GPP cpassword entries found on {Target}", Name, target);
                }

                // Note: ISMBFileStore.CloseFile is called per-file; share is disconnected via client.Disconnect()
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[{CheckName}] Error during SYSVOL scan on {Target}", Name, target);
            }
            finally
            {
                try { client?.Disconnect(); } catch { /* ignore */ }
            }
        }

        private async Task SearchSysvolForCpasswordAsync(
            ISMBFileStore share,
            string directory,
            List<(string filePath, string gppType, string decryptedPw, string userName, string changed)> findings,
            int depth)
        {
            if (depth > 10) return; // Prevent infinite recursion

            try
            {
                // List directory entries
                NTStatus status = share.CreateFile(
                    out object? dirHandle,
                    out FileStatus fileStatus,
                    directory,
                    AccessMask.GENERIC_READ,
                    SMBLibrary.FileAttributes.Directory,
                    ShareAccess.Read | ShareAccess.Write,
                    CreateDisposition.FILE_OPEN,
                    CreateOptions.FILE_DIRECTORY_FILE,
                    null);

                if (status != NTStatus.STATUS_SUCCESS || dirHandle == null)
                    return;

                List<QueryDirectoryFileInformation> entries;
                status = share.QueryDirectory(out entries, dirHandle, "*", FileInformationClass.FileDirectoryInformation);
                share.CloseFile(dirHandle);

                if (status != NTStatus.STATUS_SUCCESS)
                    return;

                foreach (var entry in entries)
                {
                    if (entry is not FileDirectoryInformation info) continue;
                    var name = info.FileName;
                    if (name == "." || name == "..") continue;

                    var fullPath = directory.TrimEnd('\\') + "\\" + name;

                    if (info.FileAttributes.HasFlag(SMBLibrary.FileAttributes.Directory))
                    {
                        // Recurse into subdirectory
                        await SearchSysvolForCpasswordAsync(share, fullPath, findings, depth + 1);
                    }
                    else
                    {
                        // Check if this is a GPP file we care about
                        var upperName = name.ToUpperInvariant();
                        if (GppFiles.Any(g => g.ToUpperInvariant() == upperName))
                        {
                            await CheckGppFileForCpasswordAsync(share, fullPath, name, findings);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Debug("[SysvolCheck] Error listing directory {Dir}: {Msg}", directory, ex.Message);
            }
        }

        private Task CheckGppFileForCpasswordAsync(
            ISMBFileStore share,
            string filePath,
            string fileName,
            List<(string filePath, string gppType, string decryptedPw, string userName, string changed)> findings)
        {
            try
            {
                NTStatus status = share.CreateFile(
                    out object? fileHandle,
                    out FileStatus fileStatus,
                    filePath,
                    AccessMask.GENERIC_READ,
                    SMBLibrary.FileAttributes.Normal,
                    ShareAccess.Read,
                    CreateDisposition.FILE_OPEN,
                    CreateOptions.FILE_NON_DIRECTORY_FILE,
                    null);

                if (status != NTStatus.STATUS_SUCCESS || fileHandle == null)
                    return Task.CompletedTask;

                // Read file content
                var content = new StringBuilder();
                long offset = 0;
                while (true)
                {
                    status = share.ReadFile(out byte[] data, fileHandle, offset, 4096);
                    if (status != NTStatus.STATUS_SUCCESS || data == null || data.Length == 0)
                        break;
                    content.Append(Encoding.UTF8.GetString(data));
                    offset += data.Length;
                    if (data.Length < 4096) break;
                }
                share.CloseFile(fileHandle);

                var xmlContent = content.ToString();
                if (string.IsNullOrWhiteSpace(xmlContent) || !xmlContent.Contains("cpassword", StringComparison.OrdinalIgnoreCase))
                    return Task.CompletedTask;

                // Parse XML and extract cpassword entries
                try
                {
                    var doc = XDocument.Parse(xmlContent);
                    var cpasswordElements = doc.Descendants()
                        .Where(e => e.Attribute("cpassword") != null);

                    foreach (var elem in cpasswordElements)
                    {
                        var cpassword = elem.Attribute("cpassword")?.Value ?? string.Empty;
                        if (string.IsNullOrWhiteSpace(cpassword)) continue;

                        var userName = elem.Attribute("userName")?.Value
                                    ?? elem.Attribute("name")?.Value
                                    ?? elem.Parent?.Attribute("name")?.Value
                                    ?? "unknown";

                        var changed = elem.Parent?.Attribute("changed")?.Value
                                   ?? elem.Attribute("changed")?.Value
                                   ?? "unknown";

                        // Decrypt the cpassword
                        var decrypted = DecryptGppPassword(cpassword);

                        Log.Warning("[SysvolCheck] GPP cpassword found in {File} for user '{User}'", filePath, userName);
                        findings.Add((filePath, Path.GetFileNameWithoutExtension(fileName), decrypted, userName, changed));
                    }
                }
                catch (Exception xmlEx)
                {
                    Log.Debug("[SysvolCheck] XML parse error in {File}: {Msg}", filePath, xmlEx.Message);
                }
            }
            catch (Exception ex)
            {
                Log.Debug("[SysvolCheck] Error reading GPP file {File}: {Msg}", filePath, ex.Message);
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// Decrypt a GPP cpassword value using Microsoft's published AES-256 key.
        /// Key source: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be
        /// </summary>
        private static string DecryptGppPassword(string cpassword)
        {
            try
            {
                // GPP uses standard Base64 with padding
                var padded = cpassword.Length % 4 == 0
                    ? cpassword
                    : cpassword + new string('=', 4 - cpassword.Length % 4);

                var cipherBytes = Convert.FromBase64String(padded);
                var iv = new byte[16]; // AES CBC with zero IV

                using var aes = Aes.Create();
                aes.Key = GppAesKey;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using var decryptor = aes.CreateDecryptor();
                using var ms = new MemoryStream(cipherBytes);
                using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
                using var sr = new StreamReader(cs, Encoding.Unicode);
                return sr.ReadToEnd();
            }
            catch
            {
                return "[decryption failed — raw cpassword: " + cpassword + "]";
            }
        }

        /// <summary>
        /// Inner class for building findings — keeps ExecuteAsync clean.
        /// </summary>
        private static class Building
        {
            public static Finding GppCpasswordFinding(
                string target, string filePath, string gppType, string decryptedPw, string userName, string changed)
            {
                var fileTypeLabel = gppType switch
                {
                    "Groups"         => "Local Groups (Groups.xml)",
                    "Services"       => "Windows Services (Services.xml)",
                    "ScheduledTasks" => "Scheduled Tasks (ScheduledTasks.xml)",
                    "Datasources"    => "Data Sources (Datasources.xml)",
                    "Printers"       => "Printers (Printers.xml)",
                    _                => gppType
                };

                var findingId = gppType == "Groups" ? "AST-SYSVOL-001" : "AST-SYSVOL-002";

                return Finding.Create(
                    id: findingId,
                    title: $"GPP cpassword found in SYSVOL — {fileTypeLabel}",
                    severity: "critical",
                    confidence: "high",
                    recommendation:
                        "1. Apply Microsoft patch KB2962486 (included in MS14-025) immediately.\n\n" +
                        "2. Remove all GPP password policies from Group Policy:\n" +
                        "   Group Policy Management → Edit GPO → Computer/User Configuration →\n" +
                        "   Preferences → Control Panel Settings → [category with cpassword]\n\n" +
                        "3. IMMEDIATELY rotate ALL passwords found in SYSVOL — they are fully decrypted.\n\n" +
                        "4. Search all SYSVOL for remaining cpassword entries:\n" +
                        "   findstr /S /I cpassword \\\\<DC>\\SYSVOL\\<domain>\\Policies\\\n\n" +
                        "5. Use LAPS (Local Administrator Password Solution) for local admin accounts instead.\n\n" +
                        "6. Audit who had access to SYSVOL in the past — assume all cpassword credentials compromised."
                )
                .WithDescription(
                    $"A Group Policy Preferences (GPP) file in SYSVOL contains a `cpassword` attribute for " +
                    $"user **`{userName}`** (last changed: {changed}).\n\n" +
                    "**Why this is critical:**\n" +
                    "Microsoft published the AES-256 encryption key used for GPP passwords in their own MSDN " +
                    "documentation. This means any authenticated domain user (or anonymous user if SYSVOL " +
                    "is accessible) can read and fully decrypt these credentials.\n\n" +
                    "**MS14-025 (CVE-2014-1812):**\n" +
                    "- Affects all Windows versions that support Group Policy Preferences\n" +
                    "- ANY domain user can decrypt cpassword values — no privileges required\n" +
                    "- Tools: `Get-GPPPassword` (PowerSploit), `gpp-decrypt`, Metasploit `smb_enum_gpp`\n" +
                    "- Microsoft patched this in May 2014 by removing the UI for GPP passwords\n" +
                    "- **Existing cpassword entries in SYSVOL are NOT automatically removed by the patch**\n\n" +
                    $"**Decrypted password recovered from `{filePath}`:**\n" +
                    $"```\n{decryptedPw}\n```"
                )
                .WithEvidence(
                    type: "config",
                    value: $"cpassword attribute in {filePath} (user: {userName}, changed: {changed})",
                    context: $"GPP file type: {fileTypeLabel}\nSYSVOL path: {filePath}\n" +
                             $"Affected user: {userName}\nLast modified: {changed}\n" +
                             "Password successfully decrypted using published Microsoft AES key (KB2962486)"
                )
                .WithReferences(
                    "https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30",
                    "https://nvd.nist.gov/vuln/detail/CVE-2014-1812",
                    "https://attack.mitre.org/techniques/T1552/006/",
                    "https://www.cisecurity.org/benchmark/microsoft_windows_server"
                )
                .WithCve("CVE-2014-1812")
                .WithAffectedComponent($"SYSVOL GPP — {fileTypeLabel} on {target}");
            }

            public static Finding SysvolAnonymousAccess(string target)
            {
                return Finding.Create(
                    id: "AST-SYSVOL-003",
                    title: "SYSVOL share accessible via anonymous/null session",
                    severity: "high",
                    confidence: "high",
                    recommendation:
                        "Restrict SYSVOL read access to authenticated domain users only:\n\n" +
                        "1. Verify SYSVOL NTFS permissions: SYSTEM (Full), Domain Admins (Full), " +
                        "Authenticated Users (Read), Creator Owner (Full)\n" +
                        "2. Remove 'Everyone' and 'Anonymous Logon' from SYSVOL ACLs if present.\n" +
                        "3. Disable anonymous SMB access: set RestrictAnonymous = 2 in registry.\n" +
                        "4. Audit Netlogon share permissions as well."
                )
                .WithDescription(
                    "The SYSVOL share on this domain controller is readable without authentication. " +
                    "SYSVOL contains Group Policy Objects (GPOs) and scripts for all domain machines. " +
                    "Anonymous access allows unauthenticated enumeration of domain policies, scripts, " +
                    "and potentially credentials stored in GPP files (MS14-025)."
                )
                .WithEvidence(
                    type: "share",
                    value: "SYSVOL accessible via null/anonymous SMB session",
                    context: $"Target: {target}\nShare: SYSVOL\nAuthentication: null session (anonymous)\n" +
                             "Risk: Domain policy enumeration + GPP credential exposure without credentials"
                )
                .WithReferences(
                    "https://attack.mitre.org/techniques/T1552/006/",
                    "https://www.cisecurity.org/benchmark/microsoft_windows_server"
                )
                .WithAffectedComponent($"SYSVOL share on {target}");
            }
        }
    }
}
