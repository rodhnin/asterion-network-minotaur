using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Serilog;
using Asterion.Core;
using Asterion.Core.Utils;
using Asterion.Models;

namespace Asterion.Checks.CrossPlatform
{
    /// <summary>
    /// FTP Security Scanner (Cross-Platform, IIS/Linux)
    ///
    /// Detects:
    /// - AST-FTP-001: Anonymous FTP access enabled
    /// - AST-FTP-002: Anonymous FTP with write permissions (STOR)
    /// - AST-FTP-003: FTP over unencrypted channel (no FTPS)
    ///
    /// Solid flow for IIS/vsFTPd:
    /// 1) Connect, read banner
    /// 2) Authenticate first (USER/PASS) with proper CRLF
    /// 3) After login: SYST / FEAT / OPTS
    /// 4) Try EPSV then PASV + STOR/DELE
    /// 5) Check FTPS explicit (AUTH TLS) and implicit (port 990)
    /// </summary>
    public class FtpScanner : BaseCheck
    {
        private const int FTP_PORT = 21;
        private const int FTPS_IMPLICIT_PORT = 990;
        private const int FTP_TIMEOUT_MS = 9000; // a tad more generous for IIS
        private static readonly Encoding Ascii = Encoding.ASCII;

        public override string Name => "FTP Security Scanner";
        public override CheckCategory Category => CheckCategory.CrossPlatform;

        public override string Description =>
            "Detects FTP security issues including anonymous access, write permissions, and lack of encryption (FTPS/TLS)";

        public override bool RequiresAuthentication => false;
        public override bool RequiresAggressiveMode => false;

        public FtpScanner(Config config) : base(config) { }

        public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
        {
            if (!CanExecute() || !ShouldExecute(options))
                return new List<Finding>();

            var findings = new List<Finding>();

            Log.Information("[{CheckName}] Starting FTP security scan on {Count} target(s)", Name, targets.Count);

            foreach (var target in targets)
            {
                try
                {
                    if (!await NetworkUtils.IsPortOpenAsync(target, FTP_PORT, _config.Scan.Timeout.Connect * 1000))
                    {
                        Log.Debug("[{CheckName}] FTP port {Port} not open on {Target}", Name, FTP_PORT, target);
                        continue;
                    }

                    Log.Debug("[{CheckName}] FTP port {Port} open on {Target}, analyzing...", Name, FTP_PORT, target);

                    var ftpInfo = await AnalyzeFtpAsync(target);

                    if (ftpInfo != null)
                    {
                        if (ftpInfo.AnonymousAccessAllowed)
                        {
                            findings.Add(CreateAnonymousAccessFinding(target, ftpInfo));

                            if (ftpInfo.AnonymousWriteAllowed)
                                findings.Add(CreateAnonymousWriteFinding(target, ftpInfo));
                        }

                        if (!ftpInfo.FtpsSupported)
                            findings.Add(CreateNoEncryptionFinding(target, ftpInfo));
                    }
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "[{CheckName}] Failed to scan FTP on {Target}", Name, target);
                }
            }

            LogExecution(targets.Count, findings.Count);
            return findings;
        }

        private async Task<FtpInfo?> AnalyzeFtpAsync(string host)
        {
            var info = new FtpInfo { Host = host };

            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(host, FTP_PORT).WaitAsync(TimeSpan.FromMilliseconds(FTP_TIMEOUT_MS));
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Ascii, false, 1024, leaveOpen: true);

                // 1) Banner
                var banner = await ReadResponseAsync(reader, default);
                info.Banner = banner.Raw;
                info.LastStatus = banner.Code;
                Log.Debug("[{CheckName}] FTP banner on {Host}: {Banner}", Name, host, banner.Raw);

                // 2) Login first (IIS is picky)
                var anon = await TryAnonymousLoginAsync(reader, stream, info, host);
                if (anon) info.AnonymousAccessAllowed = true;

                // 3) Post-login info gathering
                await SendCmdAsync(stream, "SYST");
                var syst = await ReadResponseAsync(reader, default);
                info.Syst = syst.Raw;

                await SendCmdAsync(stream, "FEAT");
                var feat = await ReadResponseAsync(reader, default);
                info.Feat = feat.Raw;

                await SendCmdAsync(stream, "OPTS UTF8 ON");
                var utf8 = await ReadResponseAsync(reader, default);
                info.UTF8Opt = utf8.Raw;

                if (anon)
                {
                    // 4) EPSV (preferred) then PASV fallback + STOR/DELE
                    var storOk = await TryAnonymousStorAsync(reader, stream, host);
                    info.AnonymousWriteAllowed = storOk.Allowed;

                    // MKD/RMD as secondary evidence
                    await SendCmdAsync(stream, "MKD .asterion_test_dir");
                    var mkd = await ReadResponseAsync(reader, default);
                    if (mkd.Code == 257)
                    {
                        info.AnonymousWriteAllowed = true;
                        await SendCmdAsync(stream, "RMD .asterion_test_dir");
                        _ = await ReadResponseAsync(reader, default);
                    }

                    // Clean logout of the authenticated session
                    await SendCmdAsync(stream, "QUIT");
                    _ = await ReadResponseAsync(reader, default);
                }

                // 5) FTPS explicit (AUTH TLS), capture evidence code/raw
                info.FtpsExplicitSupported = await CheckFtpsExplicitAsync(host, info);

                // 6) FTPS implicit (990)
                info.FtpsImplicitSupported = await CheckFtpsImplicitAsync(host);

                info.FtpsSupported = info.FtpsExplicitSupported || info.FtpsImplicitSupported;
            }
            catch (TimeoutException)
            {
                Log.Debug("[{CheckName}] FTP connection timeout on {Host}", Name, host);
                return null;
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] FTP analysis failed on {Host}", Name, host);
                return null;
            }

            return info;
        }

        /// <summary>
        /// Robust anonymous login (CRLF, handle 451/421, clean retry).
        /// </summary>
        private async Task<bool> TryAnonymousLoginAsync(StreamReader reader, Stream stream, FtpInfo info, string host)
        {
            await SendCmdAsync(stream, "USER anonymous");
            var userResp = await ReadResponseAsync(reader, default);

            if (userResp.Code == 331)
            {
                await SendCmdAsync(stream, "PASS anonymous@");
                var passResp = await ReadResponseAsync(reader, default);
                if (passResp.Code == 230)
                {
                    Log.Warning("[{CheckName}] Anonymous FTP login successful on {Host}", Name, host);
                    return true;
                }
            }
            else if (userResp.Code == 230)
            {
                Log.Warning("[{CheckName}] Anonymous FTP login successful on {Host} (no PASS required)", Name, host);
                return true;
            }
            else if (userResp.Code == 451 || userResp.Code == 421)
            {
                Log.Warning("[{CheckName}] Received {Code} on {Host}, retrying clean login", Name, userResp.Code, host);
                return await RetryAnonymousLoginAsync(host);
            }

            return false;
        }

        private async Task<bool> RetryAnonymousLoginAsync(string host)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(host, FTP_PORT).WaitAsync(TimeSpan.FromMilliseconds(FTP_TIMEOUT_MS));
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Ascii, false, 1024, leaveOpen: true);

                _ = await ReadResponseAsync(reader, default); // banner

                await SendCmdAsync(stream, "USER anonymous");
                var ur = await ReadResponseAsync(reader, default);
                if (ur.Code == 331)
                {
                    await SendCmdAsync(stream, "PASS anonymous@");
                    var pr = await ReadResponseAsync(reader, default);
                    return pr.Code == 230;
                }
                return ur.Code == 230;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// EPSV first, fallback to PASV; then STOR/DELE for write confirmation.
        /// </summary>
        private async Task<(bool Allowed, string? Evidence)> TryAnonymousStorAsync(StreamReader reader, Stream controlStream, string host)
        {
            try
            {
                await SendCmdAsync(controlStream, "TYPE I"); // binary mode
                _ = await ReadResponseAsync(reader, default);

                // --- Try EPSV first (229 Entering Extended Passive Mode (|||<port>|)) ---
                string dataHost = host;
                int dataPort = -1;

                await SendCmdAsync(controlStream, "EPSV");
                var epsv = await ReadResponseAsync(reader, default);
                if (epsv.Code == 229)
                {
                    var ok = TryParseEpsvPort(epsv.Raw, out dataPort);
                    if (!ok || dataPort <= 0)
                        return (false, $"EPSV parse failed: {epsv.Raw}");
                }
                else
                {
                    // --- Fallback to PASV (227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)) ---
                    await SendCmdAsync(controlStream, "PASV");
                    var pasvResp = await ReadResponseAsync(reader, default);
                    if (pasvResp.Code != 227)
                        return (false, $"Neither EPSV (229) nor PASV (227) accepted (EPSV={epsv.Code}, PASV={pasvResp.Code})");

                    var (_, p) = ParsePasvEndpoint(pasvResp.Raw);

                    // Important for IIS/NAT quirks: force dataHost to control connection host
                    dataHost = host;
                    dataPort = p;
                }

                using var dataClient = new TcpClient();
                await dataClient.ConnectAsync(dataHost, dataPort).WaitAsync(TimeSpan.FromMilliseconds(FTP_TIMEOUT_MS));

                await SendCmdAsync(controlStream, "STOR asterion_test.txt");
                var storInit = await ReadResponseAsync(reader, default);
                if (storInit.Code != 150 && storInit.Code != 125)
                    return (false, $"STOR rejected: {storInit.Raw}");

                using (var ds = dataClient.GetStream())
                {
                    var payload = Ascii.GetBytes("asterion write test\n");
                    using var cts = new CancellationTokenSource(FTP_TIMEOUT_MS);
                    await ds.WriteAsync(payload, 0, payload.Length, cts.Token);
                    ds.Close(); // EOF
                }

                var storDone = await ReadResponseAsync(reader, default);
                if (storDone.Code == 226 || storDone.Code == 250)
                {
                    Log.Warning("[{CheckName}] Anonymous FTP WRITE access on {Host}", Name, host);
                    await SendCmdAsync(controlStream, "DELE asterion_test.txt");
                    _ = await ReadResponseAsync(reader, default);
                    return (true, "STOR/DELE successful");
                }

                return (false, $"STOR not completed: {storDone.Raw}");
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] STOR test failed on {Host}", Name, host);
                return (false, ex.Message);
            }
        }

        /// <summary>
        /// FTPS explicit via AUTH TLS; record response code/raw into FtpInfo for evidence.
        /// </summary>
        private async Task<bool> CheckFtpsExplicitAsync(string host, FtpInfo info)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(host, FTP_PORT).WaitAsync(TimeSpan.FromMilliseconds(FTP_TIMEOUT_MS));
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Ascii, false, 1024, leaveOpen: true);

                _ = await ReadResponseAsync(reader, default); // banner

                await SendCmdAsync(stream, "AUTH TLS");
                var auth = await ReadResponseAsync(reader, default);

                info.AuthTlsCode = auth.Code;
                info.AuthTlsRaw = FirstLine(auth.Raw);

                if (auth.Code == 234)
                {
                    Log.Debug("[{CheckName}] FTPS (AUTH TLS) supported on {Host}", Name, host);
                    try { await SendCmdAsync(stream, "QUIT"); _ = await ReadResponseAsync(reader, default); } catch { /* ignore */ }
                    return true;
                }

                try { await SendCmdAsync(stream, "QUIT"); _ = await ReadResponseAsync(reader, default); } catch { /* ignore */ }
                return false;
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] Explicit FTPS (AUTH TLS) test failed on {Host}", Name, host);
                // Keep evidence as null; treat as not supported
                return false;
            }
        }

        /// <summary>
        /// FTPS implicit on 990 with real TLS handshake.
        /// </summary>
        private async Task<bool> CheckFtpsImplicitAsync(string host)
        {
            try
            {
                var open = await NetworkUtils.IsPortOpenAsync(host, FTPS_IMPLICIT_PORT, _config.Scan.Timeout.Connect * 1000);
                if (!open) return false;

                using var client = new TcpClient();
                await client.ConnectAsync(host, FTPS_IMPLICIT_PORT).WaitAsync(TimeSpan.FromMilliseconds(FTP_TIMEOUT_MS));
                using var baseStream = client.GetStream();

                using var ssl = new SslStream(baseStream, false, (sender, cert, chain, errors) => true);
                var cts = new CancellationTokenSource(FTP_TIMEOUT_MS);
                var options = new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                };

                await ssl.AuthenticateAsClientAsync(options, cts.Token);

                using var reader = new StreamReader(ssl, Ascii, false, 1024, leaveOpen: true);

                var banner = await ReadResponseAsync(reader, default);
                Log.Debug("[{CheckName}] FTPS implicit banner on {Host}: {Banner}", Name, host, banner.Raw);

                return true;
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[{CheckName}] FTPS implicit (990) test failed on {Host}", Name, host);
                return false;
            }
        }

        /// <summary>
        /// Robust response reader (multi-line RFC 959).
        /// </summary>
        private async Task<FtpResponse> ReadResponseAsync(StreamReader reader, CancellationToken ct)
        {
            var sb = new StringBuilder();
            string? firstLine = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromMilliseconds(FTP_TIMEOUT_MS), ct);
            if (firstLine == null) return new FtpResponse(0, string.Empty);

            sb.AppendLine(firstLine);

            var m = Regex.Match(firstLine, @"^(?<code>\d{3})(?<sep>[ -])(.*)$");
            if (!m.Success)
                return new FtpResponse(0, sb.ToString().TrimEnd());

            int code = int.Parse(m.Groups["code"].Value);
            char sep = m.Groups["sep"].Value[0];

            if (sep == '-')
            {
                string? line;
                while ((line = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromMilliseconds(FTP_TIMEOUT_MS), ct)) != null)
                {
                    sb.AppendLine(line);
                    if (Regex.IsMatch(line, $"^{code} "))
                        break;
                }
            }

            return new FtpResponse(code, sb.ToString().TrimEnd());
        }

        /// <summary>
        /// Send command with CRLF terminator (required by IIS).
        /// </summary>
        private async Task SendCmdAsync(Stream stream, string cmd, CancellationToken ct = default)
        {
            var bytes = Ascii.GetBytes(cmd + "\r\n");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(FTP_TIMEOUT_MS);
            await stream.WriteAsync(bytes, 0, bytes.Length, cts.Token).ConfigureAwait(false);
            await stream.FlushAsync(cts.Token).ConfigureAwait(false);
        }

        private static bool TryParseEpsvPort(string epsvRaw, out int port)
        {
            // Format: 229 Entering Extended Passive Mode (|||<port>|)
            port = -1;
            var m = Regex.Match(epsvRaw, @"\(\|\|\|(?<p>\d+)\|\)");
            if (!m.Success) return false;
            port = int.Parse(m.Groups["p"].Value);
            return true;
        }

        private (string host, int port) ParsePasvEndpoint(string pasvRaw)
        {
            // Format: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
            var match = Regex.Match(pasvRaw, @"\((?<vals>[\d,\s]+)\)");
            if (!match.Success) throw new InvalidOperationException("Could not parse PASV response");

            var parts = match.Groups["vals"].Value.Split(',');
            if (parts.Length < 6) throw new InvalidOperationException("Invalid PASV tuple");

            string host = $"{parts[0].Trim()}.{parts[1].Trim()}.{parts[2].Trim()}.{parts[3].Trim()}";
            int p1 = int.Parse(parts[4].Trim());
            int p2 = int.Parse(parts[5].Trim());
            int port = (p1 << 8) + p2;

            return (host, port);
        }

        private static string FirstLine(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return string.Empty;
            var idx = raw.IndexOf('\n');
            return idx >= 0 ? raw[..idx].Trim() : raw.Trim();
        }

        private Finding CreateAnonymousAccessFinding(string target, FtpInfo info)
        {
            return CreateFinding(
                id: "AST-FTP-001",
                title: "FTP anonymous access enabled",
                severity: "high",
                recommendation: $"Disable anonymous FTP access on {target}:\n" +
                    "1. Edit FTP server configuration (vsftpd.conf, proftpd.conf, IIS Manager).\n" +
                    "2. Linux: anonymous_enable=NO (vsFTPd) or <Anonymous> disabled (ProFTPd).\n" +
                    "   Windows/IIS: FTP Authentication → Anonymous Authentication: Disabled.\n" +
                    "3. Restart FTP service.\n" +
                    "4. If anonymous is strictly required, restrict to read-only and an isolated directory.\n" +
                    "5. Prefer strong auth or migrate to SFTP/HTTPS.",
                description: $"The FTP server on {target} allows anonymous (unauthenticated) access. " +
                    "This enables unauthenticated data access, information disclosure, abuse, and liability. " +
                    "Anonymous FTP is insecure; prefer SFTP/HTTPS.",
                evidence: new Evidence
                {
                    Type = "service",
                    Value = $"Anonymous FTP login successful on {target}:21",
                    Context = $"Banner: {info.Banner}\nSYST: {info.Syst}\nFEAT: {info.Feat}"
                },
                affectedComponent: $"{target}:21 (FTP Service)"
            )
            .WithReferences(
                "https://linux.die.net/man/5/vsftpd.conf"
            );
        }

        private Finding CreateAnonymousWriteFinding(string target, FtpInfo info)
        {
            return CreateFinding(
                id: "AST-FTP-002",
                title: "FTP anonymous access with WRITE permissions",
                severity: "critical",
                recommendation: $"URGENT: Disable anonymous write access on {target}:\n" +
                    "1. Disable upload/write for anonymous users in the FTP server configuration.\n" +
                    "   - vsFTPd: anon_upload_enable=NO, anon_mkdir_write_enable=NO\n" +
                    "   - ProFTPd: <Anonymous> with write disabled\n" +
                    "   - IIS: FTP Authorization Rules → Anonymous Users: remove Write (leave Read only)\n" +
                    "   and remove NTFS Modify/Write for IUSR/anonymous account.\n" +
                    "2. Restart FTP service.\n" +
                    "3. Audit files and logs for abuse.\n" +
                    "4. Consider shutting down FTP if not needed; migrate to SFTP.",
                description: $"The FTP server on {target} allows anonymous users to WRITE. " +
                    "Attackers can upload malware, phishing pages, or illegal content; use it for exfiltration or fill disk space. Remediate immediately.",
                evidence: new Evidence
                {
                    Type = "service",
                    Value = $"Anonymous FTP WRITE access confirmed on {target}:21",
                    Context = "STOR asterion_test.txt succeeded (and was deleted)."
                },
                affectedComponent: $"{target}:21 (FTP Service)"
            )
            .WithReferences(
                "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/security_guide/sect-security_guide-securing_ftp-anonymous_access"
            );
        }

        private Finding CreateNoEncryptionFinding(string target, FtpInfo info)
        {
            var ftpsDetail =
                $"Explicit AUTH TLS supported: {(info.FtpsExplicitSupported ? "yes" : "no")} (code={(info.AuthTlsCode?.ToString() ?? "n/a")}, resp=\"{info.AuthTlsRaw ?? "n/a"}\"); " +
                $"Implicit 990: {(info.FtpsImplicitSupported ? "supported" : "not supported")}.";

            return CreateFinding(
                id: "AST-FTP-003",
                title: "FTP traffic not encrypted (no FTPS/TLS support)",
                severity: "medium",
                recommendation: $"Enable encryption for FTP on {target}:\n" +
                    "1. Install a valid SSL/TLS certificate on the FTP server.\n" +
                    "2. Configure FTPS:\n" +
                    "   - vsFTPd: ssl_enable=YES, force_local_data_ssl=YES, force_local_logins_ssl=YES\n" +
                    "   - ProFTPd: TLSEngine on, TLSRSACertificateFile <cert>\n" +
                    "   - IIS: FTP SSL Settings → Require SSL, bind a certificate.\n" +
                    "3. Prefer SFTP (SSH) over FTPS for simpler firewalling and a better security posture.\n" +
                    "4. Disable legacy TLS (1.0/1.1) at OS level.",
                description: $"The FTP server on {target} does not appear to effectively support FTPS (explicit or implicit). " +
                    "All FTP credentials/data are transmitted in plaintext, enabling interception and MITM. " +
                    ftpsDetail,
                evidence: new Evidence
                {
                    Type = "service",
                    Value = $"FTPS not effectively supported on {target}",
                    Context = ftpsDetail
                },
                affectedComponent: $"{target}:21 (FTP Service)"
            )
            .WithReferences(
                "https://www.ssh.com/academy/ssh/sftp-ssh-file-transfer-protocol",
                "https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-shell-ssh/4145-ssh.html"
            );
        }
    }

    internal record FtpResponse(int Code, string Raw);

    internal class FtpInfo
    {
        public string Host { get; set; } = string.Empty;
        public string Banner { get; set; } = string.Empty;
        public string Syst { get; set; } = string.Empty;
        public string Feat { get; set; } = string.Empty;
        public string UTF8Opt { get; set; } = string.Empty;

        public bool AnonymousAccessAllowed { get; set; }
        public bool AnonymousWriteAllowed { get; set; }

        public bool FtpsExplicitSupported { get; set; }
        public bool FtpsImplicitSupported { get; set; }
        public bool FtpsSupported { get; set; }

        public int LastStatus { get; set; }

        // Evidence for AUTH TLS (explicit FTPS)
        public int? AuthTlsCode { get; set; }
        public string? AuthTlsRaw { get; set; }
    }

    internal static class StreamReaderExtensions
    {
        public static async Task<string?> ReadLineAsync(this StreamReader reader)
        {
            // Wrapper to keep code concise and be compatible with WaitAsync usage
            return await reader.ReadLineAsync().ConfigureAwait(false);
        }

        public static async Task<T> WaitAsync<T>(this Task<T> task, TimeSpan timeout, CancellationToken ct = default)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var delayTask = Task.Delay(timeout, cts.Token);
            var completed = await Task.WhenAny(task, delayTask).ConfigureAwait(false);
            if (completed == task)
            {
                cts.Cancel();
                return await task.ConfigureAwait(false);
            }
            throw new TimeoutException();
        }

        public static async Task WaitAsync(this Task task, TimeSpan timeout, CancellationToken ct = default)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var delayTask = Task.Delay(timeout, cts.Token);
            var completed = await Task.WhenAny(task, delayTask).ConfigureAwait(false);
            if (completed == task)
            {
                cts.Cancel();
                await task.ConfigureAwait(false);
                return;
            }
            throw new TimeoutException();
        }
    }
}
