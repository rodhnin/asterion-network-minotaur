using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Serilog;

namespace Asterion.Core
{
    /// <summary>
    /// WinRM (WS-Management) connection manager for remote Windows PowerShell execution.
    ///
    /// Uses WS-Man over HTTP (port 5985) or HTTPS (port 5986) with NTLM authentication.
    /// Protocol: Creates a cmd shell, runs powershell.exe as command, reads stdout/stderr, deletes shell.
    /// Does NOT use PSRP (PowerShell Remoting Protocol) — uses simpler WS-Man cmd shell approach.
    ///
    /// Requirements on the target Windows host:
    ///   Enable-PSRemoting -Force
    ///   Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*"  (for workgroup / cross-domain)
    ///   winrm quickconfig
    /// </summary>
    public class WinRmConnectionManager : IDisposable
    {
        private readonly string _host;
        private readonly int _port;
        private readonly bool _useHttps;
        private readonly NetworkCredential _credential;
        private readonly string _baseUrl;

        private HttpClient? _httpClient;
        private string? _shellId;
        private NtlmSessionSecurity? _sessionSecurity;
        private bool _disposed;

        // Serialize all PS executions — WinRM shells are single-threaded;
        // concurrent callers sharing this manager would race on RunCommand/Signal.
        private readonly SemaphoreSlim _execLock = new SemaphoreSlim(1, 1);

        public bool IsConnected => _httpClient != null && !string.IsNullOrEmpty(_shellId);
        public string Host => _host;

        // ── Constructor ──────────────────────────────────────────────────────────

        /// <summary>
        /// Create a WinRM connection manager.
        /// </summary>
        /// <param name="host">Target hostname or IP</param>
        /// <param name="username">Username — formats: "user", "DOMAIN\user", "user@domain"</param>
        /// <param name="password">Password</param>
        /// <param name="useHttps">Use HTTPS (port 5986). Default: HTTP (port 5985)</param>
        /// <param name="port">Override default port (5985 / 5986)</param>
        public WinRmConnectionManager(string host, string username, string password,
            bool useHttps = false, int? port = null)
        {
            _host     = host;
            _useHttps = useHttps;
            _port     = port ?? (useHttps ? 5986 : 5985);
            _baseUrl  = $"{(useHttps ? "https" : "http")}://{_host}:{_port}/wsman";

            // Parse "DOMAIN\user" or "user@domain" formats
            string domain = string.Empty;
            string user   = username;
            if (username.Contains('\\'))
            {
                var parts = username.Split('\\', 2);
                domain = parts[0];
                user   = parts[1];
            }
            else if (username.Contains('@'))
            {
                var parts = username.Split('@', 2);
                user   = parts[0];
                domain = parts[1];
            }

            _credential = new NetworkCredential(user, password, domain);
        }

        // ── Public API ───────────────────────────────────────────────────────────

        /// <summary>
        /// Test connectivity and authentication by creating a WinRM shell.
        /// Returns true if a shell was created successfully (credentials valid and WinRM reachable).
        ///
        /// Sends raw NTLM tokens under "Authorization: Negotiate" — same approach as requests-ntlm.
        /// Windows WinRM accepts bare NTLM bytes in the Negotiate header (no SPNEGO wrapping).
        /// </summary>
        public async Task<bool> ConnectAsync()
        {
            try
            {
                // Plain SocketsHttpHandler with no automatic auth — we handle the 3-way
                // NTLM handshake manually, keeping MaxConnectionsPerServer=1 so all three
                // requests (Type1, Type3, and subsequent SOAP calls) share the same socket.
                var socketsHandler = new SocketsHttpHandler
                {
                    AllowAutoRedirect        = false,
                    UseProxy                 = false,
                    MaxConnectionsPerServer  = 1,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(30),
                };

                if (_useHttps)
                    socketsHandler.SslOptions = new System.Net.Security.SslClientAuthenticationOptions
                    {
                        RemoteCertificateValidationCallback = (_, _, _, _) => true
                    };

                _httpClient = new HttpClient(socketsHandler)
                {
                    // Must be > per-request CTS timeout (120s) so the CTS is the effective limit
                    Timeout = TimeSpan.FromSeconds(150)
                };

                _shellId = await CreateShellAsync();
                if (_shellId == null)
                {
                    Log.Warning("[WinRM] Failed to create shell on {Host}:{Port} — check credentials and WinRM config", _host, _port);
                    _httpClient.Dispose();
                    _httpClient = null;
                    return false;
                }

                Log.Information("[WinRM] Connected to {Host}:{Port} (shell: {ShellId})", _host, _port, _shellId[..Math.Min(8, _shellId.Length)]);
                return true;
            }
            catch (HttpRequestException ex)
            {
                Log.Warning("[WinRM] Cannot reach {Host}:{Port} — {Message}", _host, _port, ex.Message);
            }
            catch (TaskCanceledException)
            {
                Log.Warning("[WinRM] Connection timed out to {Host}:{Port}", _host, _port);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "[WinRM] Connection failed to {Host}:{Port}", _host, _port);
            }

            _httpClient?.Dispose();
            _httpClient = null;
            _shellId    = null;
            return false;
        }

        // ── WS-Man protocol ──────────────────────────────────────────────────────

        /// <summary>
        /// Create a WinRM cmd shell using the pywinrm-equivalent flow:
        ///
        ///   Step 1 — POST /wsman + Type1 + empty body → 401 + Type2
        ///   Step 2 — POST /wsman + Type3 + empty body → 200 (NTLM session key established)
        ///   Step 3 — POST /wsman + encrypted SOAP (multipart/encrypted MIME, no auth header) → 200 + ShellId
        ///
        /// Windows WinRM requires AllowUnencrypted=False by default (MS-WSMV 2.2.9.1).
        /// All SOAP bodies must be sealed with RC4(ClientSealKey) + HMAC-MD5 signature.
        /// </summary>
        private async Task<string?> CreateShellAsync()
        {
            try
            {
                var ntlm = new NtlmV2Auth(_credential.UserName, _credential.Password, _credential.Domain, _host);

                // ── Step 1: Type1 Negotiate + empty body ────────────────────────
                var type1Raw = ntlm.BuildType1();
                using var req1 = new HttpRequestMessage(HttpMethod.Post, _baseUrl);
                req1.Headers.TryAddWithoutValidation("Authorization", $"Negotiate {Convert.ToBase64String(type1Raw)}");
                req1.Headers.TryAddWithoutValidation("Connection",    "Keep-Alive");
                req1.Headers.TryAddWithoutValidation("User-Agent",    "Python WinRM client");
                var emptyBody = new ByteArrayContent(Array.Empty<byte>());
                emptyBody.Headers.TryAddWithoutValidation("Content-Type", "application/soap+xml;charset=UTF-8");
                req1.Content = emptyBody;

                using var cts1 = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                using var rsp1 = await _httpClient!.SendAsync(req1, HttpCompletionOption.ResponseHeadersRead, cts1.Token);
                await rsp1.Content.ReadAsByteArrayAsync();  // drain

                if (rsp1.StatusCode != System.Net.HttpStatusCode.Unauthorized)
                {
                    Log.Warning("[WinRM] Expected 401 for Type1, got {Code}", (int)rsp1.StatusCode);
                    return null;
                }

                // ── Parse Type2 from WWW-Authenticate ────────────────────────────
                string? type2Param = null;
                foreach (var h in rsp1.Headers.WwwAuthenticate)
                {
                    if (h.Scheme.Equals("Negotiate", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(h.Parameter))
                    { type2Param = h.Parameter; break; }
                }
                if (type2Param == null)
                {
                    Log.Warning("[WinRM] Server did not return NTLM Type2 in WWW-Authenticate");
                    return null;
                }
                var serverBytes = Convert.FromBase64String(type2Param);
                var ntlmType2   = IsNtlm(serverBytes) ? serverBytes
                                  : NtlmSpnego.ExtractNtlm(serverBytes) ?? serverBytes;
                Log.Debug("[WinRM] NTLM Type2: {Bytes} bytes", ntlmType2.Length);

                // ── Step 2: Type3 Authenticate + empty body ──────────────────────
                var type3Raw = ntlm.BuildType3(ntlmType2);
                Log.Debug("[WinRM] NTLM Type3: {Bytes} bytes", type3Raw.Length);

                using var req2 = new HttpRequestMessage(HttpMethod.Post, _baseUrl);
                req2.Headers.TryAddWithoutValidation("Authorization", $"Negotiate {Convert.ToBase64String(type3Raw)}");
                req2.Headers.TryAddWithoutValidation("Connection",    "Keep-Alive");
                req2.Headers.TryAddWithoutValidation("User-Agent",    "Python WinRM client");
                var emptyBody2 = new ByteArrayContent(Array.Empty<byte>());
                emptyBody2.Headers.TryAddWithoutValidation("Content-Type", "application/soap+xml;charset=UTF-8");
                req2.Content = emptyBody2;

                using var cts2 = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                using var rsp2 = await _httpClient!.SendAsync(req2, HttpCompletionOption.ResponseHeadersRead, cts2.Token);
                await rsp2.Content.ReadAsByteArrayAsync();  // drain

                if (rsp2.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    Log.Warning("[WinRM] NTLM Type3 rejected (401) — invalid credentials");
                    return null;
                }

                // ── Build session security from ExportedKey ──────────────────────
                if (ntlm.ExportedKey == null)
                {
                    Log.Warning("[WinRM] No ExportedKey after Type3 — cannot encrypt SOAP");
                    return null;
                }
                _sessionSecurity?.Dispose();
                _sessionSecurity = new NtlmSessionSecurity(ntlm.ExportedKey);
                Log.Debug("[WinRM] NTLM session established — encryption active");

                // ── Step 3: Encrypted SOAP CreateShell (no auth header) ──────────
                var soapBody = BuildShellSoap(Guid.NewGuid().ToString().ToUpperInvariant());
                var shellXml = await SendEncryptedSoapAsync(soapBody);
                if (shellXml == null) return null;

                var match = Regex.Match(shellXml, @"<(?:rsp:)?ShellId>([^<]+)</(?:rsp:)?ShellId>");
                if (!match.Success)
                {
                    Log.Warning("[WinRM] No ShellId in response: {Snippet}", shellXml.Length > 300 ? shellXml[..300] : shellXml);
                    return null;
                }
                return match.Groups[1].Value;
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "[WinRM] CreateShellAsync exception on {Host}:{Port}", _host, _port);
                return null;
            }
        }

        /// <summary>
        /// Send an encrypted SOAP request and return the decrypted response body.
        /// Used for all WS-Man requests AFTER the NTLM handshake is complete.
        /// </summary>
        private async Task<string?> SendEncryptedSoapAsync(string soapBody)
        {
            if (_httpClient == null || _sessionSecurity == null) return null;
            try
            {
                var soapBytes = Encoding.UTF8.GetBytes(soapBody);
                var (encBody, contentType) = _sessionSecurity.BuildEncryptedBody(soapBytes);

                using var request = new HttpRequestMessage(HttpMethod.Post, _baseUrl);
                request.Headers.TryAddWithoutValidation("Connection",  "Keep-Alive");
                request.Headers.TryAddWithoutValidation("User-Agent",  "Python WinRM client");
                var content = new ByteArrayContent(encBody);
                content.Headers.TryAddWithoutValidation("Content-Type",   contentType);
                content.Headers.TryAddWithoutValidation("Content-Length", encBody.Length.ToString());
                request.Content = content;

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(120));
                using var response = await _httpClient.SendAsync(request, cts.Token);

                var responseBodyBytes = await response.Content.ReadAsByteArrayAsync();
                if (!response.IsSuccessStatusCode)
                {
                    var respCt  = response.Content.Headers.ContentType?.ToString() ?? "";
                    var snippet = Encoding.UTF8.GetString(responseBodyBytes);
                    Log.Warning("[WinRM] Encrypted SOAP returned {Code}: {Snippet}",
                        (int)response.StatusCode, snippet.Length > 400 ? snippet[..400] : (snippet.Length == 0 ? "(empty)" : snippet));
                    return null;
                }

                // Decrypt the response
                var respContentType = response.Content.Headers.ContentType?.ToString() ?? "";
                if (_sessionSecurity == null)
                {
                    Log.Debug("[WinRM] SendEncryptedSoapAsync: session security not initialized, cannot decrypt");
                    return null;
                }
                var decrypted       = _sessionSecurity.DecryptResponse(respContentType, responseBodyBytes);
                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[WinRM] SendEncryptedSoapAsync failed");
                return null;
            }
        }

        private static bool IsNtlm(byte[] b)
            => b.Length > 7 && b[0] == 0x4e && b[1] == 0x54 && b[2] == 0x4c && b[3] == 0x4d;

        /// <summary>
        /// Build a WS-Man SOAP envelope matching the pywinrm format (tested working with Windows Server 2019).
        /// </summary>
        private string BuildEnvelope(string msgId, string action, string selectorSet = "", string body = "",
            string timeout = "PT120S", int maxEnvelopeSize = 153600)
        {
            var selXml = string.IsNullOrEmpty(selectorSet) ? "" : $"\n    {selectorSet}";
            var bodyXml = string.IsNullOrEmpty(body) ? "" : $"\n    {body}";
            return $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<env:Envelope xmlns:xsd=""http://www.w3.org/2001/XMLSchema""
              xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
              xmlns:env=""http://www.w3.org/2003/05/soap-envelope""
              xmlns:a=""http://schemas.xmlsoap.org/ws/2004/08/addressing""
              xmlns:b=""http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd""
              xmlns:n=""http://schemas.xmlsoap.org/ws/2004/09/enumeration""
              xmlns:x=""http://schemas.xmlsoap.org/ws/2004/09/transfer""
              xmlns:w=""http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd""
              xmlns:p=""http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd""
              xmlns:rsp=""http://schemas.microsoft.com/wbem/wsman/1/windows/shell""
              xmlns:cfg=""http://schemas.microsoft.com/wbem/wsman/1/config"">
  <env:Header>
    <a:To>{_baseUrl}</a:To>
    <a:ReplyTo><a:Address mustUnderstand=""true"">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
    <w:MaxEnvelopeSize mustUnderstand=""true"">{maxEnvelopeSize}</w:MaxEnvelopeSize>
    <a:MessageID>uuid:{msgId}</a:MessageID>
    <w:Locale mustUnderstand=""false"" xml:lang=""en-US""/>
    <p:DataLocale mustUnderstand=""false"" xml:lang=""en-US""/>
    <w:OperationTimeout>{timeout}</w:OperationTimeout>
    <w:ResourceURI mustUnderstand=""true"">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <a:Action mustUnderstand=""true"">{action}</a:Action>{selXml}
  </env:Header>
  <env:Body>{bodyXml}
  </env:Body>
</env:Envelope>";
        }

        /// <summary>Build the CreateShell SOAP envelope for a given MessageID.</summary>
        private string BuildShellSoap(string msgId)
            => BuildEnvelope(msgId,
                action: "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
                body: @"<rsp:Shell>
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
    </rsp:Shell>",
                // Include OptionSet in the header via the selectorSet parameter (overloaded usage)
                selectorSet: @"<w:OptionSet>
      <w:Option Name=""WINRS_NOPROFILE"">FALSE</w:Option>
      <w:Option Name=""WINRS_CODEPAGE"">65001</w:Option>
    </w:OptionSet>");

        /// <summary>
        /// Execute a PowerShell command via WinRM.
        /// The command is base64-encoded to avoid SOAP XML escaping issues.
        /// Returns stdout output (trimmed). Stderr is logged at debug level.
        /// Returns empty string if not connected or execution fails.
        /// </summary>
        public async Task<string> ExecutePowerShellAsync(string psCommand)
        {
            if (_httpClient == null || string.IsNullOrEmpty(_shellId))
            {
                Log.Debug("[WinRM] ExecutePowerShellAsync called but not connected");
                return string.Empty;
            }

            await _execLock.WaitAsync();
            try
            {
                // Base64-encode the PS command to avoid XML/SOAP escaping headaches
                var encoded    = Convert.ToBase64String(Encoding.Unicode.GetBytes(psCommand));
                var fullCmd    = $"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}";

                var commandId = await RunCommandAsync(_shellId, fullCmd);
                if (commandId == null)
                {
                    // Shell may have been invalidated by a prior timeout/500 error — try to recreate once
                    Log.Debug("[WinRM] RunCommand failed, attempting shell recreation on {Host}", _host);
                    if (await RecreateShellAsync())
                    {
                        commandId = await RunCommandAsync(_shellId, fullCmd);
                    }
                    if (commandId == null)
                    {
                        Log.Debug("[WinRM] RunCommand returned null on {Host}", _host);
                        return string.Empty;
                    }
                }

                var (stdout, stderr, exitCode) = await ReceiveOutputAsync(_shellId, commandId);

                await SignalCommandAsync(_shellId, commandId);

                if (!string.IsNullOrWhiteSpace(stderr))
                    Log.Debug("[WinRM] PS stderr from {Host}: {Stderr}", _host, stderr.Length > 300 ? stderr[..300] : stderr);

                if (exitCode != 0)
                    Log.Debug("[WinRM] PS exit code {ExitCode} on {Host} — stdout: {Stdout}", exitCode, _host,
                        stdout.Length > 300 ? stdout[..300] : (stdout.Length == 0 ? "(empty)" : stdout));

                return stdout.Trim();
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "[WinRM] ExecutePowerShellAsync failed on {Host}", _host);
                return string.Empty;
            }
            finally
            {
                _execLock.Release();
            }
        }

        /// <summary>
        /// Full NTLM re-handshake + new shell creation after a session error.
        /// The RC4 session security state is corrupted after any failed/timed-out command
        /// (server advances its RC4 counter but client doesn't). Only a new NTLM exchange
        /// (Type1→Type2→Type3→CreateShell) restores a clean session.
        /// </summary>
        private async Task<bool> RecreateShellAsync()
        {
            try
            {
                _sessionSecurity?.Dispose();
                _sessionSecurity = null;

                var newShellId = await CreateShellAsync();
                if (newShellId == null) return false;
                _shellId = newShellId;
                Log.Debug("[WinRM] Session re-authenticated on {Host} (shell: {ShellId})", _host, _shellId[..Math.Min(8, _shellId.Length)]);
                return true;
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[WinRM] RecreateShellAsync failed on {Host}", _host);
                return false;
            }
        }

        // ── WS-Man protocol ──────────────────────────────────────────────────────

        private async Task<string?> RunCommandAsync(string shellId, string command)
        {
            var msgId      = Guid.NewGuid().ToString().ToUpperInvariant();
            var xmlCommand = System.Security.SecurityElement.Escape(command);

            var body = BuildEnvelope(msgId,
                action:  "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
                selectorSet: $@"<w:SelectorSet><w:Selector Name=""ShellId"">{shellId}</w:Selector></w:SelectorSet>",
                body:    $@"<rsp:CommandLine><rsp:Command>{xmlCommand}</rsp:Command></rsp:CommandLine>");

            var response = await PostSoapAsync(body);
            if (response == null) return null;

            var match = Regex.Match(response, @"<rsp:CommandId>([^<]+)</rsp:CommandId>");
            return match.Success ? match.Groups[1].Value : null;
        }

        private async Task<(string stdout, string stderr, int exitCode)> ReceiveOutputAsync(
            string shellId, string commandId)
        {
            var stdoutBuf = new StringBuilder();
            var stderrBuf = new StringBuilder();
            int exitCode  = 0;
            bool done     = false;

            while (!done)
            {
                var msgId = Guid.NewGuid().ToString().ToUpperInvariant();
                var body  = BuildEnvelope(msgId,
                    action:      "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
                    selectorSet: $@"<w:SelectorSet><w:Selector Name=""ShellId"">{shellId}</w:Selector></w:SelectorSet>",
                    body:        $@"<rsp:Receive><rsp:DesiredStream CommandId=""{commandId}"">stdout stderr</rsp:DesiredStream></rsp:Receive>",
                    maxEnvelopeSize: 524288);

                var response = await PostSoapAsync(body);
                if (response == null) break;

                // Decode base64 stdout chunks
                foreach (Match m in Regex.Matches(response, @"<rsp:Stream Name=""stdout""[^>]*>([^<]*)</rsp:Stream>"))
                {
                    var chunk = m.Groups[1].Value;
                    if (!string.IsNullOrEmpty(chunk))
                        stdoutBuf.Append(Encoding.UTF8.GetString(Convert.FromBase64String(chunk)));
                }

                // Decode base64 stderr chunks
                foreach (Match m in Regex.Matches(response, @"<rsp:Stream Name=""stderr""[^>]*>([^<]*)</rsp:Stream>"))
                {
                    var chunk = m.Groups[1].Value;
                    if (!string.IsNullOrEmpty(chunk))
                        stderrBuf.Append(Encoding.UTF8.GetString(Convert.FromBase64String(chunk)));
                }

                // Check for Done state
                var stateMatch = Regex.Match(response, @"State=""[^""]*Done""");
                if (stateMatch.Success)
                {
                    done = true;
                    var exitMatch = Regex.Match(response, @"<rsp:ExitCode>(\d+)</rsp:ExitCode>");
                    if (exitMatch.Success)
                    {
                        // Windows exit codes are uint32 — values like 4294967295 (= -1) overflow Int32.Parse
                        if (!int.TryParse(exitMatch.Groups[1].Value, out exitCode) &&
                            uint.TryParse(exitMatch.Groups[1].Value, out var uCode))
                            exitCode = (int)uCode; // wrap: 0xFFFFFFFF → -1
                    }
                }
            }

            return (stdoutBuf.ToString(), stderrBuf.ToString(), exitCode);
        }

        private async Task SignalCommandAsync(string shellId, string commandId)
        {
            var msgId = Guid.NewGuid().ToString().ToUpperInvariant();
            var body  = BuildEnvelope(msgId,
                action:      "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal",
                selectorSet: $@"<w:SelectorSet><w:Selector Name=""ShellId"">{shellId}</w:Selector></w:SelectorSet>",
                body:        $@"<rsp:Signal CommandId=""{commandId}""><rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c</rsp:Code></rsp:Signal>",
                timeout: "PT30S");
            await PostSoapAsync(body);
        }

        private async Task DeleteShellAsync(string shellId)
        {
            var msgId = Guid.NewGuid().ToString().ToUpperInvariant();
            var body  = BuildEnvelope(msgId,
                action:      "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
                selectorSet: $@"<w:SelectorSet><w:Selector Name=""ShellId"">{shellId}</w:Selector></w:SelectorSet>",
                body:        "",
                timeout: "PT30S");
            await PostSoapAsync(body);
        }

        private async Task<string?> PostSoapAsync(string soapBody)
            => await SendEncryptedSoapAsync(soapBody);

        // ── IDisposable ──────────────────────────────────────────────────────────

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            if (!string.IsNullOrEmpty(_shellId) && _httpClient != null)
            {
                try
                {
                    // Best-effort shell cleanup — don't let this throw
                    DeleteShellAsync(_shellId).GetAwaiter().GetResult();
                }
                catch { /* best effort */ }
            }

            _httpClient?.Dispose();
            _httpClient       = null;
            _shellId          = null;
            _sessionSecurity?.Dispose();
            _sessionSecurity  = null;
            _execLock.Dispose();
        }
    }
}
