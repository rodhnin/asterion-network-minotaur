using System;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Serilog;

namespace Asterion.Core.Utils
{
    /// <summary>
    /// Per-target OS detection using passive network signals.
    ///
    /// Strategy (in order of reliability):
    ///   1. SSH banner (port 22) — "OpenSSH" → Linux/Unix; "OpenSSH_for_Windows" → Windows
    ///   2. SMB banner (port 445) — Windows SMB fingerprint strings
    ///   3. RDP banner (port 3389) — RDP cookie → Windows
    ///   4. ICMP TTL — ≤64 → Linux/Unix, 65-128 → Windows (fallback, less reliable)
    ///   5. Unknown — if all signals conflict or ports closed
    ///
    /// Used by Orchestrator before check dispatch to route per-target OS-specific checks.
    /// </summary>
    public class OsDetector
    {
        public enum TargetOS
        {
            Unknown,
            Windows,
            Linux,
            Unix   // BSD / macOS / Solaris detected via SSH banner
        }

        private readonly int _timeoutMs;

        public OsDetector(int timeoutMs = 3000)
        {
            _timeoutMs = timeoutMs;
        }

        /// <summary>
        /// Detect the operating system of a remote target.
        /// Returns TargetOS and a human-readable reason for the determination.
        /// </summary>
        public async Task<(TargetOS Os, string Reason)> DetectAsync(string host)
        {
            Log.Debug("[OsDetector] Detecting OS for {Host}", host);

            // ── Signal 1: SSH banner (most reliable) ─────────────────────────
            if (await NetworkUtils.IsPortOpenAsync(host, 22, _timeoutMs))
            {
                var sshBanner = await NetworkUtils.GetBannerAsync(host, 22, _timeoutMs);
                if (!string.IsNullOrWhiteSpace(sshBanner))
                {
                    var osFromSsh = ParseSshBanner(sshBanner);
                    if (osFromSsh != TargetOS.Unknown)
                    {
                        var reason = $"SSH banner: {sshBanner.Trim().Split('\n')[0].Trim()}";
                        Log.Information("[OsDetector] {Host} → {OS} via {Reason}", host, osFromSsh, reason);
                        return (osFromSsh, reason);
                    }
                }
            }

            // ── Signal 2: SMB (port 445) → Windows ───────────────────────────
            if (await NetworkUtils.IsPortOpenAsync(host, 445, _timeoutMs))
            {
                var smbResult = await ProbeSmbAsync(host);
                if (smbResult != TargetOS.Unknown)
                {
                    var reason = "SMB port 445 open with Windows SMB fingerprint";
                    Log.Information("[OsDetector] {Host} → {OS} via {Reason}", host, smbResult, reason);
                    return (smbResult, reason);
                }
            }

            // ── Signal 3: RDP (port 3389) → Windows ──────────────────────────
            if (await NetworkUtils.IsPortOpenAsync(host, 3389, _timeoutMs))
            {
                var reason = "RDP port 3389 open — exclusive to Windows";
                Log.Information("[OsDetector] {Host} → Windows via {Reason}", host, reason);
                return (TargetOS.Windows, reason);
            }

            // ── Signal 4: WinRM (port 5985/5986) → Windows ───────────────────
            if (await NetworkUtils.IsPortOpenAsync(host, 5985, _timeoutMs) ||
                await NetworkUtils.IsPortOpenAsync(host, 5986, _timeoutMs))
            {
                var reason = "WinRM port 5985/5986 open — exclusive to Windows";
                Log.Information("[OsDetector] {Host} → Windows via {Reason}", host, reason);
                return (TargetOS.Windows, reason);
            }

            // ── Signal 5: ICMP TTL (fallback, unreliable through NAT/firewalls) ─
            var ttlResult = await ProbeIcmpTtlAsync(host);
            if (ttlResult.Os != TargetOS.Unknown)
            {
                Log.Information("[OsDetector] {Host} → {OS} via {Reason}", host, ttlResult.Os, ttlResult.Reason);
                return ttlResult;
            }

            Log.Debug("[OsDetector] {Host} → Unknown (no conclusive signal)", host);
            return (TargetOS.Unknown, "No conclusive OS signal detected");
        }

        // ─── SSH Banner Parsing ────────────────────────────────────────────────

        private static TargetOS ParseSshBanner(string banner)
        {
            // "SSH-2.0-OpenSSH_for_Windows_8.6"  → Windows
            if (Regex.IsMatch(banner, @"OpenSSH_for_Windows", RegexOptions.IgnoreCase))
                return TargetOS.Windows;

            // "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"  → Linux
            if (Regex.IsMatch(banner, @"OpenSSH.*ubuntu|OpenSSH.*debian|OpenSSH.*centos|" +
                                       @"OpenSSH.*rhel|OpenSSH.*fedora|OpenSSH.*alpine|" +
                                       @"OpenSSH.*kali|OpenSSH.*arch", RegexOptions.IgnoreCase))
                return TargetOS.Linux;

            // BSD / macOS
            if (Regex.IsMatch(banner, @"OpenSSH.*FreeBSD|OpenSSH.*OpenBSD|OpenSSH.*NetBSD|" +
                                       @"OpenSSH.*Darwin", RegexOptions.IgnoreCase))
                return TargetOS.Unix;

            // Generic OpenSSH without OS hint — likely Linux (most common)
            if (Regex.IsMatch(banner, @"OpenSSH", RegexOptions.IgnoreCase))
                return TargetOS.Linux;

            // Cisco / network device SSH
            if (Regex.IsMatch(banner, @"Cisco|RouterOS|MikroTik|Juniper|FortiSSH", RegexOptions.IgnoreCase))
                return TargetOS.Unix;

            return TargetOS.Unknown;
        }

        // ─── SMB Probe ────────────────────────────────────────────────────────

        /// <summary>
        /// Send a minimal SMB negotiate request and check the response for Windows strings.
        /// A raw TCP connect to 445 + SMB negotiate preamble is sufficient to fingerprint.
        /// </summary>
        private async Task<TargetOS> ProbeSmbAsync(string host)
        {
            try
            {
                using var tcp = new TcpClient();
                // Use CancellationToken-based timeout — avoids blocking .Wait() inside async method
                using var cts = new System.Threading.CancellationTokenSource(_timeoutMs);
                try
                {
                    await tcp.ConnectAsync(host, 445, cts.Token);
                }
                catch
                {
                    return TargetOS.Unknown;
                }

                using var stream = tcp.GetStream();
                stream.WriteTimeout = _timeoutMs;
                stream.ReadTimeout  = _timeoutMs;

                // SMBv1 Negotiate Protocol Request (NetBIOS session + SMB header)
                // This is a minimal well-known byte sequence
                byte[] smbNegotiate = {
                    // NetBIOS session message
                    0x00, 0x00, 0x00, 0x2f,
                    // SMB header magic
                    0xff, 0x53, 0x4d, 0x42,
                    // Command: Negotiate (0x72), Status, Flags, Flags2
                    0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc0,
                    // PID high, Signature (8 bytes), Reserved, TID, PID, UID, MID
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
                    // WordCount, ByteCount
                    0x00, 0x0c, 0x00,
                    // Dialects: "NT LM 0.12"
                    0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00
                };

                await stream.WriteAsync(smbNegotiate, 0, smbNegotiate.Length);

                var buf = new byte[256];
                int read;
                try { read = await stream.ReadAsync(buf, 0, buf.Length); }
                catch { read = 0; }

                if (read < 9) return TargetOS.Unknown;

                // Check for SMB magic: 0xff 'SMB' in response
                bool hasSmbMagic = read >= 8 &&
                    buf[4] == 0xff && buf[5] == 0x53 && buf[6] == 0x4d && buf[7] == 0x42;

                if (hasSmbMagic)
                    return TargetOS.Windows;

                // SMB2 magic: 0xfe 'SMB'
                bool hasSMB2Magic = read >= 8 &&
                    buf[4] == 0xfe && buf[5] == 0x53 && buf[6] == 0x4d && buf[7] == 0x42;

                if (hasSMB2Magic)
                    return TargetOS.Windows;

                return TargetOS.Unknown;
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[OsDetector] SMB probe failed on {Host}", host);
                return TargetOS.Unknown;
            }
        }

        // ─── ICMP TTL Probe ───────────────────────────────────────────────────

        /// <summary>
        /// Ping the host and read the reply TTL.
        /// Initial TTL heuristic:
        ///   ≤ 64  → Linux/Unix (default TTL=64, decrements en-route)
        ///   ≤ 128 → Windows   (default TTL=128)
        ///   > 128 → Unknown   (Cisco/network device)
        /// NOTE: unreliable through NAT, VPN, or when TTL is manipulated.
        /// </summary>
        private async Task<(TargetOS Os, string Reason)> ProbeIcmpTtlAsync(string host)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(host, _timeoutMs);

                if (reply.Status != IPStatus.Success)
                    return (TargetOS.Unknown, "ICMP unreachable");

                var ttl = reply.Options?.Ttl ?? 0;
                if (ttl <= 0)
                    return (TargetOS.Unknown, "ICMP TTL not available");

                if (ttl <= 64)
                    return (TargetOS.Linux, $"ICMP TTL={ttl} (≤64 → Linux/Unix default)");

                if (ttl <= 128)
                    return (TargetOS.Windows, $"ICMP TTL={ttl} (65-128 → Windows default)");

                return (TargetOS.Unknown, $"ICMP TTL={ttl} (>128 → network device or custom)");
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "[OsDetector] ICMP probe failed on {Host}", host);
                return (TargetOS.Unknown, "ICMP probe failed");
            }
        }
    }
}
