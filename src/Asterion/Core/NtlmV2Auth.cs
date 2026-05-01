using System;
using System.Security.Cryptography;
using System.Text;

namespace Asterion.Core
{
    /// <summary>
    /// Pure managed NTLMv2 implementation for WinRM authentication on Linux.
    ///
    /// Replaces NegotiateAuthentication + gss-ntlmssp (which generates tokens that
    /// Windows Server 2019 WinRM rejects despite status=Completed).
    ///
    /// Implements the MS-NLMP 3-way handshake:
    ///   Type1 → NTLMv2 Negotiate (40 bytes, with VERSION struct)
    ///   Type2 → Parse server challenge + target info
    ///   Type3 → NTLMv2 Authenticate (88-byte header, MIC, enhanced TargetInfo)
    ///
    /// Token format: raw NTLM bytes sent as "Authorization: Negotiate {base64}"
    /// (no SPNEGO wrapping — Windows WinRM accepts bare NTLM in Negotiate header).
    ///
    /// Key differences vs a minimal implementation (required by Windows Server 2016+):
    ///   - LM response = 24 bytes (ESS-style: client challenge + 16 zeros)
    ///   - TargetInfo enhanced with MsvAvFlags(2) + MsvAvChannelBindings(zeros)
    ///   - Type3 header = 88 bytes: [0..63] AUTHENTICATE fields +
    ///                              [64..71] VERSION struct +
    ///                              [72..87] MIC (HMAC-MD5 over entire handshake)
    /// </summary>
    internal sealed class NtlmV2Auth
    {
        private readonly string _username;
        private readonly string _domain;
        private readonly string _password;
        private readonly string _host;

        // Stored so BuildType3 can include Type1 in MIC computation
        private byte[]? _type1Bytes;

        /// <summary>
        /// The ExportedSessionKey after <see cref="BuildType3"/> is called.
        /// Use this to construct a <see cref="NtlmSessionSecurity"/> for message-level
        /// encryption (required by Windows WinRM AllowUnencrypted=False default).
        /// </summary>
        public byte[]? ExportedKey { get; private set; }

        public NtlmV2Auth(string username, string password, string domain = "", string host = "")
        {
            _username = username;
            _domain   = domain;
            _password = password;
            _host     = host;
        }

        // ── Public API ───────────────────────────────────────────────────────────

        /// <summary>Build an NTLM Type1 (Negotiate) message — 40 bytes with VERSION.</summary>
        public byte[] BuildType1()
        {
            // Flags matching pyspnego/requests-ntlm (which Windows Server 2019 accepts)
            const uint flags =
                NtlmFlags.NegotiateUnicode           |
                NtlmFlags.NegotiateOem               |
                NtlmFlags.RequestTarget              |
                NtlmFlags.NegotiateSign              |
                NtlmFlags.NegotiateSeal              |
                NtlmFlags.NegotiateNtlm              |
                NtlmFlags.NegotiateAlwaysSign        |
                NtlmFlags.NegotiateExtendedSecurity  |
                NtlmFlags.NegotiateVersion           |
                NtlmFlags.Negotiate128               |
                NtlmFlags.NegotiateKeyExch           |
                NtlmFlags.Negotiate56;

            // Header (32) + SecurityBuffers for domain/workstation (both empty = 16) + VERSION (8) = 40 bytes
            var buf = new byte[40];
            WriteSignature(buf, 0);
            LittleEndian(buf, 8,  1u);       // MessageType = 1
            LittleEndian(buf, 12, flags);
            // DomainNameFields [16..24] = zero (offset 40, len 0)
            LittleEndian(buf, 16, 0u); LittleEndian(buf, 20, 40u); // len=0 maxLen=0 offset=40
            // WorkstationFields [24..32] = zero (offset 40, len 0)
            LittleEndian(buf, 24, 0u); LittleEndian(buf, 28, 40u);
            // VERSION [32..39]: major=0, minor=10, build=0, reserved=0, revision=0x0F
            buf[32] = 0x00; buf[33] = 0x0a; buf[34] = 0x00; buf[35] = 0x00;
            buf[36] = 0x00; buf[37] = 0x00; buf[38] = 0x00; buf[39] = 0x0f;

            _type1Bytes = buf;
            return buf;
        }

        /// <summary>Build an NTLM Type3 (Authenticate) message from the server's Type2.</summary>
        public byte[] BuildType3(byte[] type2)
        {
            if (_type1Bytes == null)
                throw new InvalidOperationException("Call BuildType1() before BuildType3().");

            // ── Parse Type2 ───────────────────────────────────────────────────
            var serverChallenge = new byte[8];
            Array.Copy(type2, 24, serverChallenge, 0, 8);

            var targetInfoLen    = type2.Length >= 44 ? LittleEndian16(type2, 40) : 0;
            var targetInfoOffset = type2.Length >= 48 ? LittleEndian32(type2, 44) : 0;
            var serverTargetInfo = targetInfoLen > 0 && targetInfoOffset + targetInfoLen <= type2.Length
                ? type2[targetInfoOffset..(targetInfoOffset + targetInfoLen)]
                : Array.Empty<byte>();

            // ── Check if server sent AvTimestamp (AvId=7) ────────────────────
            // Windows Server 2016+ always sends Timestamp. When present:
            //   • Use the server's timestamp in the blob (not client time)
            //   • LM response → 24 zero bytes (not computed value)
            //   • MIC field → required, computed with ExportedSessionKey
            var serverTimestamp = FindAvPairValue(serverTargetInfo, 7); // AvId.timestamp
            bool micRequired    = serverTimestamp != null;
            var tsBytes         = serverTimestamp ?? BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc());

            // ── Build enhanced TargetInfo ─────────────────────────────────────
            // Preserve server's AvPairs in original order (strip EOL), then append:
            //   AvId=9  MsvAvTargetName = SPN "http/<host>" (required for Windows Server 2016+)
            //   AvId=6  MsvAvFlags = 0x00000002 (MIC_PROVIDED, when mic is required)
            //   AvId=0  EOL
            // Note: NO AvId=10 ChannelBindings — pywinrm does not send these by default.
            var strippedInfo = StripAvEol(serverTargetInfo);
            var spnBytes     = Encoding.Unicode.GetBytes($"http/{_host}");
            var avTargetName = MakeAvPair(9, spnBytes);                               // SPN
            var avEol        = new byte[] { 0x00, 0x00, 0x00, 0x00 };
            byte[] enhancedInfo;
            if (micRequired)
            {
                var avFlags  = MakeAvPair(6, new byte[] { 0x02, 0x00, 0x00, 0x00 }); // MIC present
                enhancedInfo = Concat(strippedInfo, avTargetName, avFlags, avEol);
            }
            else
            {
                enhancedInfo = Concat(strippedInfo, avTargetName, avEol);
            }

            // ── Compute NTLMv2 response ───────────────────────────────────────
            var ntHash    = NtHash(_password);
            var ntlmV2Key = NtlmV2Hash(ntHash, _username, _domain);

            var clientChallenge = new byte[8];
            RandomNumberGenerator.Fill(clientChallenge);

            // NTLMv2 blob per MS-NLMP / spnego source:
            //   NTClientChallengeV2.pack() = header(8)+Timestamp(8)+ClientChallenge(8)+Z(4)+TargetInfo
            //   Then b"\x00\x00\x00\x00" is appended before HMAC and included in NTResponse.
            // The 4 trailing zeros are separate from the MsvAvEOL at the end of TargetInfo.
            var blob = Concat(
                new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                tsBytes,
                clientChallenge,
                new byte[4],       // reserved Z(4)
                enhancedInfo,      // enhanced AvPairs (ends with MsvAvEOL = 4 bytes)
                new byte[4]        // 4 additional trailing zeros (spnego: b"\x00\x00\x00\x00")
            );

            var ntProofStr = HmacMd5(ntlmV2Key, Concat(serverChallenge, blob));
            var ntResponse = Concat(ntProofStr, blob);

            // LM response: when MIC is required (server sent Timestamp), must be 24 zero bytes.
            // Otherwise: clientChallenge + 16 zeros (ESS-style).
            var lmResponse = micRequired ? new byte[24] : Concat(clientChallenge, new byte[16]);

            // Session key
            var sessionBaseKey = HmacMd5(ntlmV2Key, ntProofStr);
            var exportedKey    = new byte[16];
            RandomNumberGenerator.Fill(exportedKey);
            using var rc4 = new RC4(sessionBaseKey);
            var encryptedKey   = rc4.Process(exportedKey);

            // Expose the exportedKey so the caller can build NtlmSessionSecurity
            ExportedKey = exportedKey;

            // ── Build Type3 layout ────────────────────────────────────────────
            // [0..63]  Standard AUTHENTICATE_MESSAGE header fields
            // [64..71] VERSION struct (8 bytes)
            // [72..87] MIC field (16 bytes, initially zero — filled in after MIC computation)
            // [88..]   Payload
            const int headerSize = 88;

            var domainBytes = Encoding.Unicode.GetBytes(_domain);
            var userBytes   = Encoding.Unicode.GetBytes(_username);
            var wsBytes     = Encoding.Unicode.GetBytes(GetWorkstation());

            var lmOff  = headerSize;
            var ntOff  = lmOff  + lmResponse.Length;
            var domOff = ntOff  + ntResponse.Length;
            var usrOff = domOff + domainBytes.Length;
            var wsOff  = usrOff + userBytes.Length;
            var skOff  = wsOff  + wsBytes.Length;
            var total  = skOff  + encryptedKey.Length;

            var msg = new byte[total];
            WriteSignature(msg, 0);
            LittleEndian(msg, 8, 3u);  // MessageType = 3

            WriteSecBuf(msg, 12, (ushort)lmResponse.Length,  lmOff);
            WriteSecBuf(msg, 20, (ushort)ntResponse.Length,  ntOff);
            WriteSecBuf(msg, 28, (ushort)domainBytes.Length, domOff);
            WriteSecBuf(msg, 36, (ushort)userBytes.Length,   usrOff);
            WriteSecBuf(msg, 44, (ushort)wsBytes.Length,     wsOff);
            WriteSecBuf(msg, 52, (ushort)encryptedKey.Length, skOff);

            // Flags: match working requests-ntlm value (0xe2898235).
            // Key differences vs Type1:
            //   - No NegotiateOem (0x02) — Type3 must be Unicode-only
            //   - NtlmTargetTypeDomain (0x00010000) — echoed from server's Type2 (DC target)
            const uint flags3 =
                NtlmFlags.NegotiateUnicode           |
                NtlmFlags.RequestTarget              |
                NtlmFlags.NegotiateSign              |
                NtlmFlags.NegotiateSeal              |
                NtlmFlags.NegotiateNtlm              |
                NtlmFlags.NegotiateAlwaysSign        |
                NtlmFlags.NtlmTargetTypeDomain       |
                NtlmFlags.NegotiateTargetInfo        |
                NtlmFlags.NegotiateExtendedSecurity  |
                NtlmFlags.NegotiateVersion           |
                NtlmFlags.Negotiate128               |
                NtlmFlags.NegotiateKeyExch           |
                NtlmFlags.Negotiate56;
            LittleEndian(msg, 60, flags3);

            // VERSION [64..71]: same as Type1
            msg[64] = 0x00; msg[65] = 0x0a; msg[66] = 0x00; msg[67] = 0x00;
            msg[68] = 0x00; msg[69] = 0x00; msg[70] = 0x00; msg[71] = 0x0f;

            // MIC [72..87]: leave as zeros — will compute and overwrite below

            // Payload
            Array.Copy(lmResponse,   0, msg, lmOff,  lmResponse.Length);
            Array.Copy(ntResponse,   0, msg, ntOff,  ntResponse.Length);
            Array.Copy(domainBytes,  0, msg, domOff, domainBytes.Length);
            Array.Copy(userBytes,    0, msg, usrOff, userBytes.Length);
            Array.Copy(wsBytes,      0, msg, wsOff,  wsBytes.Length);
            Array.Copy(encryptedKey, 0, msg, skOff,  encryptedKey.Length);

            // ── Compute MIC ───────────────────────────────────────────────────
            // MIC = HMAC-MD5(ExportedSessionKey, Type1 || Type2 || Type3_with_MIC=0)
            // ExportedSessionKey is the plaintext random key (before RC4 encryption)
            var micInput = Concat(_type1Bytes, type2, msg);
            var mic      = HmacMd5(exportedKey, micInput);
            Array.Copy(mic, 0, msg, 72, 16);

            return msg;
        }

        // ── NTLM Cryptography ────────────────────────────────────────────────────

        private static byte[] NtHash(string password)
            => Md4.Hash(Encoding.Unicode.GetBytes(password));

        private static byte[] NtlmV2Hash(byte[] ntHash, string username, string domain)
        {
            var value = Encoding.Unicode.GetBytes(username.ToUpperInvariant() + domain);
            return HmacMd5(ntHash, value);
        }

        private static byte[] HmacMd5(byte[] key, byte[] data)
        {
            using var h = new HMACMD5(key);
            return h.ComputeHash(data);
        }

        // ── AvPair helpers ────────────────────────────────────────────────────────

        /// <summary>
        /// Scan the serialized AvPairs for a specific AvId and return its value bytes.
        /// Returns null if AvId not found.
        /// </summary>
        private static byte[]? FindAvPairValue(byte[] avPairs, ushort targetAvId)
        {
            int pos = 0;
            while (pos + 4 <= avPairs.Length)
            {
                var avId  = (ushort)(avPairs[pos] | (avPairs[pos + 1] << 8));
                var avLen = (ushort)(avPairs[pos + 2] | (avPairs[pos + 3] << 8));
                if (avId == 0) break;  // MsvAvEOL
                if (avId == targetAvId && avLen > 0 && pos + 4 + avLen <= avPairs.Length)
                {
                    var val = new byte[avLen];
                    Array.Copy(avPairs, pos + 4, val, 0, avLen);
                    return val;
                }
                pos += 4 + avLen;
            }
            return null;
        }

        /// <summary>Build one AvPair: AvId (2 bytes LE) + AvLen (2 bytes LE) + value.</summary>
        private static byte[] MakeAvPair(ushort avId, byte[] value)
        {
            var pair = new byte[4 + value.Length];
            pair[0] = (byte)(avId);
            pair[1] = (byte)(avId >> 8);
            pair[2] = (byte)(value.Length);
            pair[3] = (byte)(value.Length >> 8);
            Array.Copy(value, 0, pair, 4, value.Length);
            return pair;
        }

        /// <summary>Remove the last AvPair if it is MsvAvEOL (0x0000, 0x0000).</summary>
        private static byte[] StripAvEol(byte[] avPairs)
        {
            if (avPairs.Length >= 4 &&
                avPairs[avPairs.Length - 4] == 0 &&
                avPairs[avPairs.Length - 3] == 0 &&
                avPairs[avPairs.Length - 2] == 0 &&
                avPairs[avPairs.Length - 1] == 0)
            {
                return avPairs[..(avPairs.Length - 4)];
            }
            return avPairs;
        }

        // ── Encoding helpers ──────────────────────────────────────────────────────

        private static string GetWorkstation()
        {
            try { return System.Net.Dns.GetHostName().ToUpperInvariant(); }
            catch { return "WORKSTATION"; }
        }

        private static void WriteSignature(byte[] buf, int offset)
        {
            buf[offset]   = 0x4e; buf[offset+1] = 0x54; buf[offset+2] = 0x4c;
            buf[offset+3] = 0x4d; buf[offset+4] = 0x53; buf[offset+5] = 0x53;
            buf[offset+6] = 0x50; buf[offset+7] = 0x00;
        }

        private static void LittleEndian(byte[] buf, int offset, uint value)
        {
            buf[offset]   = (byte)(value);
            buf[offset+1] = (byte)(value >> 8);
            buf[offset+2] = (byte)(value >> 16);
            buf[offset+3] = (byte)(value >> 24);
        }

        private static void WriteSecBuf(byte[] buf, int offset, ushort length, int dataOffset)
        {
            buf[offset]   = (byte)(length);
            buf[offset+1] = (byte)(length >> 8);
            buf[offset+2] = (byte)(length);      // MaxLen = Length
            buf[offset+3] = (byte)(length >> 8);
            buf[offset+4] = (byte)(dataOffset);
            buf[offset+5] = (byte)(dataOffset >> 8);
            buf[offset+6] = (byte)(dataOffset >> 16);
            buf[offset+7] = (byte)(dataOffset >> 24);
        }

        private static int LittleEndian16(byte[] buf, int offset)
            => buf[offset] | (buf[offset+1] << 8);

        private static int LittleEndian32(byte[] buf, int offset)
            => buf[offset] | (buf[offset+1] << 8) | (buf[offset+2] << 16) | (buf[offset+3] << 24);

        private static byte[] Concat(params byte[][] arrays)
        {
            var total  = 0;
            foreach (var a in arrays) total += a.Length;
            var result = new byte[total];
            var pos    = 0;
            foreach (var a in arrays) { Array.Copy(a, 0, result, pos, a.Length); pos += a.Length; }
            return result;
        }

        // ── NTLM flags ───────────────────────────────────────────────────────────

        private static class NtlmFlags
        {
            public const uint NegotiateUnicode           = 0x00000001;
            public const uint NegotiateOem               = 0x00000002;
            public const uint RequestTarget              = 0x00000004;
            public const uint NegotiateSign              = 0x00000010;
            public const uint NegotiateSeal              = 0x00000020;
            public const uint NegotiateNtlm              = 0x00000200;
            public const uint NegotiateAlwaysSign        = 0x00008000;
            public const uint NtlmTargetTypeDomain       = 0x00010000; // Server is a domain (echoed from Type2)
            public const uint NegotiateTargetInfo        = 0x00800000;
            public const uint NegotiateExtendedSecurity  = 0x00080000;
            public const uint NegotiateVersion           = 0x02000000;
            public const uint Negotiate128               = 0x20000000;
            public const uint NegotiateKeyExch           = 0x40000000;
            public const uint Negotiate56                = 0x80000000;
        }
    }

    // ── RC4 (for session key encryption) ────────────────────────────────────────

    internal sealed class RC4 : IDisposable
    {
        private readonly byte[] _s = new byte[256];
        private int _i, _j;

        public RC4(byte[] key)
        {
            for (int i = 0; i < 256; i++) _s[i] = (byte)i;
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + _s[i] + key[i % key.Length]) & 0xff;
                (_s[i], _s[j]) = (_s[j], _s[i]);
            }
        }

        public byte[] Process(byte[] data)
        {
            var output = new byte[data.Length];
            for (int k = 0; k < data.Length; k++)
            {
                _i = (_i + 1) & 0xff;
                _j = (_j + _s[_i]) & 0xff;
                (_s[_i], _s[_j]) = (_s[_j], _s[_i]);
                output[k] = (byte)(data[k] ^ _s[(_s[_i] + _s[_j]) & 0xff]);
            }
            return output;
        }

        public void Dispose() { }
    }

    // ── MD4 ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// MD4 hash (RFC 1320). Required for NTLM NT hash computation.
    /// MD4 is not in .NET's standard library.
    /// </summary>
    internal static class Md4
    {
        public static byte[] Hash(byte[] input)
        {
            var msgLen  = input.Length;
            var bitLen  = (ulong)msgLen * 8;
            var zeroPad = (55 - msgLen % 64 + 64) % 64;
            var padded  = new byte[msgLen + 1 + zeroPad + 8];
            Array.Copy(input, padded, msgLen);
            padded[msgLen] = 0x80;
            BitConverter.GetBytes(bitLen).CopyTo(padded, msgLen + 1 + zeroPad);

            uint a = 0x67452301u, b = 0xefcdab89u, c = 0x98badcfeu, d = 0x10325476u;

            for (int i = 0; i < padded.Length; i += 64)
            {
                var X = new uint[16];
                for (int j = 0; j < 16; j++)
                    X[j] = BitConverter.ToUInt32(padded, i + j * 4);

                uint aa = a, bb = b, cc = c, dd = d;

                static uint F(uint x, uint y, uint z) => (x & y) | (~x & z);
                static uint R1(uint v, uint w, uint x, uint y, uint k, int s)
                    => RotL(v + F(w, x, y) + k, s);

                a = R1(a,b,c,d,X[0], 3); d=R1(d,a,b,c,X[1], 7); c=R1(c,d,a,b,X[2], 11); b=R1(b,c,d,a,X[3], 19);
                a = R1(a,b,c,d,X[4], 3); d=R1(d,a,b,c,X[5], 7); c=R1(c,d,a,b,X[6], 11); b=R1(b,c,d,a,X[7], 19);
                a = R1(a,b,c,d,X[8], 3); d=R1(d,a,b,c,X[9], 7); c=R1(c,d,a,b,X[10],11); b=R1(b,c,d,a,X[11],19);
                a = R1(a,b,c,d,X[12],3); d=R1(d,a,b,c,X[13],7); c=R1(c,d,a,b,X[14],11); b=R1(b,c,d,a,X[15],19);

                const uint C2 = 0x5a827999u;
                static uint G(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);
                static uint R2(uint v, uint w, uint x, uint y, uint k, int s)
                    => RotL(v + G(w, x, y) + k + C2, s);

                a=R2(a,b,c,d,X[0], 3); d=R2(d,a,b,c,X[4], 5); c=R2(c,d,a,b,X[8], 9); b=R2(b,c,d,a,X[12],13);
                a=R2(a,b,c,d,X[1], 3); d=R2(d,a,b,c,X[5], 5); c=R2(c,d,a,b,X[9], 9); b=R2(b,c,d,a,X[13],13);
                a=R2(a,b,c,d,X[2], 3); d=R2(d,a,b,c,X[6], 5); c=R2(c,d,a,b,X[10],9); b=R2(b,c,d,a,X[14],13);
                a=R2(a,b,c,d,X[3], 3); d=R2(d,a,b,c,X[7], 5); c=R2(c,d,a,b,X[11],9); b=R2(b,c,d,a,X[15],13);

                const uint C3 = 0x6ed9eba1u;
                static uint H(uint x, uint y, uint z) => x ^ y ^ z;
                static uint R3(uint v, uint w, uint x, uint y, uint k, int s)
                    => RotL(v + H(w, x, y) + k + C3, s);

                a=R3(a,b,c,d,X[0], 3); d=R3(d,a,b,c,X[8], 9); c=R3(c,d,a,b,X[4],11); b=R3(b,c,d,a,X[12],15);
                a=R3(a,b,c,d,X[2], 3); d=R3(d,a,b,c,X[10],9); c=R3(c,d,a,b,X[6],11); b=R3(b,c,d,a,X[14],15);
                a=R3(a,b,c,d,X[1], 3); d=R3(d,a,b,c,X[9], 9); c=R3(c,d,a,b,X[5],11); b=R3(b,c,d,a,X[13],15);
                a=R3(a,b,c,d,X[3], 3); d=R3(d,a,b,c,X[11],9); c=R3(c,d,a,b,X[7],11); b=R3(b,c,d,a,X[15],15);

                a += aa; b += bb; c += cc; d += dd;
            }

            var hash = new byte[16];
            BitConverter.GetBytes(a).CopyTo(hash, 0);
            BitConverter.GetBytes(b).CopyTo(hash, 4);
            BitConverter.GetBytes(c).CopyTo(hash, 8);
            BitConverter.GetBytes(d).CopyTo(hash, 12);
            return hash;
        }

        private static uint RotL(uint x, int n) => (x << n) | (x >> (32 - n));
    }

    // ── NTLM Session Security (MS-WSMV 2.2.9.1 / MS-NLMP 3.4) ──────────────────
    //
    // Windows WinRM requires message-level encryption by default (AllowUnencrypted=False).
    // After the NTLM Type1/Type3 handshake, all SOAP bodies must be wrapped in a
    // multipart/encrypted MIME envelope using RC4 + HMAC-MD5 signing.
    //
    // Key derivation from ExportedSessionKey (per MS-NLMP 3.4.5.1):
    //   ClientSignKey = MD5(ExportedSessionKey + CLIENT_SIGN_MAGIC + "\0")
    //   ClientSealKey = MD5(ExportedSessionKey + CLIENT_SEAL_MAGIC + "\0")
    //   ServerSignKey = MD5(ExportedSessionKey + SERVER_SIGN_MAGIC + "\0")
    //   ServerSealKey = MD5(ExportedSessionKey + SERVER_SEAL_MAGIC + "\0")
    //
    // Sealing (MS-NLMP 3.4.4.2, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY):
    //   EncMsg  = RC4(ClientSealHandle, plaintext)         -- stateful RC4
    //   Chksum  = HMAC-MD5(ClientSignKey, SeqNum||plain)[0:8]
    //   Chksum ^= RC4(ClientSealHandle, 8_zeros)           -- same stateful handle
    //   Sig     = 0x00000001 + Chksum + SeqNum             -- 16 bytes
    //
    // Multipart MIME wrapper for SOAP (Content-Type=multipart/encrypted;...):
    //   --Encrypted Boundary
    //     Content-Type: application/HTTP-SPNEGO-session-encrypted
    //     OriginalContent: type=application/soap+xml;charset=UTF-8;Length=<len>
    //   --Encrypted Boundary
    //     Content-Type: application/octet-stream
    //     [4-byte LE sig_len=16][16-byte sig][sealed_message]
    //   --Encrypted Boundary--

    internal sealed class NtlmSessionSecurity : IDisposable
    {
        private const string ClientSignMagic = "session key to client-to-server signing key magic constant\0";
        private const string ClientSealMagic = "session key to client-to-server sealing key magic constant\0";
        private const string ServerSignMagic = "session key to server-to-client signing key magic constant\0";
        private const string ServerSealMagic = "session key to server-to-client sealing key magic constant\0";

        private const string ProtocolString = "application/HTTP-SPNEGO-session-encrypted";
        private const string MimeBoundary    = "--Encrypted Boundary";

        private readonly byte[] _clientSignKey;
        private readonly byte[] _serverSignKey;
        private RC4 _clientSealRc4;
        private RC4 _serverSealRc4;
        private uint _sendSeq;
        private uint _recvSeq;
        private bool _disposed;

        public NtlmSessionSecurity(byte[] exportedSessionKey)
        {
            _clientSignKey  = Md5(Concat(exportedSessionKey, Encoding.ASCII.GetBytes(ClientSignMagic)));
            var clientSeal  = Md5(Concat(exportedSessionKey, Encoding.ASCII.GetBytes(ClientSealMagic)));
            _serverSignKey  = Md5(Concat(exportedSessionKey, Encoding.ASCII.GetBytes(ServerSignMagic)));
            var serverSeal  = Md5(Concat(exportedSessionKey, Encoding.ASCII.GetBytes(ServerSealMagic)));
            _clientSealRc4  = new RC4(clientSeal);
            _serverSealRc4  = new RC4(serverSeal);
        }

        // ── Seal outgoing message ───────────────────────────────────────────────

        /// <summary>
        /// Encrypt and sign <paramref name="message"/> using the client-to-server session keys.
        /// Returns (signature[16], sealedMessage).
        /// </summary>
        public (byte[] signature, byte[] sealedMessage) Seal(byte[] message)
        {
            var seqBytes      = BitConverter.GetBytes(_sendSeq++);         // LE32
            var sealedMessage = _clientSealRc4.Process(message);            // RC4 encrypt

            // HMAC-MD5(SignKey, SeqNum||plaintext)[0:8]
            var hmac8 = HmacMd5Slice8(_clientSignKey, seqBytes, message);

            // XOR with next 8 RC4 bytes from the same seal handle
            var xorKey    = _clientSealRc4.Process(new byte[8]);
            var checksum  = new byte[8];
            for (int i = 0; i < 8; i++) checksum[i] = (byte)(hmac8[i] ^ xorKey[i]);

            // Signature: version(1 LE32) + checksum(8) + seqNum(LE32) = 16 bytes
            var sig = new byte[16];
            sig[0] = 1;                                    // version = 0x00000001
            Array.Copy(checksum, 0, sig, 4, 8);
            Array.Copy(seqBytes, 0, sig, 12, 4);

            return (sig, sealedMessage);
        }

        /// <summary>
        /// Build the multipart/encrypted MIME body for a SOAP payload.
        /// Returns the raw bytes and the Content-Type header value.
        /// </summary>
        public (byte[] body, string contentType) BuildEncryptedBody(byte[] soapBytes)
        {
            var (sig, sealed_) = Seal(soapBytes);

            // encrypted_stream = 4-byte sig_len + signature + sealed_message
            var sigLen = BitConverter.GetBytes((int)sig.Length);   // always 16

            using var ms = new System.IO.MemoryStream();
            void WriteStr(string s)  { var b = Encoding.ASCII.GetBytes(s); ms.Write(b); }
            void WriteBytes(byte[] b){ ms.Write(b); }

            WriteStr($"{MimeBoundary}\r\n");
            WriteStr($"\tContent-Type: {ProtocolString}\r\n");
            WriteStr($"\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={soapBytes.Length}\r\n");
            WriteStr($"{MimeBoundary}\r\n");
            WriteStr($"\tContent-Type: application/octet-stream\r\n");
            WriteBytes(sigLen);
            WriteBytes(sig);
            WriteBytes(sealed_);
            // Final boundary immediately after binary content — NO preceding \r\n (matches pywinrm exactly)
            WriteStr($"{MimeBoundary}--\r\n");

            var contentType = $"multipart/encrypted;protocol=\"{ProtocolString}\";boundary=\"Encrypted Boundary\"";
            return (ms.ToArray(), contentType);
        }

        // ── Unseal incoming message ──────────────────────────────────────────────

        /// <summary>
        /// Decrypt and verify a MIME-encrypted server response.
        /// Returns the decrypted SOAP bytes (or the raw body if not encrypted).
        /// </summary>
        public byte[] DecryptResponse(string contentType, byte[] responseBody)
        {
            if (!contentType.Contains(ProtocolString))
                return responseBody;   // not encrypted — return as-is

            // Parse MIME: find the octet-stream part (after the 2nd boundary)
            var encPayload = ExtractOctetStream(responseBody);
            if (encPayload == null) return responseBody;

            // encPayload = sigLen(4) + sig(16) + sealedMessage
            if (encPayload.Length < 20) return responseBody;
            var sigLen        = BitConverter.ToInt32(encPayload, 0);
            if (sigLen < 0 || 4 + sigLen > encPayload.Length) return responseBody;
            var sig           = encPayload[4..(4 + sigLen)];
            var sealedMessage = encPayload[(4 + sigLen)..];

            // Decrypt with server seal key (RC4 advances by len(sealedMessage))
            var plaintext = _serverSealRc4.Process(sealedMessage);

            // The server also consumed 8 more RC4 bytes for the signature XOR — we must advance
            // our handle by the same 8 bytes to stay in sync for subsequent messages.
            _ = _serverSealRc4.Process(new byte[8]);

            // (Signature verification skipped — just return plaintext)
            _ = sig;
            _recvSeq++;

            return plaintext;
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private static byte[] Md5(byte[] data)
        {
            using var md5 = System.Security.Cryptography.MD5.Create();
            return md5.ComputeHash(data);
        }

        private static byte[] HmacMd5Slice8(byte[] key, byte[] a, byte[] b)
        {
            using var h = new HMACMD5(key);
            h.TransformBlock(a, 0, a.Length, null, 0);
            h.TransformFinalBlock(b, 0, b.Length);
            return h.Hash![..8];
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Array.Copy(a, 0, r, 0,        a.Length);
            Array.Copy(b, 0, r, a.Length, b.Length);
            return r;
        }

        private static byte[]? ExtractOctetStream(byte[] mimeBody)
        {
            // Find "--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n"
            // then return the bytes after that line until the next boundary
            var marker    = Encoding.ASCII.GetBytes("application/octet-stream\r\n");
            var end       = Encoding.ASCII.GetBytes(MimeBoundary);
            int startIdx  = IndexOf(mimeBody, marker);
            if (startIdx < 0) return null;
            int dataStart = startIdx + marker.Length;
            int dataEnd   = IndexOf(mimeBody, end, dataStart);
            if (dataEnd < 0) dataEnd = mimeBody.Length;
            // Trim trailing \r\n before next boundary
            while (dataEnd > dataStart && (mimeBody[dataEnd - 1] == '\n' || mimeBody[dataEnd - 1] == '\r'))
                dataEnd--;
            return mimeBody[dataStart..dataEnd];
        }

        private static int IndexOf(byte[] haystack, byte[] needle, int from = 0)
        {
            for (int i = from; i <= haystack.Length - needle.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < needle.Length; j++)
                    if (haystack[i + j] != needle[j]) { found = false; break; }
                if (found) return i;
            }
            return -1;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _clientSealRc4.Dispose();
            _serverSealRc4.Dispose();
        }
    }
}
