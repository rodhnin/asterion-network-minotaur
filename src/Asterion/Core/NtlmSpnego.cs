using System;

namespace Asterion.Core
{
    /// <summary>
    /// Minimal SPNEGO helper for unwrapping NTLM tokens from server WWW-Authenticate responses.
    ///
    /// WinRM servers may return a SPNEGO-wrapped Type2 challenge in the Negotiate header.
    /// This class extracts the raw NTLM bytes (identified by the NTLMSSP\0 signature) so
    /// NtlmV2Auth can process the server challenge directly.
    /// </summary>
    internal static class NtlmSpnego
    {
        // NTLMSSP signature bytes
        private static readonly byte[] NtlmSig = { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 };

        /// <summary>
        /// Extract raw NTLM bytes from a SPNEGO server token.
        /// Looks for the NTLMSSP\0 signature anywhere in the token.
        /// Returns null if not found (caller should use the raw token as-is).
        /// </summary>
        public static byte[]? ExtractNtlm(byte[] spnegoToken)
        {
            int idx = IndexOf(spnegoToken, NtlmSig);
            return idx >= 0 ? spnegoToken[idx..] : null;
        }

        private static int IndexOf(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < needle.Length; j++)
                    if (haystack[i + j] != needle[j]) { found = false; break; }
                if (found) return i;
            }
            return -1;
        }
    }
}
