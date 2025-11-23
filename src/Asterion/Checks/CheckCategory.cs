namespace Asterion.Checks
{
    /// <summary>
    /// Category of security check based on execution context
    /// </summary>
    public enum CheckCategory
    {
        /// <summary>
        /// Cross-platform network checks (SMB, RDP, LDAP, etc.)
        /// Can run from any OS, scans remote services
        /// </summary>
        CrossPlatform,

        /// <summary>
        /// Windows-specific local checks (firewall, registry, AD policies)
        /// Requires Windows OS with appropriate permissions
        /// </summary>
        Windows,

        /// <summary>
        /// Linux-specific local checks (iptables, SSH config, SUID binaries)
        /// Requires Linux OS with appropriate permissions
        /// </summary>
        Linux
    }
}