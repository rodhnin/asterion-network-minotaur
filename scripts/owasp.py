"""
OWASP Top 10 2021 Compliance Mapping for Asterion Network Security Auditor

Maps each AST-* finding code to its OWASP Top 10 2021 category.
Applied automatically during AI enrichment — no changes needed in C# scanners.

Reference: https://owasp.org/Top10/
"""

# OWASP Top 10 2021 categories
OWASP_CATEGORIES = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection',
    'A04': 'Insecure Design',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable and Outdated Components',
    'A07': 'Identification and Authentication Failures',
    'A08': 'Software and Data Integrity Failures',
    'A09': 'Security Logging and Monitoring Failures',
    'A10': 'Server-Side Request Forgery (SSRF)',
}

# Mapping: AST-* finding ID → OWASP category ID
FINDING_TO_OWASP = {

    # =========================================================================
    # SMB / CIFS (SmbScanner.cs)
    # =========================================================================
    'AST-SMB-001': 'A01',   # Guest/null session → anonymous access = broken access control
    'AST-SMB-002': 'A05',   # SMB signing not required → misconfiguration enabling relay
    'AST-SMB-003': 'A06',   # SMBv1 enabled = vulnerable and outdated component (EternalBlue)
    'AST-SMB-004': 'A07',   # NTLMv1 authentication = identification/authentication failure
    'AST-SMB-005': 'A01',   # Writable/sensitive share via pass-the-hash = broken access control

    # =========================================================================
    # RDP (RdpScanner.cs)
    # =========================================================================
    'AST-RDP-001': 'A07',   # No NLA = authentication failure (pre-auth attack surface)
    'AST-RDP-002': 'A02',   # Legacy RC4/Standard RDP Security = cryptographic failure
    'AST-RDP-003': 'A06',   # BlueKeep heuristic = vulnerable outdated component
    'AST-RDP-004': 'A05',   # Self-signed/default certificate = misconfiguration

    # =========================================================================
    # LDAP / Active Directory (LdapScanner.cs)
    # =========================================================================
    'AST-LDAP-001': 'A07',  # Anonymous bind = authentication failure
    'AST-LDAP-002': 'A02',  # No LDAPS (cleartext LDAP) = cryptographic failure
    'AST-LDAP-003': 'A05',  # Domain trusts = security misconfiguration (expanded attack surface)
    'AST-AD-001':   'A05',  # LDAP signing not required = misconfiguration (relay risk)
    'AST-AD-002':   'A07',  # Weak password policy = identification/authentication failure
    'AST-AD-003':   'A02',  # RC4/NTLMv1 Kerberos encryption = cryptographic failure
    'AST-AD-004':   'A07',  # Passwords never expire (admins) = authentication weakness
    'AST-AD-005':   'A05',  # Account lockout disabled = misconfiguration (brute-force)
    'AST-AD-006':   'A05',  # GPO weak permissions = misconfiguration
    'AST-AD-007':   'A01',  # Unconstrained delegation = broken access control
    'AST-AD-008':   'A01',  # AdminSDHolder misconfiguration = broken access control

    # =========================================================================
    # AD Policies — local Windows checks (AdPolicyCheck.cs)
    # =========================================================================
    'AST-AD-WIN-001': 'A05',  # LDAP signing not required (local GPO) = misconfiguration
    'AST-AD-WIN-002': 'A07',  # Weak password policy / excess privileged users = auth failure
    'AST-AD-WIN-003': 'A01',  # Insecure domain trusts = broken access control

    # =========================================================================
    # Kerberos (KerberosScanner.cs)
    # =========================================================================
    'AST-KRB-001':  'A07',  # AS-REP roasting (DONT_REQUIRE_PREAUTH) = auth failure
    'AST-KRB-002':  'A05',  # Excessive ticket lifetime = misconfiguration
    'AST-KRB-003':  'A01',  # Kerberoastable SPNs = broken access control (hash exposure)

    # =========================================================================
    # SNMP (SnmpScanner.cs)
    # AST-SNMP-001 = default community strings (public/private)
    # AST-SNMP-002 = SNMP RW write access (community has write perms)
    # AST-SNMP-003 = SNMPv1/v2c plaintext protocol in use
    # =========================================================================
    'AST-SNMP-001': 'A07',  # Default community strings = authentication failure
    'AST-SNMP-002': 'A01',  # SNMP write access = broken access control
    'AST-SNMP-003': 'A02',  # SNMPv1/v2c cleartext = cryptographic failure

    # =========================================================================
    # DNS / Network (DnsScanner.cs)
    # =========================================================================
    'AST-NET-001':  'A05',  # DNS zone transfer allowed = misconfiguration (info disclosure)
    'AST-NET-002':  'A05',  # LLMNR/NetBIOS active = misconfiguration (poisoning risk)
    'AST-NET-003':  'A05',  # mDNS responder active = misconfiguration (info disclosure)
    'AST-NET-004':  'A05',  # Dangerous service exposed on unexpected port = misconfiguration
    'AST-DNS-001':  'A05',  # Zone transfer (scanner code) = misconfiguration
    'AST-DNS-003':  'A05',  # mDNS responder (scanner code) = misconfiguration

    # =========================================================================
    # FTP (FtpScanner.cs)
    # =========================================================================
    'AST-FTP-001':  'A07',  # Anonymous FTP access = authentication failure
    'AST-FTP-002':  'A01',  # Anonymous write access = broken access control
    'AST-FTP-003':  'A02',  # No FTPS (plaintext) = cryptographic failure
    'AST-FTP-004':  'A05',  # FTP banner version disclosure = misconfiguration

    # =========================================================================
    # Windows Firewall (WinFirewallCheck.cs)
    # =========================================================================
    'AST-FW-001':     'A05',  # Firewall disabled / default allow = misconfiguration
    'AST-FW-002':     'A05',  # Permissive rules (ANY source) = misconfiguration
    'AST-FW-003':     'A09',  # Firewall logging disabled = logging failure
    'AST-FW-WIN-001': 'A05',
    'AST-FW-WIN-002': 'A05',
    'AST-FW-WIN-003': 'A09',
    'AST-FW-WIN-004': 'A05',

    # =========================================================================
    # Windows Registry (WinRegistryCheck.cs)
    # =========================================================================
    'AST-WIN-001':     'A07',  # LM/NTLMv1 auth (LmCompatibilityLevel < 5) = auth failure
    'AST-WIN-002':     'A05',  # UAC disabled = misconfiguration
    'AST-WIN-003':     'A07',  # AutoAdminLogon = credentials stored in registry = auth failure
    'AST-WIN-004':     'A07',  # LSA protection disabled = authentication weakness
    'AST-REG-WIN-001': 'A07',  # LmCompatibilityLevel < 5 = auth failure
    'AST-REG-WIN-002': 'A07',  # NoLMHash not set = LM hashes stored
    'AST-REG-WIN-003': 'A01',  # RestrictAnonymous = 0 = broken access control
    'AST-REG-WIN-004': 'A07',  # Weak NTLM client security = auth failure
    'AST-REG-WIN-005': 'A07',  # Weak NTLM server security = auth failure
    'AST-REG-WIN-006': 'A05',  # UAC disabled = misconfiguration
    'AST-REG-WIN-007': 'A05',  # UAC admin prompt insecure = misconfiguration
    'AST-REG-WIN-008': 'A05',  # UAC secure desktop disabled = misconfiguration
    'AST-REG-WIN-011': 'A01',  # Everyone includes Anonymous = broken access control
    'AST-REG-WIN-012': 'A02',  # WDigest plaintext credentials in LSASS = cryptographic failure

    # =========================================================================
    # Windows Services / IIS / SQL / Exchange (WinServicesCheck.cs)
    # =========================================================================
    'AST-IIS-WIN-001':  'A05',  # WebDAV enabled = misconfiguration
    'AST-IIS-WIN-002':  'A07',  # Anonymous auth = authentication failure
    'AST-IIS-WIN-003':  'A05',  # Default welcome page = misconfiguration
    'AST-IIS-WIN-004':  'A02',  # HTTPS not configured = cryptographic failure
    'AST-IIS-WIN-005':  'A05',  # Directory browsing = misconfiguration
    'AST-SQL-WIN-001':  'A06',  # SQL Server outdated version = vulnerable component
    'AST-SQL-WIN-002':  'A07',  # SQL Mixed Mode auth = authentication failure
    'AST-SQL-WIN-003':  'A07',  # SA account enabled = authentication failure
    'AST-EXCH-WIN-001': 'A06',  # Exchange Server requires patches = vulnerable component
    'AST-SVC-WIN-001':  'A01',  # Service running as LocalSystem = broken access control
    'AST-SVC-WIN-003':  'A09',  # Critical services detected (informational) = logging/monitoring
    'AST-PRIV-WIN-001': 'A01',  # Service exe writable = broken access control
    'AST-PRIV-WIN-002': 'A05',  # Unquoted service path = misconfiguration
    'AST-PRIV-WIN-003': 'A01',  # DLL hijacking possible = broken access control

    # =========================================================================
    # Windows PrivEsc (PrivEscCheckWin.cs)
    # =========================================================================
    'AST-PRV-001':     'A01',  # Service executable writable = broken access control
    'AST-PRV-002':     'A05',  # Unquoted service path = misconfiguration (CWE-428)
    'AST-PRV-003':     'A05',  # AlwaysInstallElevated = misconfiguration
    'AST-PRV-004':     'A01',  # Scheduled task with writable exe = broken access control
    'AST-PRIV-WIN-004':'A01',  # Scheduled task writable exe = broken access control
    'AST-PRIV-WIN-005':'A05',  # AlwaysInstallElevated = misconfiguration
    'AST-PRIV-WIN-006':'A01',  # Weak ACLs on system dirs = broken access control
    'AST-PRIV-WIN-007':'A01',  # Writable PATH directories = broken access control
    'AST-PRIV-WIN-008':'A01',  # Writable AutoRun registry = broken access control
    'AST-PRIV-WIN-009':'A01',  # Writable startup folder = broken access control
    'AST-PRIV-WIN-010':'A01',  # SeImpersonatePrivilege (Potato attacks) = broken access control

    # =========================================================================
    # Linux Firewall (LinuxFirewallCheck.cs)
    # =========================================================================
    'AST-LNX-001':    'A05',  # UFW / iptables disabled = misconfiguration
    'AST-LNX-002':    'A05',  # Default INPUT policy ACCEPT = misconfiguration
    'AST-LNX-003':    'A05',  # Permissive iptables rules = misconfiguration
    'AST-FW-LNX-001': 'A05',
    'AST-FW-LNX-002': 'A05',
    'AST-FW-LNX-003': 'A05',
    'AST-FW-LNX-004': 'A05',

    # =========================================================================
    # NFS (SambaNfsCheck.cs)
    # =========================================================================
    'AST-NFS-001':     'A01',  # NFS no_root_squash = broken access control
    'AST-NFS-002':     'A01',  # NFS world-accessible (*(rw)) = broken access control
    'AST-NFS-003':     'A02',  # NFSv3 no auth/encryption = cryptographic failure
    'AST-NFS-LNX-001': 'A01',
    'AST-NFS-LNX-002': 'A01',

    # =========================================================================
    # SSH Config (SshConfigCheck.cs)
    # =========================================================================
    'AST-SSH-001':     'A07',  # PermitRootLogin yes = authentication failure
    'AST-SSH-002':     'A05',  # PasswordAuthentication yes (no MFA) = misconfiguration
    'AST-SSH-003':     'A02',  # Weak ciphers/MACs = cryptographic failure
    'AST-SSH-004':     'A07',  # PermitEmptyPasswords = authentication failure
    'AST-SSH-LNX-001': 'A07',
    'AST-SSH-LNX-002': 'A02',
    'AST-SSH-LNX-003': 'A05',
    'AST-SSH-LNX-004': 'A07',
    'AST-SSH-LNX-005': 'A05',  # X11Forwarding = misconfiguration

    # =========================================================================
    # Samba (SambaNfsCheck.cs)
    # =========================================================================
    'AST-SAMBA-LNX-001': 'A01',  # Guest share = broken access control
    'AST-SAMBA-LNX-002': 'A06',  # Samba SMBv1 = vulnerable component

    # =========================================================================
    # Linux PrivEsc (PrivEscCheckLinux.cs)
    # =========================================================================
    'AST-PRV-005':     'A01',  # SUID binaries (dangerous) = broken access control
    'AST-PRV-006':     'A01',  # SUID in writable dir = broken access control
    'AST-PRV-007':     'A05',  # Sudoers NOPASSWD = misconfiguration
    'AST-PRV-008':     'A01',  # World-readable /etc/shadow = broken access control
    'AST-PRIV-LNX-001':'A01',
    'AST-PRIV-LNX-002':'A01',
    'AST-PRIV-LNX-003':'A05',
    'AST-PRIV-LNX-004':'A01',
    'AST-PRIV-LNX-005':'A01',
    'AST-PRIV-LNX-006':'A05',  # Docker socket exposed = security misconfiguration
    'AST-PRIV-LNX-007':'A05',  # Writable systemd units = security misconfiguration
    'AST-PRIV-LNX-008':'A02',  # Exposed credential files = cryptographic/secrets failure

    # =========================================================================
    # =========================================================================
    # v0.2.0 TLS/SSL (TlsScanner.cs)
    # =========================================================================
    'AST-TLS-001': 'A02',  # Deprecated TLS protocol (TLS 1.0/1.1) = cryptographic failure
    'AST-TLS-002': 'A02',  # Weak cipher suite (RC4/3DES/NULL/EXPORT) = cryptographic failure
    'AST-TLS-003': 'A02',  # Self-signed or expired certificate = cryptographic failure
    'AST-TLS-004': 'A05',  # Certificate hostname mismatch = misconfiguration
    'AST-TLS-005': 'A02',  # No TLS on expected encrypted port = cryptographic failure

    # =========================================================================
    # v0.2.0 SYSVOL / GPP (SysvolCheck.cs)
    # =========================================================================
    'AST-SYSVOL-001': 'A02',  # GPP cpassword in Groups.xml = cryptographic failure (published key)
    'AST-SYSVOL-002': 'A02',  # GPP cpassword in other GPP file = cryptographic failure
    'AST-SYSVOL-003': 'A01',  # SYSVOL anonymous access = broken access control

    # v0.2.0 Aggressive AD checks (AST-FEATURE-004)
    # =========================================================================
    'AST-AD-010': 'A07',  # AS-REP roasting (aggressive)
    'AST-AD-011': 'A01',  # Unconstrained delegation
    'AST-AD-012': 'A01',  # Weak ACLs (GenericAll, WriteDacl)
    'AST-AD-013': 'A01',  # AdminCount analysis
    'AST-AD-014': 'A05',  # GPO weak permissions
    'AST-AD-015': 'A05',  # LAPS not deployed
    'AST-AD-016': 'A01',  # BloodHound data — excessive permissions

    # v0.2.0 Linux kernel/container PrivEsc (AST-FEATURE-004)
    'AST-PRV-009': 'A06',  # Kernel CVE (DirtyCow, PwnKit, etc.)
    'AST-PRV-010': 'A01',  # Docker socket accessible
    'AST-PRV-011': 'A05',  # Writable systemd units
    'AST-PRV-012': 'A01',  # Credential files accessible (.bash_history, .env)
}


def get_owasp(finding_id: str) -> dict:
    """
    Return OWASP Top 10 2021 mapping for a finding ID.

    Returns {'id': 'A05', 'name': 'Security Misconfiguration'} or None.
    """
    category_id = FINDING_TO_OWASP.get(finding_id)
    if category_id is None:
        return None
    return {
        'id':   category_id,
        'name': OWASP_CATEGORIES[category_id],
    }


def enrich_findings_with_owasp(findings: list) -> list:
    """
    Add 'owasp' field to each finding that has a known mapping.
    Modifies findings in-place and returns the list.
    """
    for finding in findings:
        fid = finding.get('id', '')
        mapping = get_owasp(fid)
        if mapping:
            finding['owasp'] = mapping
    return findings
