"""
Compliance Mapping for Asterion Network Security Auditor

Maps each AST-* finding code to CIS Controls v8, NIST CSF 2.0, and PCI-DSS 4.0 controls.
Applied automatically during AI enrichment alongside OWASP mapping.

References:
- CIS Controls v8: https://www.cisecurity.org/controls/v8
- NIST CSF 2.0:    https://www.nist.gov/cyberframework
- PCI-DSS 4.0:     https://www.pcisecuritystandards.org/
"""

# ---------------------------------------------------------------------------
# CIS Controls v8 — short names for the most referenced controls
# ---------------------------------------------------------------------------
CIS_CONTROLS = {
    'CIS-1':  'Inventory and Control of Enterprise Assets',
    'CIS-2':  'Inventory and Control of Software Assets',
    'CIS-3':  'Data Protection',
    'CIS-4':  'Secure Configuration of Enterprise Assets and Software',
    'CIS-5':  'Account Management',
    'CIS-6':  'Access Control Management',
    'CIS-7':  'Continuous Vulnerability Management',
    'CIS-8':  'Audit Log Management',
    'CIS-9':  'Email and Web Browser Protections',
    'CIS-10': 'Malware Defenses',
    'CIS-11': 'Data Recovery',
    'CIS-12': 'Network Infrastructure Management',
    'CIS-13': 'Network Monitoring and Defense',
    'CIS-14': 'Security Awareness and Skills Training',
    'CIS-15': 'Service Provider Management',
    'CIS-16': 'Application Software Security',
    'CIS-17': 'Incident Response Management',
    'CIS-18': 'Penetration Testing',
}

# ---------------------------------------------------------------------------
# NIST CSF 2.0 — subcategory IDs (function.category.subcategory)
# ---------------------------------------------------------------------------
NIST_CONTROLS = {
    'PR.AA-01': 'Identities and credentials for authorized users are managed',
    'PR.AA-02': 'Identities are proofed and bound to credentials based on context',
    'PR.AA-03': 'Users, services, and hardware are authenticated',
    'PR.AA-05': 'Access permissions and authorizations are managed',
    'PR.AA-06': 'Physical access to assets is managed',
    'PR.DS-01': 'The confidentiality, integrity, and availability of data-at-rest are protected',
    'PR.DS-02': 'The confidentiality, integrity, and availability of data-in-transit are protected',
    'PR.PS-01': 'Configuration management practices are established and applied',
    'PR.PS-02': 'Software is maintained, replaced, and removed commensurate with risk',
    'DE.CM-01': 'Networks and network services are monitored',
    'DE.CM-03': 'Personnel activity and technology usage are monitored',
    'ID.AM-01': 'Assets are inventoried',
    'ID.RA-01': 'Vulnerabilities in assets are identified, validated, and recorded',
    'RS.MI-02': 'Incidents are mitigated',
}

# ---------------------------------------------------------------------------
# PCI-DSS 4.0 — requirement numbers
# ---------------------------------------------------------------------------
PCI_REQUIREMENTS = {
    'PCI-1':  'Install and Maintain Network Security Controls',
    'PCI-2':  'Apply Secure Configurations to All System Components',
    'PCI-3':  'Protect Stored Account Data',
    'PCI-4':  'Protect Cardholder Data with Strong Cryptography During Transmission',
    'PCI-5':  'Protect All Systems and Networks from Malicious Software',
    'PCI-6':  'Develop and Maintain Secure Systems and Software',
    'PCI-7':  'Restrict Access to System Components and Cardholder Data by Business Need to Know',
    'PCI-8':  'Identify Users and Authenticate Access to System Components',
    'PCI-10': 'Log and Monitor All Access to System Components and Cardholder Data',
    'PCI-11': 'Test Security of Systems and Networks Regularly',
    'PCI-12': 'Support Information Security with Organizational Policies and Programs',
}

# ---------------------------------------------------------------------------
# Mapping: AST-* finding ID → (CIS control, NIST subcategory, PCI requirement)
# ---------------------------------------------------------------------------
FINDING_TO_COMPLIANCE = {

    # =========================================================================
    # SMB / CIFS
    # =========================================================================
    'AST-SMB-001': ('CIS-6',  'PR.AA-05', 'PCI-7'),   # Null session → access control
    'AST-SMB-002': ('CIS-4',  'PR.DS-02', 'PCI-2'),   # SMB signing → config / transit crypto
    'AST-SMB-003': ('CIS-7',  'PR.PS-02', 'PCI-6'),   # SMBv1 → vuln mgmt / patch
    'AST-SMB-005': ('CIS-6',  'PR.AA-05', 'PCI-7'),   # Writable share → access control

    # =========================================================================
    # RDP
    # =========================================================================
    'AST-RDP-001': ('CIS-4',  'PR.AA-03', 'PCI-8'),   # No NLA → auth / config
    'AST-RDP-002': ('CIS-3',  'PR.DS-02', 'PCI-4'),   # Weak encryption → data-in-transit
    'AST-RDP-003': ('CIS-7',  'PR.PS-02', 'PCI-6'),   # BlueKeep heuristic → vuln mgmt
    'AST-RDP-004': ('CIS-4',  'PR.PS-01', 'PCI-2'),   # Self-signed cert → config mgmt

    # =========================================================================
    # LDAP / Active Directory
    # =========================================================================
    'AST-LDAP-001': ('CIS-5',  'PR.AA-03', 'PCI-8'),  # Anonymous bind → auth mgmt
    'AST-LDAP-002': ('CIS-3',  'PR.DS-02', 'PCI-4'),  # Cleartext LDAP → transit crypto
    'AST-LDAP-003': ('CIS-4',  'PR.PS-01', 'PCI-2'),  # Domain trusts → security config
    'AST-AD-001':   ('CIS-4',  'PR.PS-01', 'PCI-2'),  # LDAP signing not required
    'AST-AD-002':   ('CIS-5',  'PR.AA-01', 'PCI-8'),  # Weak password policy
    'AST-AD-003':   ('CIS-3',  'PR.DS-02', 'PCI-4'),  # RC4/NTLMv1 Kerberos
    'AST-AD-004':   ('CIS-5',  'PR.AA-01', 'PCI-8'),  # Passwords never expire
    'AST-AD-005':   ('CIS-4',  'PR.AA-03', 'PCI-8'),  # Account lockout disabled
    'AST-AD-WIN-001': ('CIS-4', 'PR.PS-01', 'PCI-2'), # LDAP signing GPO
    'AST-AD-WIN-002': ('CIS-5', 'PR.AA-01', 'PCI-8'), # Weak password policy local
    'AST-AD-WIN-003': ('CIS-6', 'PR.AA-05', 'PCI-7'), # Insecure domain trusts

    # =========================================================================
    # Kerberos
    # =========================================================================
    'AST-KRB-001': ('CIS-5',  'PR.AA-03', 'PCI-8'),   # AS-REP roasting
    'AST-KRB-002': ('CIS-4',  'PR.PS-01', 'PCI-2'),   # Excessive ticket lifetime
    'AST-KRB-003': ('CIS-6',  'PR.AA-05', 'PCI-7'),   # Kerberoastable SPNs

    # =========================================================================
    # SNMP
    # =========================================================================
    'AST-SNMP-001': ('CIS-4',  'PR.AA-03', 'PCI-8'),  # Default community strings
    'AST-SNMP-002': ('CIS-6',  'PR.AA-05', 'PCI-7'),  # SNMP write access
    'AST-SNMP-003': ('CIS-3',  'PR.DS-02', 'PCI-4'),  # SNMPv1/v2c cleartext

    # =========================================================================
    # DNS / Network
    # =========================================================================
    'AST-DNS-001':  ('CIS-12', 'PR.PS-01', 'PCI-1'),  # Zone transfer
    'AST-DNS-003':  ('CIS-12', 'PR.PS-01', 'PCI-1'),  # mDNS
    'AST-NET-002':  ('CIS-12', 'DE.CM-01', 'PCI-1'),  # LLMNR/NetBIOS
    'AST-NET-003':  ('CIS-12', 'DE.CM-01', 'PCI-1'),  # mDNS responder
    'AST-NET-004':  ('CIS-4',  'PR.PS-01', 'PCI-2'),  # Dangerous service exposure

    # =========================================================================
    # FTP
    # =========================================================================
    'AST-FTP-001': ('CIS-5',  'PR.AA-03', 'PCI-8'),   # Anonymous FTP
    'AST-FTP-002': ('CIS-6',  'PR.AA-05', 'PCI-7'),   # Anonymous write access
    'AST-FTP-003': ('CIS-3',  'PR.DS-02', 'PCI-4'),   # Plaintext FTP

    # =========================================================================
    # Windows Firewall
    # =========================================================================
    'AST-FW-WIN-001': ('CIS-12', 'PR.PS-01', 'PCI-1'), # Firewall disabled
    'AST-FW-WIN-002': ('CIS-12', 'PR.PS-01', 'PCI-1'), # Permissive rules
    'AST-FW-WIN-003': ('CIS-8',  'DE.CM-01', 'PCI-10'),# Logging disabled
    'AST-FW-WIN-004': ('CIS-4',  'PR.PS-01', 'PCI-2'), # Default-allow profile

    # =========================================================================
    # Windows Registry
    # =========================================================================
    'AST-REG-WIN-001': ('CIS-4',  'PR.AA-03', 'PCI-8'), # LmCompatibilityLevel
    'AST-REG-WIN-002': ('CIS-3',  'PR.DS-01', 'PCI-3'), # LM hashes stored
    'AST-REG-WIN-003': ('CIS-6',  'PR.AA-05', 'PCI-7'), # RestrictAnonymous = 0
    'AST-REG-WIN-004': ('CIS-4',  'PR.AA-03', 'PCI-8'), # Weak NTLM client
    'AST-REG-WIN-005': ('CIS-4',  'PR.AA-03', 'PCI-8'), # Weak NTLM server
    'AST-REG-WIN-006': ('CIS-4',  'PR.PS-01', 'PCI-2'), # UAC disabled
    'AST-REG-WIN-007': ('CIS-4',  'PR.PS-01', 'PCI-2'), # UAC admin prompt
    'AST-REG-WIN-008': ('CIS-4',  'PR.PS-01', 'PCI-2'), # UAC secure desktop
    'AST-REG-WIN-011': ('CIS-6',  'PR.AA-05', 'PCI-7'), # Everyone=Anonymous
    'AST-REG-WIN-012': ('CIS-3',  'PR.DS-01', 'PCI-3'), # WDigest plaintext

    # =========================================================================
    # Windows Services / IIS / SQL / Exchange
    # =========================================================================
    'AST-IIS-WIN-001': ('CIS-4',  'PR.PS-01', 'PCI-2'),  # WebDAV enabled
    'AST-IIS-WIN-002': ('CIS-5',  'PR.AA-03', 'PCI-8'),  # Anonymous IIS auth
    'AST-IIS-WIN-003': ('CIS-4',  'PR.PS-01', 'PCI-2'),  # Default welcome page
    'AST-IIS-WIN-004': ('CIS-3',  'PR.DS-02', 'PCI-4'),  # No HTTPS
    'AST-IIS-WIN-005': ('CIS-4',  'PR.PS-01', 'PCI-2'),  # Directory browsing
    'AST-SQL-WIN-001': ('CIS-7',  'PR.PS-02', 'PCI-6'),  # SQL Server outdated
    'AST-SQL-WIN-002': ('CIS-5',  'PR.AA-03', 'PCI-8'),  # SQL Mixed Mode auth
    'AST-SQL-WIN-003': ('CIS-5',  'PR.AA-01', 'PCI-8'),  # SA account enabled
    'AST-EXCH-WIN-001':('CIS-7',  'PR.PS-02', 'PCI-6'),  # Exchange patches
    'AST-SVC-WIN-001': ('CIS-6',  'PR.AA-05', 'PCI-7'),  # Service as LocalSystem
    'AST-SVC-WIN-003': ('CIS-8',  'DE.CM-03', 'PCI-10'), # Critical services info

    # =========================================================================
    # Windows PrivEsc
    # =========================================================================
    'AST-PRIV-WIN-001': ('CIS-6',  'PR.AA-05', 'PCI-7'), # Writable service exe
    'AST-PRIV-WIN-002': ('CIS-4',  'PR.PS-01', 'PCI-2'), # Unquoted service path
    'AST-PRIV-WIN-003': ('CIS-6',  'PR.AA-05', 'PCI-7'), # DLL hijacking
    'AST-PRIV-WIN-004': ('CIS-6',  'PR.AA-05', 'PCI-7'), # Scheduled task writable
    'AST-PRIV-WIN-005': ('CIS-4',  'PR.PS-01', 'PCI-2'), # AlwaysInstallElevated
    'AST-PRIV-WIN-006': ('CIS-6',  'PR.AA-05', 'PCI-7'), # Weak ACLs system dirs
    'AST-PRIV-WIN-007': ('CIS-6',  'PR.AA-05', 'PCI-7'), # Writable PATH dirs
    'AST-PRIV-WIN-008': ('CIS-6',  'PR.AA-05', 'PCI-7'), # Writable AutoRun reg
    'AST-PRIV-WIN-009': ('CIS-6',  'PR.AA-05', 'PCI-7'), # Writable startup folder
    'AST-PRIV-WIN-010': ('CIS-6',  'PR.AA-05', 'PCI-7'), # SeImpersonatePrivilege

    # =========================================================================
    # Linux Firewall
    # =========================================================================
    'AST-FW-LNX-001': ('CIS-12', 'PR.PS-01', 'PCI-1'),  # iptables/UFW disabled
    'AST-FW-LNX-002': ('CIS-12', 'PR.PS-01', 'PCI-1'),  # Default INPUT ACCEPT
    'AST-FW-LNX-003': ('CIS-12', 'PR.PS-01', 'PCI-1'),  # Permissive rules
    'AST-FW-LNX-004': ('CIS-12', 'PR.PS-01', 'PCI-1'),  # IPv6 unfiltered

    # =========================================================================
    # NFS
    # =========================================================================
    'AST-NFS-LNX-001': ('CIS-6',  'PR.AA-05', 'PCI-7'), # no_root_squash
    'AST-NFS-LNX-002': ('CIS-6',  'PR.AA-05', 'PCI-7'), # World-accessible NFS

    # =========================================================================
    # SSH Config
    # =========================================================================
    'AST-SSH-LNX-001': ('CIS-5',  'PR.AA-03', 'PCI-8'), # PermitRootLogin
    'AST-SSH-LNX-002': ('CIS-3',  'PR.DS-02', 'PCI-4'), # Weak ciphers
    'AST-SSH-LNX-003': ('CIS-4',  'PR.PS-01', 'PCI-2'), # PasswordAuthentication
    'AST-SSH-LNX-004': ('CIS-5',  'PR.AA-03', 'PCI-8'), # PermitEmptyPasswords
    'AST-SSH-LNX-005': ('CIS-4',  'PR.PS-01', 'PCI-2'), # X11Forwarding

    # =========================================================================
    # Samba
    # =========================================================================
    'AST-SAMBA-LNX-001': ('CIS-6',  'PR.AA-05', 'PCI-7'), # Samba guest share
    'AST-SAMBA-LNX-002': ('CIS-7',  'PR.PS-02', 'PCI-6'), # Samba SMBv1

    # =========================================================================
    # Linux PrivEsc
    # =========================================================================
    'AST-PRIV-LNX-001': ('CIS-6',  'PR.AA-05', 'PCI-7'), # SUID dangerous binary
    'AST-PRIV-LNX-003': ('CIS-4',  'PR.PS-01', 'PCI-2'), # sudo NOPASSWD
    'AST-PRIV-LNX-004': ('CIS-3',  'PR.DS-01', 'PCI-3'), # World-readable shadow
    'AST-PRIV-LNX-005': ('CIS-6',  'PR.AA-05', 'PCI-7'), # SUID in writable dir
    'AST-PRIV-LNX-006': ('CIS-4',  'PR.PS-01', 'PCI-2'), # Docker socket → insecure config
    'AST-PRIV-LNX-007': ('CIS-4',  'PR.PS-01', 'PCI-2'), # Writable systemd units
    'AST-PRIV-LNX-008': ('CIS-3',  'PR.DS-01', 'PCI-3'), # Exposed credential files

    # =========================================================================
    # v0.2.0 TLS/SSL (TlsScanner.cs)
    # =========================================================================
    'AST-TLS-001': ('CIS-3',  'PR.DS-02', 'PCI-4'),  # Deprecated TLS protocol
    'AST-TLS-002': ('CIS-3',  'PR.DS-02', 'PCI-4'),  # Weak cipher suite
    'AST-TLS-003': ('CIS-3',  'PR.DS-02', 'PCI-4'),  # Self-signed/expired cert
    'AST-TLS-004': ('CIS-4',  'PR.PS-01', 'PCI-2'),  # Certificate hostname mismatch
    'AST-TLS-005': ('CIS-3',  'PR.DS-02', 'PCI-4'),  # No TLS on encrypted port

    # =========================================================================
    # v0.2.0 SYSVOL / GPP (MS14-025)
    # =========================================================================
    'AST-SYSVOL-001': ('CIS-3',  'PR.DS-01', 'PCI-3'),  # GPP cpassword Groups.xml
    'AST-SYSVOL-002': ('CIS-3',  'PR.DS-01', 'PCI-3'),  # GPP cpassword other GPP
    'AST-SYSVOL-003': ('CIS-6',  'PR.AA-05', 'PCI-7'),  # SYSVOL anonymous access

    # =========================================================================
    # v0.2.0 Aggressive AD checks
    # =========================================================================
    'AST-AD-010': ('CIS-5',  'PR.AA-03', 'PCI-8'),  # AS-REP roasting
    'AST-AD-011': ('CIS-6',  'PR.AA-05', 'PCI-7'),  # Unconstrained delegation
    'AST-AD-012': ('CIS-6',  'PR.AA-05', 'PCI-7'),  # Weak ACLs
    'AST-AD-013': ('CIS-5',  'PR.AA-01', 'PCI-8'),  # AdminCount
    'AST-AD-014': ('CIS-4',  'PR.PS-01', 'PCI-2'),  # GPO weak perms
    'AST-AD-015': ('CIS-4',  'PR.PS-01', 'PCI-2'),  # LAPS not deployed
    'AST-AD-016': ('CIS-6',  'PR.AA-05', 'PCI-7'),  # BloodHound excess perms

    # =========================================================================
    # v0.2.0 Linux kernel/container PrivEsc
    # =========================================================================
    'AST-PRV-009': ('CIS-7',  'ID.RA-01', 'PCI-6'), # Kernel CVE
    'AST-PRV-010': ('CIS-6',  'PR.AA-05', 'PCI-7'), # Docker socket
    'AST-PRV-011': ('CIS-4',  'PR.PS-01', 'PCI-2'), # Writable systemd units
    'AST-PRV-012': ('CIS-3',  'PR.DS-01', 'PCI-3'), # Credential files exposed
}


def get_compliance(finding_id: str) -> dict:
    """
    Return CIS Controls v8, NIST CSF 2.0, and PCI-DSS 4.0 mapping for a finding ID.

    Returns:
        {
            'cis':  {'id': 'CIS-4', 'name': 'Secure Configuration...'},
            'nist': {'id': 'PR.PS-01', 'name': 'Configuration management...'},
            'pci':  {'id': 'PCI-2', 'name': 'Apply Secure Configurations...'},
        }
        or None if no mapping exists.
    """
    mapping = FINDING_TO_COMPLIANCE.get(finding_id)
    if mapping is None:
        return None

    cis_id, nist_id, pci_id = mapping
    return {
        'cis':  {'id': cis_id,  'name': CIS_CONTROLS.get(cis_id, cis_id)},
        'nist': {'id': nist_id, 'name': NIST_CONTROLS.get(nist_id, nist_id)},
        'pci':  {'id': pci_id,  'name': PCI_REQUIREMENTS.get(pci_id, pci_id)},
    }


def enrich_findings_with_compliance(findings: list) -> list:
    """
    Add 'compliance' field to each finding that has a known mapping.
    Modifies findings in-place and returns the list.
    """
    for finding in findings:
        fid = finding.get('id', '')
        mapping = get_compliance(fid)
        if mapping:
            finding['compliance'] = mapping
    return findings
