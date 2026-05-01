"""
CVE Lookup Module for Asterion Network Security Auditor — v0.2.0
Pure API-based CVE enrichment: NVD API v2 + CIRCL Fallback.

Strategy (in order):
  1. NVD keyword search  — when no version string is detected in evidence.
                           Maps each AST-* finding code to precise search terms
                           so NVD returns the CVEs that correspond to that
                           misconfiguration (SMBv1 → EternalBlue family, etc.)
  2. NVD CPE lookup      — when software + version IS detected in evidence
                           (FTP banner "vsFTPd 3.0.5", SSH "OpenSSH_8.9p1", etc.)
  3. CIRCL fallback      — when NVD times out or has no CPE mapping (CPE path only)

No hardcoded CVE data. All CVE records come from live API responses.

Rate limits (NVD):
  Without key:  5 req / 30 s  → sleep 7 s between calls
  With key:    50 req / 30 s  → sleep 0.6 s between calls

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# ─── NVD / CIRCL endpoints ───────────────────────────────────────────────────
NVD_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_BASE = "https://cve.circl.lu/api"

# ─── CPE vendor/product map — network services (Asterion domain) ─────────────
# Format: normalized_key → (nvd_vendor, nvd_product)
CPE_MAP: Dict[str, Tuple[str, str]] = {
    # Remote access / file transfer
    "openssh":          ("openbsd",           "openssh"),
    "ssh":              ("openbsd",           "openssh"),
    "vsftpd":           ("vsftpd_project",    "vsftpd"),
    "proftpd":          ("proftpd",           "proftpd"),
    "pureftpd":         ("pureftpd",          "pure-ftpd"),
    "filezilla":        ("filezilla-project", "filezilla_server"),

    # File sharing / directory
    "samba":            ("samba",             "samba"),
    "smb":              ("samba",             "samba"),       # Linux Samba
    "nfs":              ("linux",             "nfs_utils"),
    "rpcbind":          ("sun",               "rpc"),

    # Directory / authentication
    "openldap":         ("openldap",          "openldap"),
    "ldap":             ("openldap",          "openldap"),
    "kerberos":         ("mit",               "kerberos_5"),
    "krb5":             ("mit",               "kerberos_5"),
    "heimdal":          ("heimdal_project",   "heimdal"),

    # Windows-specific
    "windows":          ("microsoft",         "windows"),
    "iis":              ("microsoft",         "internet_information_services"),
    "rdp":              ("microsoft",         "remote_desktop_protocol"),
    "winrm":            ("microsoft",         "windows_remote_management"),
    "mssql":            ("microsoft",         "sql_server"),
    "sqlserver":        ("microsoft",         "sql_server"),
    "activedirectory":  ("microsoft",         "active_directory"),
    "ad":               ("microsoft",         "active_directory"),

    # Network services
    "bind":             ("isc",              "bind"),
    "bind9":            ("isc",              "bind"),
    "namedns":          ("isc",              "bind"),
    "dnsmasq":          ("thekelleys",       "dnsmasq"),
    "unbound":          ("nlnet_labs",       "unbound"),
    "snmp":             ("net-snmp",         "net-snmp"),
    "netsnmp":          ("net-snmp",         "net-snmp"),
    "avahi":            ("avahi",            "avahi"),
    "mdns":             ("avahi",            "avahi"),

    # Crypto / TLS
    "openssl":          ("openssl",          "openssl"),

    # Web (Windows IIS / embedded)
    "apache":           ("apache",           "http_server"),
    "nginx":            ("f5",               "nginx"),

    # Database
    "mysql":            ("oracle",           "mysql"),
    "postgresql":       ("postgresql",       "postgresql"),
    "redis":            ("redis",            "redis"),

    # Linux system
    "linux":            ("linux",            "linux_kernel"),
    "kernel":           ("linux",            "linux_kernel"),
    "sudo":             ("sudo_project",     "sudo"),
    "iptables":         ("linux",            "iptables"),
    "nftables":         ("linux",            "nftables"),

    # Network devices (appear in SNMP sysDescr)
    "cisco":            ("cisco",            "ios"),
    "ciscoios":         ("cisco",            "ios"),
    "ciscoasa":         ("cisco",            "adaptive_security_appliance_software"),
    "juniper":          ("juniper",          "junos"),
    "junos":            ("juniper",          "junos"),
    "fortigate":        ("fortinet",         "fortios"),
    "fortios":          ("fortinet",         "fortios"),
    "fortinet":         ("fortinet",         "fortios"),
    "paloalto":         ("paloaltonetworks", "pan-os"),
    "panos":            ("paloaltonetworks", "pan-os"),
    "mikrotik":         ("mikrotik",         "routeros"),
    "routeros":         ("mikrotik",         "routeros"),
    "aruba":            ("arubanetworks",    "arubaos"),
    "arubaos":          ("arubanetworks",    "arubaos"),
    "netscaler":        ("citrix",           "netscaler_gateway"),
    "bigip":            ("f5",               "big-ip"),
    "f5":               ("f5",               "big-ip"),
}

# ─── CWE names (offline, avoids extra API call) ───────────────────────────────
_CWE_NAMES: Dict[str, str] = {
    "CWE-20":  "Improper Input Validation",
    "CWE-22":  "Path Traversal",
    "CWE-77":  "Command Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-119": "Improper Restriction of Operations within Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-264": "Permissions, Privileges and Access Controls",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-310": "Cryptographic Issues",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-362": "Concurrent Execution Using Shared Resource (Race Condition)",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free",
    "CWE-428": "Unquoted Search Path or Element",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}

# ─── In-memory cache (thread-safe) ───────────────────────────────────────────
# Cache key: ("cpe", vendor, product, version) for CPE lookups
#            ("kw",  keyword_string, "")        for keyword lookups
_CACHE: Dict[Tuple[str, str, str, str], List[Dict]] = {}
_CACHE_LOCK = threading.Lock()


# =============================================================================
# FINDING → KEYWORD SEARCH TERMS
# Maps every AST-* finding code emitted by the scanner to precise NVD keyword
# search terms. Codes verified against actual C# scanner source files.
#
# Used when no software+version is detected in evidence (protocol-level
# misconfigs: SMBv1, LDAP anon bind, no NLA, etc.). NVD keywordSearch API
# returns relevant CVEs; top N by CVSS score are attached to the finding.
#
# Intentionally excluded (no meaningful CVE exists for these):
#   AST-NET-003    — open ports detected (informational scan result)
#   AST-NET-004    — dangerous service exposed (too generic; service-specific
#                    findings cover the actual vulnerability)
#   AST-SVC-WIN-003— critical services detected (informational)
#   AST-FW-WIN-*   — Windows firewall config state (no CVE for config state)
#   AST-FW-LNX-*   — Linux firewall config state (no CVE for config state)
# =============================================================================
FINDING_SEARCH_TERMS: Dict[str, str] = {
    # Key: every term in the string must appear in the NVD description simultaneously.
    # Informal names (EternalBlue, BlueKeep, ProxyLogon, AS-REP roasting…) are NOT
    # indexed by NVD — use formal CVE terminology only. Terms validated against live
    # NVD API v2 (keywordSearch) on 2026-03-21.
    #
    # Result counts shown are from live tests (no API key, 2026-03-21):

    # ── SMB / CIFS ────────────────────────────────────────────────────────────
    "AST-SMB-001": "SMB null session",                   # 4 results
    "AST-SMB-002": "SMB signing",                        # 11 results
    "AST-SMB-003": "SMB remote code execution",          # 39 results
    "AST-SMB-005": "Windows SMB Server",                 # 88 results

    # ── RDP ───────────────────────────────────────────────────────────────────
    "AST-RDP-001": "Remote Desktop authentication",      # 32 results
    "AST-RDP-002": "Remote Desktop encryption",          # 9 results
    "AST-RDP-003": "Remote Desktop Services remote code",# 29 results
    "AST-RDP-004": "Remote Desktop certificate",         # 15 results

    # ── LDAP ──────────────────────────────────────────────────────────────────
    "AST-LDAP-001": "LDAP anonymous",                    # 30 results
    "AST-LDAP-002": "LDAP cleartext",                    # 24 results
    "AST-LDAP-003": "Windows domain trust attack",        # 3 results — domain trust misconfiguration

    # ── Active Directory ──────────────────────────────────────────────────────
    "AST-AD-001":     "NTLM relay",                      # 17 results (LDAP signing → relay)
    "AST-AD-002":     "Active Directory password",       # 39 results
    "AST-AD-003":     "Windows Kerberos elevation",      # 20 results
    "AST-AD-004":     "Active Directory password",       # 39 results
    "AST-AD-005":     "account lockout",                 # 78 results
    "AST-AD-WIN-001": "NTLM relay",                      # 17 results (same vector as AD-001)
    "AST-AD-WIN-002": "Active Directory password",       # 39 results
    "AST-AD-WIN-003": "domain trust Windows",            # 6 results

    # ── Kerberos ─────────────────────────────────────────────────────────────
    "AST-KRB-001": "Windows Kerberos elevation",         # 20 results
    "AST-KRB-002": "Kerberos service ticket",            # 15 results
    "AST-KRB-003": "Kerberos SPN",                       # 9 results

    # ── SNMP ─────────────────────────────────────────────────────────────────
    "AST-SNMP-001": "SNMP community",                    # 124 results
    "AST-SNMP-002": "SNMP community string",             # 88 results (write community)
    "AST-SNMP-003": "SNMP community",                    # 124 results (cleartext SNMP)

    # ── DNS / Network ─────────────────────────────────────────────────────────
    "AST-DNS-001": "DNS zone transfer",                  # 5 results
    "AST-DNS-003": "mDNS",                               # 58 results
    "AST-NET-002": "LLMNR",                              # 6 results

    # ── FTP ───────────────────────────────────────────────────────────────────
    "AST-FTP-001": "anonymous FTP",                      # 25 results
    "AST-FTP-002": "FTP write access",                   # 10 results
    "AST-FTP-003": "FTP cleartext",                      # 15 results

    # ── Windows Registry ─────────────────────────────────────────────────────
    "AST-REG-WIN-001": "NTLMv1 authentication",          # 2 results
    "AST-REG-WIN-002": "NTLM Windows authentication",    # 27 results
    "AST-REG-WIN-003": "SMB null session",               # 4 results (RestrictAnonymous → null sessions)
    "AST-REG-WIN-004": "NTLM Windows authentication",    # 27 results
    "AST-REG-WIN-005": "NTLM Windows authentication",    # 27 results
    "AST-REG-WIN-006": "User Account Control bypass",    # 47 results
    "AST-REG-WIN-007": "User Account Control bypass",    # 47 results
    "AST-REG-WIN-008": "User Account Control bypass",    # 47 results
    "AST-REG-WIN-011": "Windows anonymous access",       # Everyone=Anonymous → anonymous access
    "AST-REG-WIN-012": "WDigest credential",             # WDigest plaintext credentials in LSASS

    # ── IIS ───────────────────────────────────────────────────────────────────
    "AST-IIS-WIN-001": "IIS WebDAV",                     # 5 results
    "AST-IIS-WIN-002": "IIS authentication",             # IIS auth bypass CVEs
    "AST-IIS-WIN-003": "IIS information disclosure",     # IIS banner/default page CVEs
    "AST-IIS-WIN-004": "IIS cleartext",                  # no HTTPS on IIS
    "AST-IIS-WIN-005": "IIS directory",                  # directory listing CVEs

    # ── SQL Server ────────────────────────────────────────────────────────────
    "AST-SQL-WIN-001": "Microsoft SQL Server remote code", # formal product name
    "AST-SQL-WIN-002": "SQL Server authentication",      # 47 results
    "AST-SQL-WIN-003": "SQL Server sa account",          # 10 results

    # ── Exchange ─────────────────────────────────────────────────────────────
    "AST-EXCH-WIN-001": "Exchange Server remote code",   # 82 results

    # ── Windows Services ─────────────────────────────────────────────────────
    "AST-SVC-WIN-001": "Windows service LocalSystem",    # 24 results

    # ── Windows Privilege Escalation ─────────────────────────────────────────
    "AST-PRIV-WIN-001": "Windows service elevation privilege",  # writable service binary
    "AST-PRIV-WIN-002": "unquoted service path",         # 319 results
    "AST-PRIV-WIN-003": "DLL hijacking",                 # 380 results
    "AST-PRIV-WIN-004": "Windows scheduled task",        # 9 results
    "AST-PRIV-WIN-005": "Windows Installer privilege",   # AlwaysInstallElevated (formal MS name)
    "AST-PRIV-WIN-006": "Windows ACL privilege",         # 18 results
    "AST-PRIV-WIN-007": "Windows PATH privilege",        # writable PATH binary hijack
    "AST-PRIV-WIN-008": "Windows autorun",               # 6 results
    "AST-PRIV-WIN-009": "Windows startup privilege",     # 21 results
    "AST-PRIV-WIN-010": "SeImpersonatePrivilege",        # 5 results

    # ── Linux SSH Config ──────────────────────────────────────────────────────
    "AST-SSH-LNX-001": "SSH root brute",                 # 2 results
    "AST-SSH-LNX-002": "OpenSSH CBC",                    # 1 result
    "AST-SSH-LNX-003": "SSH brute force",                # SSH password brute force CVEs
    "AST-SSH-LNX-004": "SSH empty password",             # 2 results
    "AST-SSH-LNX-005": "SSH X11 forwarding",             # 7 results

    # ── Linux NFS ─────────────────────────────────────────────────────────────
    "AST-NFS-LNX-001": "NFS no_root_squash",             # 2 results
    "AST-NFS-LNX-002": "NFS export",                     # 39 results

    # ── Linux Samba ───────────────────────────────────────────────────────────
    "AST-SAMBA-LNX-001": "Samba anonymous",              # 1 result
    "AST-SAMBA-LNX-002": "Samba remote code",            # 34 results

    # ── Linux Privilege Escalation ────────────────────────────────────────────
    "AST-PRIV-LNX-001": "SUID privilege escalation",     # 18 results
    "AST-PRIV-LNX-003": "sudo NOPASSWD",                 # 5 results
    "AST-PRIV-LNX-004": "world readable password",       # 19 results
    "AST-PRIV-LNX-005": "SUID privilege escalation",     # 18 results (both are SUID vectors)
    "AST-PRIV-LNX-006": "Docker privilege escalation",  # Docker socket escape to root
    "AST-PRIV-LNX-007": "systemd privilege escalation", # writable service unit files
    "AST-PRIV-LNX-008": "Linux credentials disclosure",  # exposed credential files

    # ── v0.2.0 TLS/SSL (TlsScanner.cs) ───────────────────────────────────────
    "AST-TLS-001": "TLS deprecated",                     # 6 results — deprecated TLS protocol
    "AST-TLS-002": "TLS weak cipher",                    # 14 results — RC4/3DES/NULL/EXPORT
    "AST-TLS-003": "TLS certificate",                    # 390 results — self-signed/expired cert
    "AST-TLS-004": "TLS certificate",                    # 390 results — hostname mismatch
    "AST-TLS-005": "cleartext protocol",                 # 44 results — no TLS on encrypted port

    # ── v0.2.0 SYSVOL / GPP (MS14-025 / CVE-2014-1812) ──────────────────────
    "AST-SYSVOL-001": "Group Policy Preferences password",  # 1 result — MS14-025 CVE-2014-1812
    "AST-SYSVOL-002": "Group Policy Preferences password",  # 1 result — same CVE
    "AST-SYSVOL-003": "SMB null session",                   # 4 results — anonymous SYSVOL access

    # ── v0.2.0 Aggressive AD (pending C# implementation) ─────────────────────
    "AST-AD-010": "Windows Kerberos elevation",          # preauthentication disabled
    "AST-AD-011": "Active Directory delegation",         # unconstrained delegation
    "AST-AD-012": "Active Directory ACL privilege",      # GenericAll / WriteDacl
    "AST-AD-013": "Active Directory privileged account", # adminCount analysis
    "AST-AD-014": "Active Directory Group Policy",       # GPO weak permissions
    "AST-AD-015": "Windows local administrator password",# LAPS not deployed
    "AST-AD-016": "Active Directory domain privilege",   # excessive permissions

    # ── v0.2.0 Linux Kernel / Container PrivEsc (pending C# implementation) ───
    "AST-PRV-009": "Linux kernel privilege escalation",  # DirtyCow / PwnKit family
    "AST-PRV-010": "Docker privilege escalation",        # Docker socket escape
    "AST-PRV-011": "systemd privilege escalation",       # writable unit files
    "AST-PRV-012": "Linux credential exposure",          # .bash_history / .env files
}


# =============================================================================
# VERSION EXTRACTION — parse software name + version from evidence strings
# =============================================================================

_VERSION_PATTERNS = [
    # FTP daemons
    r"(?:vsftpd|vsFTPd)\s+([\d\.]+)",
    r"(?:ProFTPD|proftpd)\s+([\d\.]+)",
    r"(?:FileZilla\s+Server)\s+([\d\.]+)",
    # SSH
    r"OpenSSH[_\s]+([\d\.]+\w*)",
    # Samba
    r"(?:Samba|samba)\s+([\d\.]+)",
    # Linux kernel — uname/SNMP sysDescr format: "Linux hostname 5.10.0-8-generic #1"
    # Matches version as the THIRD whitespace-separated token after "Linux"
    r"Linux\s+\S+\s+([\d]+\.[\d]+\.[\d\w\.\-]+)",
    # Linux kernel — direct: "Linux 5.10.0"
    r"Linux\s+([\d]+\.[\d]+\.[\d\w\.\-]+)",
    # net-snmp: "net-snmp/5.9.1"
    r"net-snmp/([\d\.]+)",
    # Cisco IOS: "Cisco IOS Software, Version 15.2(4)M3"
    r"[Cc]isco\s+IOS\s+[Ss]oftware[^,]*,\s+[Vv]ersion\s+([\d\.()A-Za-z]+)",
    r"[Cc]isco\s+(?:IOS|ASA|NX-OS)[^\d]*([\d]+\.[\d]+\.?[\d\w]*)",
    # Juniper JunOS: "Juniper Networks ... JUNOS 21.2R3"
    r"JUNOS\s+([\d]+\.[\d]+[A-Z0-9\-]*)",
    # FortiGate: "FortiGate-... v7.2.5"
    r"[Ff]orti(?:Gate|net|OS)[^\d]*([\d]+\.[\d]+\.[\d]+)",
    # Palo Alto: "PAN-OS 10.1.3"
    r"PAN-OS\s+([\d]+\.[\d]+\.[\d]+)",
    # Generic: "version X.Y.Z" or "Version X.Y.Z"
    r"[Vv]ersion\s+([\d]+\.[\d]+\.?[\d\w]*)",
    # Generic semver anywhere in string
    r"(?:v|ver|version)\s*([\d]+\.[\d]+\.?[\d]*)",
]

_SOFTWARE_HINTS = {
    # FTP daemons
    "vsftpd":            "vsftpd",
    "vsFTPd":            "vsftpd",
    "ProFTPD":           "proftpd",
    "proftpd":           "proftpd",
    "FileZilla":         "filezilla",
    # SSH
    "OpenSSH":           "openssh",
    # Samba / SMB
    "Samba":             "samba",
    "samba":             "samba",
    # SNMP / net-snmp
    "net-snmp":          "netsnmp",
    # Linux kernel (from SNMP sysDescr / uname)
    "Linux":             "linux",
    # Network devices (SNMP sysDescr common strings)
    "Cisco IOS":         "cisco",
    "Cisco NX-OS":       "cisco",
    "Cisco ASA":         "ciscoasa",
    "cisco":             "cisco",
    "JUNOS":             "juniper",
    "Juniper":           "juniper",
    "FortiGate":         "fortigate",
    "FortiOS":           "fortios",
    "Fortinet":          "fortinet",
    "PAN-OS":            "paloalto",
    "Palo Alto":         "paloalto",
    "RouterOS":          "mikrotik",
    "MikroTik":          "mikrotik",
    "ArubaOS":           "aruba",
    "Aruba":             "aruba",
    "BigIP":             "bigip",
    "BIG-IP":            "bigip",
    # Microsoft FTP (from IIS FTP banner)
    "Microsoft FTP":     "iis",
}


def extract_software_version(evidence_value: str) -> Optional[Tuple[str, str]]:
    """
    Try to extract (software_key, version_string) from an evidence value.
    Returns None if nothing can be extracted.

    Examples:
      "220 vsFTPd 3.0.5 ready"         → ("vsftpd", "3.0.5")
      "SSH-2.0-OpenSSH_8.9p1 Ubuntu"   → ("openssh", "8.9p1")
      "Samba 4.15.0-Debian"            → ("samba", "4.15.0")
      "Linux 5.4.0-135-generic #152"   → ("linux", "5.4.0")
    """
    if not evidence_value:
        return None

    for hint, software_key in _SOFTWARE_HINTS.items():
        if hint in evidence_value:
            for pattern in _VERSION_PATTERNS:
                m = re.search(pattern, evidence_value, re.IGNORECASE)
                if m:
                    version = m.group(1).strip()
                    return (software_key, version)
            return None

    return None


def get_software_for_finding(
    finding: Dict[str, Any]
) -> Optional[Tuple[str, str]]:
    """
    Given a finding dict, determine what software+version to look up in NVD.
    Checks evidence.value, evidence.context, and description.
    Returns (software_key, version) or None.
    """
    evidence = finding.get("evidence") or {}
    if isinstance(evidence, dict):
        for field in ("value", "context"):
            val = evidence.get(field, "") or ""
            result = extract_software_version(val)
            if result:
                return result

    desc = finding.get("description", "") or ""
    if desc:
        result = extract_software_version(desc)
        if result:
            return result

    return None


# =============================================================================
# NVD KEYWORD SEARCH (no version required)
# =============================================================================

def lookup_cves_by_keyword(
    keyword: str,
    max_results: int = 8,
    min_cvss: float = 0.0,
    api_key: Optional[str] = None,
    timeout: int = 15,
) -> List[Dict[str, Any]]:
    """
    Search NVD for CVEs using free-text keywords.
    Returns up to max_results entries sorted by CVSS score descending.
    Only returns CVEs with cvss_score >= min_cvss (default: all).

    Cache key: ("kw", keyword, str(min_cvss))
    """
    cache_key = ("kw", keyword, str(min_cvss))
    with _CACHE_LOCK:
        if cache_key in _CACHE:
            return _CACHE[cache_key][:max_results]

    results = _query_nvd_keyword(keyword, api_key, timeout)

    # Apply min CVSS filter
    if min_cvss > 0:
        results = [r for r in results if (r.get("cvss_score") or 0.0) >= min_cvss]

    # Sort by CVSS descending
    results.sort(key=lambda x: x.get("cvss_score") or 0.0, reverse=True)

    with _CACHE_LOCK:
        _CACHE[cache_key] = results

    logger.info(f"NVD keyword '{keyword}': {len(results)} CVEs found")
    return results[:max_results]


def _query_nvd_keyword(
    keyword: str,
    api_key: Optional[str],
    timeout: int,
) -> List[Dict[str, Any]]:
    """Query NVD API v2 using keywordSearch parameter."""
    params = {
        "keywordSearch":    keyword,
        "resultsPerPage":   50,   # take top 50, then filter by CVSS
    }
    headers = {"apiKey": api_key} if api_key else {}

    try:
        logger.debug(f"NVD keyword search: '{keyword}'")
        resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=timeout)

        if resp.status_code == 403:
            logger.warning("NVD rate limited — sleeping 30 s then retrying")
            time.sleep(30)
            resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=timeout)

        if resp.status_code in (404, 204):
            return []

        resp.raise_for_status()
        data  = resp.json()
        vulns = data.get("vulnerabilities", [])
        results = [r for r in (_parse_nvd(v) for v in vulns) if r]
        return results

    except requests.exceptions.Timeout:
        logger.warning(f"NVD keyword search timeout for '{keyword}'")
        return []

    except Exception as e:
        logger.debug(f"NVD keyword error: {e}")
        return []


# =============================================================================
# NVD CPE LOOKUP (version-based)
# =============================================================================

def lookup_cves(
    software: str,
    version: str,
    max_results: int = 8,
    api_key: Optional[str] = None,
    timeout: int = 12,
) -> List[Dict[str, Any]]:
    """
    Dynamic CVE lookup from NVD for a specific software+version.
    Falls back to CIRCL if NVD doesn't have a CPE mapping.
    """
    if not version or version.strip().lower() in ("unknown", "n/a", "-", ""):
        return []

    key = software.lower().replace("-", "").replace(" ", "").replace("_", "")
    cpe_entry = CPE_MAP.get(key)
    if not cpe_entry:
        logger.debug(f"No CPE mapping for '{software}' — trying CIRCL")
        return _circl_fallback(software, version, max_results, timeout)

    vendor, product = cpe_entry
    cache_key = ("cpe", vendor, product, version)

    with _CACHE_LOCK:
        if cache_key in _CACHE:
            return _CACHE[cache_key][:max_results]

    results = _query_nvd(vendor, product, version, api_key, timeout)

    with _CACHE_LOCK:
        _CACHE[cache_key] = results

    return results[:max_results]


def _query_nvd(
    vendor: str,
    product: str,
    version: str,
    api_key: Optional[str],
    timeout: int,
) -> List[Dict[str, Any]]:
    """Query NVD API v2 with CPE virtualMatchString."""
    cpe_string = f"cpe:2.3:a:{vendor}:{product}:{version}"
    params = {"virtualMatchString": cpe_string, "resultsPerPage": 2000}
    headers = {"apiKey": api_key} if api_key else {}

    try:
        logger.debug(f"NVD CPE query: {cpe_string}")
        resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=timeout)

        if resp.status_code == 403:
            logger.warning("NVD rate limited — sleeping 30 s then retrying")
            time.sleep(30)
            resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=timeout)

        if resp.status_code in (404, 204):
            return []

        resp.raise_for_status()
        data  = resp.json()
        vulns = data.get("vulnerabilities", [])
        results = [r for r in (_parse_nvd(v) for v in vulns) if r]
        results.sort(key=lambda x: x.get("cvss_score") or 0.0, reverse=True)
        logger.info(f"NVD: {len(results)} CVE(s) for {vendor}/{product} {version}")
        return results

    except requests.exceptions.Timeout:
        logger.warning(f"NVD timeout — trying CIRCL for {vendor}/{product}")
        return _circl_fallback(f"{vendor} {product}", version, 8, timeout)

    except Exception as e:
        logger.debug(f"NVD error: {e}")
        return []


def _parse_nvd(vuln: Dict) -> Optional[Dict[str, Any]]:
    """Parse one NVD vulnerability entry into our schema format."""
    try:
        cve     = vuln["cve"]
        cve_id  = cve["id"]
        desc_en = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
        )
        metrics       = cve.get("metrics", {})
        cvss_score    = None
        cvss_severity = None

        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                d = entries[0]["cvssData"]
                cvss_score    = d.get("baseScore")
                cvss_severity = d.get("baseSeverity")
                break

        if cvss_score is None:
            entries = metrics.get("cvssMetricV2", [])
            if entries:
                cvss_score    = entries[0]["cvssData"].get("baseScore")
                cvss_severity = entries[0].get("baseSeverity", "")

        cwe_ids = [
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("lang") == "en" and d.get("value", "").startswith("CWE-")
        ]
        cwe_id = cwe_ids[0] if cwe_ids else None

        record: Dict[str, Any] = {
            "cve_id":        cve_id,
            "title":         desc_en[:120] or cve_id,
            "description":   desc_en,
            "link":          f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cvss_score":    cvss_score,
            "cvss_severity": cvss_severity,
            "published":     cve.get("published", "")[:10],
        }
        if cwe_id:
            record["cwe_id"]   = cwe_id
            record["cwe_name"] = _CWE_NAMES.get(cwe_id, "")
        return record

    except Exception as e:
        logger.debug(f"CVE parse error: {e}")
        return None


def _circl_fallback(
    software: str,
    version: str,
    max_results: int,
    timeout: int,
) -> List[Dict[str, Any]]:
    """CIRCL CVE Search API fallback (for CPE lookups only)."""
    parts   = software.lower().replace("-", "_").split()
    vendor  = parts[0] if parts else software.lower()
    product = "_".join(parts) if parts else software.lower()
    url = f"{CIRCL_BASE}/search/{vendor}/{product}"

    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return []

        data  = resp.json()
        items = data if isinstance(data, list) else data.get("data", [])
        results = []

        for item in items:
            cve_id  = item.get("id", "")
            summary = item.get("summary", "")
            cvss    = item.get("cvss")
            cwe     = item.get("cwe", "")
            try:
                cvss_f = float(cvss) if cvss else None
            except (TypeError, ValueError):
                cvss_f = None

            rec: Dict[str, Any] = {
                "cve_id":        cve_id,
                "title":         summary[:120] or cve_id,
                "description":   summary,
                "link":          f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "cvss_score":    cvss_f,
                "cvss_severity": _score_to_severity(cvss_f),
                "published":     item.get("Published", "")[:10],
            }
            if isinstance(cwe, str) and cwe.startswith("CWE-"):
                rec["cwe_id"]   = cwe
                rec["cwe_name"] = _CWE_NAMES.get(cwe, "")
            results.append(rec)

        results.sort(key=lambda x: x.get("cvss_score") or 0.0, reverse=True)
        return results[:max_results]

    except Exception as e:
        logger.debug(f"CIRCL fallback error: {e}")
        return []


def _score_to_severity(score: Optional[float]) -> Optional[str]:
    if score is None: return None
    if score >= 9.0:  return "CRITICAL"
    if score >= 7.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    if score > 0:     return "LOW"
    return "NONE"


# =============================================================================
# MAIN ENRICHMENT FUNCTION
# =============================================================================

def enrich_finding_with_cves(
    finding: Dict[str, Any],
    software: Optional[str] = None,
    version: Optional[str] = None,
    max_results: int = 5,
    api_key: Optional[str] = None,
) -> None:
    """
    Enrich a finding dict in-place with CVE data from live APIs.

    Lookup order:
      1. NVD CPE lookup  — if software + version are available
                           (explicit args OR extracted from evidence string)
      2. NVD keyword search — if no version, uses FINDING_SEARCH_TERMS[finding_id]
                              to find relevant CVEs for this type of misconfiguration

    No hardcoded CVE data. All records come from NVD/CIRCL API responses.

    Sets:
      finding['vulnerabilities'] — list of CVE records (dedup'd, sorted by CVSS)
      finding['cve']             — list of CVE IDs
      finding['cvss']            — highest CVSS score
    """
    finding_id = finding.get("id", "")
    merged: List[Dict[str, Any]] = []
    seen_ids: set = set()

    # ── Step 1: try version-based CPE lookup ──────────────────────────────────
    sw, ver = software, version
    if not (sw and ver):
        extracted = get_software_for_finding(finding)
        if extracted:
            sw, ver = extracted

    if sw and ver:
        cpe_results = lookup_cves(sw, ver, max_results=max_results, api_key=api_key)
        for cve in cpe_results:
            cid = cve.get("cve_id", "")
            if cid and cid not in seen_ids:
                merged.append(cve)
                seen_ids.add(cid)

        if cpe_results:
            time.sleep(7 if not api_key else 0.6)

    # ── Step 2: keyword search when no version detected ───────────────────────
    if not merged and finding_id in FINDING_SEARCH_TERMS:
        keyword  = FINDING_SEARCH_TERMS[finding_id]
        kw_results = lookup_cves_by_keyword(
            keyword,
            max_results=max_results,
            min_cvss=0.0,
            api_key=api_key,
        )
        for cve in kw_results:
            cid = cve.get("cve_id", "")
            if cid and cid not in seen_ids:
                merged.append(cve)
                seen_ids.add(cid)

        if kw_results:
            time.sleep(7 if not api_key else 0.6)

    if not merged:
        return

    # Sort by CVSS descending
    merged.sort(key=lambda x: x.get("cvss_score") or 0.0, reverse=True)

    finding["vulnerabilities"] = merged
    finding["cve"] = [c["cve_id"] for c in merged if c.get("cve_id")]

    scores = [c["cvss_score"] for c in merged if c.get("cvss_score") is not None]
    if scores:
        finding["cvss"] = round(max(scores), 1)

    logger.debug(
        f"Enriched {finding_id}: {len(merged)} CVEs "
        f"(top CVSS: {finding.get('cvss', 'N/A')})"
    )


def enrich_findings(
    findings: List[Dict[str, Any]],
    api_key: Optional[str] = None,
    skip_dynamic_for: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Enrich all findings in a report with CVE data.
    All CVE data comes from live NVD/CIRCL API calls (keyword or CPE lookup).

    Args:
        findings:         list of finding dicts from the report
        api_key:          optional NVD API key (higher rate limit: 50 req/30s)
        skip_dynamic_for: list of finding IDs to skip NVD lookup entirely

    Returns the same list (modified in-place).
    """
    skip = set(skip_dynamic_for or [])
    for finding in findings:
        fid = finding.get("id", "")
        if fid in skip:
            continue
        enrich_finding_with_cves(finding, api_key=api_key)
    return findings


def clear_cache() -> None:
    """Clear in-memory CVE cache."""
    with _CACHE_LOCK:
        _CACHE.clear()
