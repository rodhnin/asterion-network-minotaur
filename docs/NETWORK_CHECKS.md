# Network Security Checks Catalog

> **Comprehensive Security Check Reference**: Asterion v0.2.0 implements 130+ security checks across network protocols, Windows systems (local + WinRM remote), and Linux systems (local + SSH remote). This document catalogs every check with detection criteria, severity levels, and remediation guidance.

## Table of Contents

- [Overview](#overview)
- [Severity Levels](#severity-levels)
- [CrossPlatform Network Checks](#crossplatform-network-checks)
    - [SMB/CIFS Scanner](#smbcifs-scanner)
    - [RDP Scanner](#rdp-scanner)
    - [LDAP/Active Directory Scanner](#ldapactive-directory-scanner)
    - [Kerberos Scanner](#kerberos-scanner)
    - [DNS/LLMNR/mDNS Scanner](#dnsllmnrmdns-scanner)
    - [SNMP Scanner](#snmp-scanner)
    - [FTP Scanner](#ftp-scanner)
    - [Port Scanner](#port-scanner)
- [Windows Security Checks](#windows-security-checks)
    - [Windows Firewall](#windows-firewall)
    - [Windows Registry](#windows-registry)
    - [Active Directory Policy](#active-directory-policy)
    - [Windows Services](#windows-services)
    - [Windows Privilege Escalation](#windows-privilege-escalation)
- [Linux Security Checks](#linux-security-checks)
    - [Linux Firewall](#linux-firewall)
    - [SSH Configuration](#ssh-configuration)
    - [Samba/NFS Configuration](#sambanfs-configuration)
    - [Linux Privilege Escalation](#linux-privilege-escalation)
- [Statistics](#statistics)
- [Check Implementation](#check-implementation)

---

## Overview

**Total Security Checks:** 130+ (v0.2.0)
**Code Location:** `src/Asterion/Checks/`
**Categories:**

- **CrossPlatform Network:** 35+ checks (10 scanners — added TLS, SYSVOL)
- **Windows:** 50+ checks (7 check classes — WinRM remote checks + IIS/SQL/Exchange)
- **Linux:** 35+ checks (4 check classes — 3 new aggressive SSH checks)
- **Attack Chains:** 8 correlation rules (`AST-CHAIN-001..008`)

**Usage:**

```bash
# Run all checks in safe mode
ast scan --target 192.168.1.0/24 --mode safe

# Run all checks in aggressive mode (requires consent)
ast scan --target 192.168.1.0/24 --mode aggressive
```

---

## Severity Levels

| Severity     | Description                                             | Count | Examples                                                         |
| ------------ | ------------------------------------------------------- | ----- | ---------------------------------------------------------------- |
| **CRITICAL** | Immediate exploitation risk, system compromise imminent | 13    | BlueKeep, NFS no_root_squash, AlwaysInstallElevated, SUID shells |
| **HIGH**     | Significant security weakness, likely attack vector     | 44    | SMBv1, anonymous LDAP, AS-REP roasting, root SSH login           |
| **MEDIUM**   | Moderate security concern, defense-in-depth issue       | 29    | Weak password policy, LDAPS disabled, legacy SSH ciphers         |
| **LOW**      | Minor security improvement, hardening recommendation    | 7     | X11 forwarding, long Kerberos ticket lifetime, SNMP unencrypted  |
| **INFO**     | Informational finding, no direct vulnerability          | 6     | Open ports, services detected, AD trusts                         |

---

## CrossPlatform Network Checks

### SMB/CIFS Scanner

**Code:** `src/Asterion/Checks/CrossPlatform/SmbScanner.cs` (42KB, 1,234 lines)
**Protocol:** Server Message Block (SMB/CIFS)
**Ports:** 445 (SMB), 139 (NetBIOS)

| Check ID        | Title                                              | Severity | Confidence | Detection Criteria                             |
| --------------- | -------------------------------------------------- | -------- | ---------- | ---------------------------------------------- |
| **AST-SMB-001** | SMB accessible via anonymous bind/guest account    | CRITICAL | HIGH       | Null session or guest account login successful |
| **AST-SMB-002** | SMB signing not required                           | HIGH     | MEDIUM     | Anonymous session could enumerate shares       |
| **AST-SMB-003** | SMBv1 protocol enabled (EternalBlue vector)        | HIGH     | HIGH       | SMBv1 connection successful                    |
| **AST-SMB-005** | Sensitive shares accessible via NTLM pass-the-hash | HIGH     | HIGH       | NTLM auth successful to ADMIN$, SYSVOL, etc.   |

#### AST-SMB-001: Anonymous SMB Access

**Description:**
SMB server allows anonymous (null session) or guest account authentication, enabling attackers to enumerate:

- Shares, files, and directories
- User accounts and groups
- Security policies
- System information

**Detection:**

```csharp
// 1. Attempt null session
SMBLibrary.Client.ISMBClient client = new SMB2Client();
client.Connect(target, SMBTransportType.DirectTCPTransport);
NTStatus status = client.Login("", "");  // Empty credentials

// 2. Attempt guest login
status = client.Login("Guest", "");
```

**Remediation:**

```powershell
# Disable Guest account
net user Guest /active:no

# Registry: Restrict anonymous enumeration
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictAnonymous /t REG_DWORD /d 2

# GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
# "Network access: Do not allow anonymous enumeration of SAM accounts and shares" = Enabled
```

**References:**

- MS Security Guide
- CIS Windows Server Benchmark 2.3.10.x

---

#### AST-SMB-002: SMB Signing Not Required

**Description:**
SMB server does not enforce message signing, allowing man-in-the-middle (MITM) attacks including:

- SMB relay attacks
- Session hijacking
- Credential interception

**Detection:**

```csharp
// Check SMB2 negotiate response
SMB2NegotiateResponse negotiateResponse = client.Negotiate(...);
bool signingRequired = negotiateResponse.SecurityMode.HasFlag(SecurityMode.SigningRequired);
```

**Remediation:**

```powershell
# Local Computer Policy
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1

# GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# "Microsoft network server: Digitally sign communications (always)" = Enabled
# "Microsoft network client: Digitally sign communications (always)" = Enabled

# Reboot required
shutdown /r /t 60
```

**Impact:**

- Disables SMB relay attacks (Responder, ntlmrelayx)
- May impact performance on high-throughput SMB workloads (test in production)

**References:**

- CVE-2019-1040 (Drop the MIC)
- Petitpotam, PXE boot MITM

---

#### AST-SMB-003: SMBv1 Enabled (EternalBlue)

**Description:**
SMBv1 is an obsolete protocol with critical vulnerabilities:

- **MS17-010 (EternalBlue):** Remote code execution exploited by WannaCry, NotPetya
- **CVE-2017-0143 through CVE-2017-0148**
- **CVE-2017-7494:** Samba "SambaCry"

**Detection:**

```csharp
// Attempt SMB1 connection
SMB1Client smb1Client = new SMB1Client();
bool smb1Available = smb1Client.Connect(target, SMBTransportType.DirectTCPTransport);
```

**Remediation:**

```powershell
# Windows: Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Or via DISM (no reboot)
dism /online /disable-feature /featurename:SMB1Protocol /norestart

# Verify disabled
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Samba (Linux): /etc/samba/smb.conf
[global]
server min protocol = SMB2
# systemctl restart smbd nmbd
```

**Critical:**

- **URGENT** - Disable immediately, even if "testing" or "legacy compatibility needed"
- SMBv1 is **NOT SAFE** to keep enabled even temporarily
- Document legacy applications requiring SMBv1, prioritize replacement

**References:**

- [Microsoft: SMBv1 should not be installed or enabled](https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows)
- MS17-010, WannaCry, NotPetya, SambaCry

---

#### AST-SMB-005: NTLM Pass-the-Hash to Sensitive Shares

**Description:**
NTLM authentication (vs Kerberos) allows pass-the-hash attacks where stolen NTLM hashes (from mimikatz, secretsdump) can be used to authenticate without knowing the plaintext password.

**Sensitive Shares:**

- `\\server\ADMIN$` (C:\Windows)
- `\\server\C$` (full drive access)
- `\\DC\SYSVOL` (domain policies, scripts)
- `\\DC\NETLOGON` (logon scripts)

**Detection:**

```csharp
// Attempt NTLM authentication with provided hash
NTStatus status = client.Login(domain, username, password, AuthenticationMethod.NTLMv2);
// Check access to ADMIN$
```

**Remediation:**

```
IMMEDIATE:
1. Change compromised account password immediately
2. Assume compromise - investigate for malware/backdoors
3. Review Event ID 4624 (successful logon) for unauthorized access

LONG-TERM:
1. Implement Privileged Access Workstations (PAW) for admin accounts
2. Enable SMB signing (AST-SMB-002)
3. Disable NTLM where possible, use Kerberos only:
   - GPO: "Network security: Restrict NTLM: Incoming NTLM traffic" = Deny all
   - Monitor Event ID 4776 (NTLM auth) before enforcing
4. Credential Guard (Windows 10/Server 2016+)
5. Use LAPS for local admin passwords
```

**References:**

- MITRE ATT&CK T1550.002 (Pass the Hash)
- [Microsoft Pass-the-Hash guidance](<https://download.microsoft.com/download/7/7/A/77ABC5BD-8320-41AF-863C-6ECFB10CB4B9/Mitigating%20Pass-the-Hash%20(PtH)%20Attacks%20and%20Other%20Credential%20Theft%20Techniques_English.pdf>)

---

### RDP Scanner

**Code:** `src/Asterion/Checks/CrossPlatform/RdpScanner.cs` (24KB, 687 lines)
**Protocol:** Remote Desktop Protocol (RDP)
**Port:** 3389 (TCP)

| Check ID        | Title                                            | Severity | Confidence | Detection Criteria                              |
| --------------- | ------------------------------------------------ | -------- | ---------- | ----------------------------------------------- |
| **AST-RDP-001** | RDP without Network Level Authentication         | HIGH     | HIGH       | X.224 response shows NLA not enforced           |
| **AST-RDP-002** | RDP using legacy security protocol (non-TLS)     | MEDIUM   | HIGH       | Standard RDP Security negotiated instead of TLS |
| **AST-RDP-003** | Potential BlueKeep vulnerability (CVE-2019-0708) | CRITICAL | MEDIUM     | Legacy RDP Security + no NLA detected           |
| **AST-RDP-004** | RDP using weak/self-signed certificate           | LOW      | MEDIUM     | Legacy protocol indicates default cert          |

#### AST-RDP-001: RDP Without Network Level Authentication

**Description:**
Network Level Authentication (NLA) requires authentication before establishing an RDP session. Without NLA:

- Attackers can enumerate usernames via login prompts
- RDP service is exposed to brute-force attacks at protocol level
- No pre-authentication barrier (vs. Kerberos pre-auth)

**Detection:**

```csharp
// Parse X.224 Connection Confirm response
// Check negotiationToken for supportedProtocols
bool nlaSupported = (supportedProtocols & ProtocolFlags.HYBRID) == ProtocolFlags.HYBRID;
```

**Remediation:**

```powershell
# Via System Properties
# Right-click "This PC" > Properties > Remote settings
# Check "Allow connections only from computers running Remote Desktop with Network Level Authentication"

# Via GPO
# Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security
# "Require user authentication for remote connections by using Network Level Authentication" = Enabled

# Via Registry
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1

# Verify
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication
```

**References:**

- MS-RDPBCGR: Remote Desktop Protocol Basic Connectivity and Graphics Remoting Specification
- CIS Windows Server Benchmark 18.9.60.x

---

#### AST-RDP-003: BlueKeep Vulnerability (CVE-2019-0708)

**Description:**
**CRITICAL** pre-authentication remote code execution vulnerability in RDP:

- Affects Windows 7, Server 2008 R2, Server 2008, XP, Vista
- Wormable (no user interaction required)
- Allows SYSTEM-level code execution
- Exploited in-the-wild by BlueKeep exploit kit, DejaBlue

**Detection:**

```csharp
// Heuristic (not definitive, requires patch-level check):
if (legacy RDP Security negotiated AND NLA not enforced)
{
    // Likely vulnerable, recommend immediate patching
}
```

**Remediation:**

```powershell
# URGENT - Apply patches immediately
# Windows 7 SP1 / Server 2008 R2: KB4499175
# Windows Server 2008: KB4499180
# Windows XP / Vista: Out-of-support, Microsoft released emergency patches

# Via Windows Update
wuauclt /detectnow /updatenow

# Or download from Microsoft Update Catalog

# WORKAROUND (if patching delayed):
# 1. Enable NLA (AST-RDP-001)
# 2. Restrict RDP access via firewall to known IP ranges
# 3. Disable RDP if not needed:
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1

# BEST: Upgrade to Windows 10/11, Server 2016/2019/2022
```

**CRITICAL NOTES:**

- **Wormable:** Can spread automatically like WannaCry
- **Pre-authentication:** No credentials needed to exploit
- **SYSTEM execution:** Full control of target system
- **Do not delay patching**

**References:**

- CVE-2019-0708
- [Microsoft BlueKeep Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708)
- MITRE ATT&CK T1210 (Exploitation of Remote Services)

---

### LDAP/Active Directory Scanner

**Code:** `src/Asterion/Checks/CrossPlatform/LdapScanner.cs` (38KB, 1,089 lines)
**Protocol:** Lightweight Directory Access Protocol (LDAP)
**Ports:** 389 (LDAP), 636 (LDAPS), 3268/3269 (Global Catalog)

| Check ID         | Title                                                  | Severity | Confidence |
| ---------------- | ------------------------------------------------------ | -------- | ---------- |
| **AST-LDAP-001** | LDAP anonymous bind allowed with query capability      | HIGH     | HIGH       |
| **AST-AD-001**   | LDAP signing not required by Domain Controller         | HIGH     | HIGH       |
| **AST-LDAP-002** | LDAPS (LDAP over SSL) not available                    | MEDIUM   | HIGH       |
| **AST-AD-002**   | Weak domain password policy                            | MEDIUM   | HIGH       |
| **AST-AD-003**   | NTLMv1/LM authentication allowed                       | HIGH     | HIGH       |
| **AST-AD-004**   | Accounts with password never expires flag              | MEDIUM   | HIGH       |
| **AST-AD-005**   | Account lockout policy disabled (lockoutThreshold = 0) | MEDIUM   | HIGH       |

#### AST-LDAP-001: Anonymous LDAP Bind

**Description:**
LDAP server allows anonymous (unauthenticated) bind with query capability, exposing:

- Domain user accounts (username enumeration)
- Group memberships
- Computer accounts
- Domain policies (password policy, Kerberos settings)
- Service Principal Names (SPNs) for Kerberoasting

**Detection:**

```csharp
// Attempt anonymous bind
LdapConnection conn = new LdapConnection(target);
conn.AuthType = AuthType.Anonymous;
conn.Bind();

// Query domain
SearchRequest request = new SearchRequest("DC=domain,DC=com", "(objectClass=*)", SearchScope.Subtree);
SearchResponse response = (SearchResponse)conn.SendRequest(request);
```

**Remediation:**

```powershell
# GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
# "Network access: Do not allow anonymous enumeration of SAM accounts and shares" = Enabled

# Registry: Restrict anonymous LDAP
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictAnonymous /t REG_DWORD /d 1
# Level 1: Default anonymous enumeration disabled
# Level 2: No access without explicit anonymous permissions

# Restart netlogon service
net stop netlogon && net start netlogon

# Verify
# Attempt anonymous bind from non-domain machine, should fail
ldp.exe -> Connection > Connect > Bind as: Currently logged on user (should fail)
```

**Impact:**

- Prevents BloodHound/SharpHound enumeration without credentials
- Stops pre-authentication reconnaissance
- Forces attackers to obtain valid credentials first

**References:**

- CVE-2017-8563 (LDAP NULL session information disclosure)
- CIS Windows Server Benchmark 2.3.11.x

---

#### AST-AD-001: LDAP Signing Not Required

**Description:**
Domain Controller does not enforce LDAP signing, allowing man-in-the-middle (MITM) attacks:

- LDAP relay attacks (similar to SMB relay)
- Credential interception
- Domain policy modification via unsigned LDAP messages

**Detection:**

```csharp
// Attempt unsigned LDAP bind
LdapConnection conn = new LdapConnection(dc);
conn.SessionOptions.Signing = false;
conn.Bind(NetworkCredential);  // Should fail if signing required
```

**Remediation:**

```powershell
# GPO: Default Domain Controllers Policy
# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# "Domain controller: LDAP server signing requirements" = Require signing

# Registry (on each DC)
reg add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /v LDAPServerIntegrity /t REG_DWORD /d 2
# 0 = None (insecure)
# 1 = Negotiate signing (default, still allows unsigned)
# 2 = Require signing (secure)

# Reboot DCs in maintenance window
shutdown /r /t 300 /c "Applying LDAP signing policy - reboot in 5 minutes"

# Verify
# Monitor Event ID 2886 on DCs before enforcing (shows unsigned LDAP clients)
# Event Viewer > Applications and Services Logs > Directory Service
```

**Impact:**

- **Client compatibility:** Ensure all LDAP clients support signing (Windows 2000+, modern Linux)
- **Application testing:** Test LOB applications using LDAP before enforcing
- **Monitor first:** Set to "Negotiate signing" + audit for 30 days, then enforce

**References:**

- [Microsoft LDAP Signing Guidance](https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a)
- ADV190023

---

#### AST-AD-002: Weak Domain Password Policy

**Description:**
Domain password policy does not meet security best practices:

- **minPwdLength < 8:** Short passwords vulnerable to brute-force
- **Complexity disabled:** Allows simple passwords (Password1, Summer2023)
- **pwdHistoryLength < 12:** Users can reuse recent passwords
- **maxPwdAge > 180 days:** Passwords never expire, or expire too infrequently

**Detection:**

```csharp
// Query Domain password policy via LDAP
SearchRequest request = new SearchRequest(
    "DC=domain,DC=com",
    "(objectClass=domainDNS)",
    SearchScope.Base,
    "minPwdLength", "pwdProperties", "pwdHistoryLength", "maxPwdAge"
);
```

**Remediation:**

```powershell
# GPO: Default Domain Policy
# Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy

# Minimum password length: 12 characters (CIS: 14+)
net accounts /minpwlen:12

# Password must meet complexity requirements: Enabled
# (Requires uppercase, lowercase, digit, special character)

# Enforce password history: 12 passwords
net accounts /uniquepw:12

# Maximum password age: 90 days (CIS: 60-90)
net accounts /maxpwage:90

# Minimum password age: 1 day (prevents rapid password changes to bypass history)
net accounts /minpwage:1

# Apply via GPO for domain-wide enforcement
gpupdate /force

# Verify
net accounts
```

**Modern Alternative: Fine-Grained Password Policies (PSOs)**

```powershell
# Create high-security PSO for admins
New-ADFineGrainedPasswordPolicy -Name "AdminPasswordPolicy" `
    -Precedence 10 `
    -MinPasswordLength 16 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge 45.00:00:00 `
    -ComplexityEnabled $true `
    -LockoutThreshold 3 `
    -LockoutDuration 01:00:00 `
    -LockoutObservationWindow 00:15:00

# Apply to Domain Admins group
Add-ADFineGrainedPasswordPolicySubject -Identity "AdminPasswordPolicy" -Subjects "Domain Admins"
```

**References:**

- NIST SP 800-63B: Digital Identity Guidelines
- CIS Windows Server Benchmark 1.1.x
- [Microsoft Password Guidance](https://www.microsoft.com/en-us/research/publication/password-guidance/)

---

### Kerberos Scanner

**Code:** `src/Asterion/Checks/CrossPlatform/KerberosScanner.cs` (18KB, 523 lines)
**Protocol:** Kerberos authentication
**Port:** 88 (TCP/UDP)

| Check ID        | Title                                                          | Severity | Confidence |
| --------------- | -------------------------------------------------------------- | -------- | ---------- |
| **AST-KRB-001** | Kerberos accounts without preauthentication (AS-REP roastable) | HIGH     | HIGH       |
| **AST-KRB-002** | Weak Kerberos ticket lifetime (> 10 hours)                     | LOW      | HIGH       |
| **AST-KRB-003** | Service accounts with SPNs vulnerable to Kerberoasting         | HIGH     | HIGH       |

#### AST-KRB-001: AS-REP Roasting

**Description:**
User accounts with "Do not require Kerberos preauthentication" (`DONT_REQUIRE_PREAUTH`) flag set allow attackers to:

1. Request AS-REP (Authentication Service Response) without authentication
2. Receive AS-REP encrypted with user's password-derived key
3. Offline brute-force the response to recover password

**Detection:**

```csharp
// LDAP query for vulnerable accounts
SearchRequest request = new SearchRequest(
    "DC=domain,DC=com",
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",  // UF_DONT_REQUIRE_PREAUTH
    SearchScope.Subtree,
    "samAccountName", "distinguishedName"
);
```

**Exploitation:**

```bash
# Rubeus (Windows)
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# impacket (Linux)
GetNPUsers.py domain.com/ -dc-ip 10.0.0.1 -request -format hashcat -outputfile asrep_hashes.txt

# Hashcat
hashcat -m 18200 asrep_hashes.txt rockyou.txt
```

**Remediation:**

```powershell
# Query affected accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select-Object Name,DistinguishedName

# Fix individual account
Set-ADUser -Identity "username" -DoesNotRequirePreAuth $false

# Fix all at once (CAUTION: Test first)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADUser -DoesNotRequirePreAuth $false

# If pre-auth must be disabled for legacy app:
# - Enforce 20+ character random password
# - Use managed service account if possible
# - Monitor Event ID 4768 (Kerberos TGT request)
```

**Impact:**

- Offline password cracking (no account lockout)
- 100% success rate if weak password used
- Commonly found on service accounts, old user accounts

**References:**

- MITRE ATT&CK T1558.004 (AS-REP Roasting)
- [HarmJ0y: Roasting AS-REPs](https://blog.harmj0y.net/activedirectory/roasting-as-reps/)

---

#### AST-KRB-003: Kerberoasting

**Description:**
Any authenticated domain user can request Kerberos service tickets (TGS) for accounts with Service Principal Names (SPNs). The TGS is encrypted with the service account's password-derived key, allowing offline password cracking.

**Commonly Vulnerable:**

- SQL Server service accounts
- IIS application pool identities
- SharePoint service accounts
- Custom service accounts with SPNs

**Detection:**

```csharp
// LDAP query for accounts with SPNs
SearchRequest request = new SearchRequest(
    "DC=domain,DC=com",
    "(&(objectClass=user)(servicePrincipalName=*))",
    SearchScope.Subtree,
    "samAccountName", "servicePrincipalName", "pwdLastSet"
);
```

**Exploitation:**

```bash
# Rubeus (Windows)
Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast_hashes.txt

# impacket (Linux)
GetUserSPNs.py domain.com/user:password -dc-ip 10.0.0.1 -request

# Hashcat
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt  # TGS-REP (Kerberoasting)
```

**Remediation:**

```powershell
# 1. Query service accounts with SPNs
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName,PasswordLastSet,PasswordNeverExpires |
    Select-Object Name,ServicePrincipalName,PasswordLastSet,PasswordNeverExpires

# 2. BEST SOLUTION: Migrate to Group Managed Service Accounts (gMSA)
# - 127-character random password, auto-rotated every 30 days
# - No password management required
New-ADServiceAccount -Name "SQLServiceGMSA" -DNSHostName "sqlserver.domain.com" -PrincipalsAllowedToRetrieveManagedPassword "SQLServers$"

# 3. If gMSA not feasible: Enforce 25+ character random passwords
$password = [System.Web.Security.Membership]::GeneratePassword(32, 8)
Set-ADAccountPassword -Identity "svc_sql" -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)

# 4. Rotate passwords every 90 days (automate via scheduled task)

# 5. Monitor Event ID 4769 (Kerberos service ticket request)
# Look for unusual TGS requests (e.g., user account requesting tickets for all SPNs)
```

**Impact:**

- **Most common Active Directory attack** after initial access
- 100% success rate with weak service account passwords
- No account lockout (offline attack)

**References:**

- MITRE ATT&CK T1558.003 (Kerberoasting)
- [Tim Medin: Attacking Kerberos - Kicking the Guard Dog of Hades](https://www.youtube.com/watch?v=PUyhlN-E5MU)
- [Microsoft: gMSA Getting Started Guide](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts)

---

### DNS/LLMNR/mDNS Scanner

**Code:** `src/Asterion/Checks/CrossPlatform/DnsScanner.cs` (16KB, 456 lines)
**Protocol:** Domain Name System (DNS), Link-Local Multicast Name Resolution (LLMNR), Multicast DNS (mDNS)
**Ports:** 53 (DNS), 5355 (LLMNR), 5353 (mDNS)

| Check ID        | Title                                | Severity | Confidence |
| --------------- | ------------------------------------ | -------- | ---------- |
| **AST-DNS-001** | DNS zone transfer (AXFR) allowed     | CRITICAL | HIGH       |
| **AST-NET-002** | LLMNR/NetBIOS enabled on network     | MEDIUM   | MEDIUM     |
| **AST-DNS-003** | mDNS (Multicast DNS) service exposed | LOW      | MEDIUM     |

#### AST-DNS-001: DNS Zone Transfer (AXFR)

**Description:**
DNS server allows unrestricted zone transfers (AXFR), exposing complete DNS zone data:

- All hostnames and IP addresses (reconnaissance)
- Mail servers (email infrastructure)
- Service records (SRV) revealing internal architecture
- Subdomain enumeration

**Detection:**

```csharp
// Attempt AXFR query
using DnsClient;
var lookup = new LookupClient();
var response = await lookup.QueryAsync(domain, QueryType.AXFR);
```

**Remediation:**

```bash
# BIND (Linux): /etc/bind/named.conf.local
zone "example.com" {
    type master;
    file "/etc/bind/db.example.com";
    allow-transfer {
        10.0.0.2;  # Secondary NS IP
        10.0.0.3;  # Another secondary
    };
    # Or use TSIG for authenticated transfers
    allow-transfer { key "zone-transfer-key"; };
};

# Verify
dig @ns1.example.com example.com AXFR  # Should be refused

# Windows DNS Server: DNS Manager
# Right-click zone > Properties > Zone Transfers
# [ ] Allow zone transfers
# Or: "Only to servers listed on the Name Servers tab"
# Apply TSIG keys for authentication
```

**Impact:**

- **Full reconnaissance:** Attacker learns entire internal DNS layout
- **Subdomain discovery:** Find hidden/development/admin subdomains
- **Email harvesting:** Identify mail servers for phishing campaigns

**References:**

- RFC 5155: DNS Security (DNSSEC)
- CWE-497: Exposure of System Data to an Unauthorized Control Sphere

---

#### AST-NET-002: LLMNR/NetBIOS Enabled

**Description:**
Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are fallback name resolution protocols used when DNS fails. Attackers can:

1. Poison LLMNR/NBT-NS responses (respond to all queries claiming to be the target)
2. Intercept SMB authentication attempts
3. Capture NTLMv2 hashes
4. Crack hashes offline or relay authentication

**Detection:**

```csharp
// Check for LLMNR traffic on UDP 5355
// Send LLMNR query, check if responses received

// Check for NetBIOS traffic on UDP 137
// Send NBNS query
```

**Exploitation:**

```bash
# Responder (Linux) - LLMNR/NBT-NS poisoner
sudo responder -I eth0 -wrf

# Captured hashes (NTLMv2)
# [+] [SMB] NTLMv2-SSP Hash     : user::DOMAIN:1122334455667788:hash...
# Crack with hashcat -m 5600
```

**Remediation:**

```powershell
# GPO: Computer Configuration > Administrative Templates > Network > DNS Client
# "Turn off multicast name resolution" = Enabled

# Registry (individual host)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0

# Disable NetBIOS over TCP/IP via DHCP scope options or adapter settings
# Network Adapter > Properties > TCP/IPv4 > Advanced > WINS > "Disable NetBIOS over TCP/IP"

# Verify
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast

# Ensure reliable DNS infrastructure (primary reason for LLMNR/NBT-NS fallback)
```

**Impact:**

- **Credential theft:** Passive attack, no account lockout
- **MitM authentication:** SMB relay, HTTP relay
- **Common attack vector:** Responder is first step in most internal pentests

**References:**

- MITRE ATT&CK T1557.001 (LLMNR/NBT-NS Poisoning)
- [SpiderLabs: LLMNR/NBT-NS Poisoning](https://www.aptive.co.uk/blog/llmnr-nbt-ns-spoofing/)

---

### SNMP Scanner

**Code:** `src/Asterion/Checks/CrossPlatform/SnmpScanner.cs` (14KB, 398 lines)
**Protocol:** Simple Network Management Protocol (SNMP)
**Port:** 161 (UDP)

| Check ID         | Title                                 | Severity    | Confidence |
| ---------------- | ------------------------------------- | ----------- | ---------- |
| **AST-SNMP-001** | SNMP using default community string   | MEDIUM/HIGH | HIGH       |
| **AST-SNMP-002** | SNMP with write access (RW community) | CRITICAL    | MEDIUM     |
| **AST-SNMP-003** | SNMPv1/v2c in use (unencrypted)       | LOW         | HIGH       |

#### AST-SNMP-002: SNMP Write Access

**Description:**
SNMP server allows write access (SET operations) via community string, enabling attackers to:

- Modify device configurations
- Change routing tables
- Disable interfaces
- Exfiltrate sensitive data
- Execute commands (on some devices)

**Common RW Community Strings:**

- `private`, `write`, `admin`, `secret`, `rwcommunity`, `rw`

**Detection:**

```csharp
// Attempt SNMP SET operation with RW community
var snmp = new SimpleSnmp(target, "private");
var result = snmp.Set(SnmpVersion.Ver2, new VarBind[] {
    new VarBind(new Oid("1.3.6.1.2.1.1.6.0"), new OctetString("test"))
});
// If successful � Write access confirmed
```

**Remediation:**

```bash
# Cisco IOS/IOS-XE
(config)# no snmp-server community private RW
(config)# snmp-server community [random-32-char-string] RO
(config)# access-list 50 permit 10.0.0.0 0.0.0.255  # Management subnet only
(config)# snmp-server community [random] RO 50

# Linux (net-snmp): /etc/snmp/snmpd.conf
# Remove/comment out RW communities
#rocommunity  private
rocommunity  [random-32-char-string]  10.0.0.0/24

# Restart
sudo systemctl restart snmpd

# BEST: Upgrade to SNMPv3 with authentication + encryption
(config)# snmp-server group v3group v3 priv
(config)# snmp-server user v3user v3group v3 auth sha [auth-pass] priv aes 256 [priv-pass]
```

**Impact:**

- **Complete device compromise:** Configuration changes, denial of service
- **Lateral movement:** Modify routing to intercept traffic
- **Data exfiltration:** Read and modify MIB objects

**References:**

- CVE-2002-0013 (Multiple SNMP vulnerabilities)
- CIS Network Device Benchmark

---

### FTP Scanner

**Code:** `src/Asterion/Checks/CrossPlatform/FtpScanner.cs` (11KB, 312 lines)
**Protocol:** File Transfer Protocol (FTP)
**Port:** 21 (control), 20 (data - active mode)

| Check ID        | Title                                | Severity | Confidence |
| --------------- | ------------------------------------ | -------- | ---------- |
| **AST-FTP-001** | Anonymous FTP access enabled         | HIGH     | HIGH       |
| **AST-FTP-002** | Anonymous FTP with WRITE permissions | CRITICAL | HIGH       |
| **AST-FTP-003** | FTP not encrypted (no FTPS/TLS)      | MEDIUM   | MEDIUM     |

#### AST-FTP-002: Anonymous FTP Write Access

**Description:**
FTP server allows anonymous users to upload files, creating risk of:

- **Malware distribution:** Attackers upload malicious files
- **Warez/piracy:** Server used for illegal file sharing
- **Data exfiltration staging:** Stolen data uploaded temporarily
- **Web shell uploads:** If FTP root is also web root (e.g., `/var/www/html`)

**Detection:**

```csharp
// 1. Connect as anonymous
FtpClient client = new FtpClient(target);
client.Credentials = new NetworkCredential("anonymous", "anonymous@example.com");
client.Connect();

// 2. Attempt file upload (STOR command)
using (Stream ostream = client.OpenWrite("/test.txt"))
{
    // If successful � Write access confirmed
}
```

**Remediation:**

```bash
# vsFTPd (Linux): /etc/vsftpd.conf
anonymous_enable=NO
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO

# If anonymous READ-ONLY access needed (e.g., public FTP):
anonymous_enable=YES
anon_upload_enable=NO  # Explicitly deny write
local_enable=YES
write_enable=YES  # For authenticated users only
chown_uploads=YES
chown_username=ftp

# ProFTPd: /etc/proftpd/proftpd.conf
# Comment out or restrict <Anonymous> block
#<Anonymous ~ftp>
#  User ftp
#  Group nogroup
#  <Limit WRITE>
#    DenyAll
#  </Limit>
#</Anonymous>

# IIS FTP (Windows): FTP Authentication
# IIS Manager > Sites > FTP site > FTP Authentication
# Disable "Anonymous Authentication"
# Enable "Basic Authentication" (with FTPS)

# Verify
ftp anonymous@target  # Should be denied
# Or attempt upload - should fail

# Audit for abuse
find /srv/ftp -type f -mtime -7  # Files uploaded in last week
```

**Impact:**

- **Legal liability:** Server used for piracy, malware distribution
- **Server compromise:** Uploaded PHP/ASP web shells if web root shared
- **Resource abuse:** Bandwidth, storage consumed

**References:**

- OWASP: Unrestricted File Upload
- CWE-434: Unrestricted Upload of File with Dangerous Type

---

### Port Scanner

**Code:** `src/Asterion/Checks/CrossPlatform/PortScanner.cs` (8KB, 234 lines)
**Protocol:** TCP connect() scan
**Ports:** Configurable (default: common services)

| Check ID        | Title                     | Severity        | Confidence |
| --------------- | ------------------------- | --------------- | ---------- |
| **AST-NET-003** | Open ports detected       | INFO            | HIGH       |
| **AST-NET-004** | Dangerous service exposed | LOW/MEDIUM/HIGH | HIGH       |

#### AST-NET-004: Dangerous Services Exposed

**Description:**
Network services exposed to untrusted networks (Internet, guest WiFi) that should be restricted:

| Port  | Service       | Risk                                                | Severity |
| ----- | ------------- | --------------------------------------------------- | -------- |
| 23    | Telnet        | Unencrypted remote access, credentials in plaintext | HIGH     |
| 135   | Microsoft RPC | Windows exploitation, DCOM abuse                    | HIGH     |
| 445   | SMB/CIFS      | Ransomware (WannaCry, NotPetya), lateral movement   | HIGH     |
| 3389  | RDP           | Brute-force, BlueKeep (CVE-2019-0708)               | HIGH     |
| 1433  | MS SQL Server | SQL injection, credential theft                     | MEDIUM   |
| 3306  | MySQL         | SQL injection, weak authentication                  | MEDIUM   |
| 5432  | PostgreSQL    | SQL injection, privilege escalation                 | MEDIUM   |
| 27017 | MongoDB       | NoSQL injection, often unauthenticated              | HIGH     |
| 6379  | Redis         | RCE via config SET, often no authentication         | HIGH     |
| 9200  | Elasticsearch | RCE, data exfiltration                              | HIGH     |

**Remediation:**

```bash
# FIREWALL: Restrict to authorized IPs only
# Linux (ufw)
sudo ufw deny 445/tcp
sudo ufw allow from 10.0.0.0/24 to any port 445 proto tcp

# Linux (iptables)
iptables -A INPUT -p tcp --dport 445 -s 10.0.0.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 445 -j DROP

# Windows Firewall
New-NetFirewallRule -DisplayName "SMB Restrict" -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress 10.0.0.0/24 -Action Allow
New-NetFirewallRule -DisplayName "SMB Deny Others" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block

# CLOUD: Use Network Security Groups (NSG) / Security Groups
# Azure NSG: Deny SMB (445) from Internet
# AWS Security Group: Allow 445 only from VPC CIDR

# VPN/BASTION: Move services behind VPN or jump host
# Replace RDP (3389) with Azure Bastion, AWS Systems Manager Session Manager

# SERVICE HARDENING:
# - Telnet: Replace with SSH
# - RDP: Require VPN, enable NLA, use RD Gateway
# - Databases: Bind to localhost (127.0.0.1) if local-only, require TLS
# - MongoDB: Enable authentication (mongod --auth), bind to internal IP
# - Redis: requirepass, bind 127.0.0.1, disable dangerous commands (FLUSHALL, CONFIG)
# - Elasticsearch: Enable X-Pack security, require authentication
```

**References:**

- CIS Critical Security Controls: CSC 9 (Limitation and Control of Network Ports)
- SANS Top 25: CWE-1188 (Insecure Default Initialization of Resource)

---

## Windows Security Checks

### Windows Firewall

**Code:** `src/Asterion/Checks/CrossPlatform/Windows/WinFirewallCheck.cs` (9KB, 267 lines)
**Category:** Windows

| Check ID           | Title                                | Severity    | Confidence |
| ------------------ | ------------------------------------ | ----------- | ---------- |
| **AST-FW-WIN-001** | Windows Firewall disabled on profile | HIGH        | HIGH       |
| **AST-FW-WIN-002** | Overly permissive firewall rules     | MEDIUM/HIGH | HIGH       |
| **AST-FW-WIN-003** | Firewall logging disabled            | LOW         | HIGH       |
| **AST-FW-WIN-004** | Windows Firewall service not running | CRITICAL    | HIGH       |

#### AST-FW-WIN-001: Windows Firewall Disabled

**Remediation:**

```powershell
# Enable via PowerShell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow

# Verify
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction

# Via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security
# Domain/Private/Public Profile > State = On
# Inbound connections = Block (default)
# Outbound connections = Allow (default)
```

---

### Windows Registry

**Code:** `src/Asterion/Checks/CrossPlatform/Windows/WinRegistryCheck.cs` (12KB, 354 lines)
**Category:** Windows

| Check ID            | Title                                                     | Severity    |
| ------------------- | --------------------------------------------------------- | ----------- |
| **AST-REG-WIN-001** | Insecure LM/NTLM compatibility level (< 5)                | HIGH/MEDIUM |
| **AST-REG-WIN-002** | LM password hashes stored in SAM                          | HIGH        |
| **AST-REG-WIN-003** | Anonymous SAM account/share enumeration not restricted    | MEDIUM      |
| **AST-REG-WIN-004** | NTLM client session security weak                         | MEDIUM      |
| **AST-REG-WIN-005** | NTLM server session security weak                         | MEDIUM      |
| **AST-REG-WIN-006** | User Account Control (UAC) completely disabled            | HIGH        |
| **AST-REG-WIN-007** | UAC elevates without prompting                            | HIGH        |
| **AST-REG-WIN-008** | UAC secure desktop disabled                               | MEDIUM      |
| **AST-REG-WIN-011** | Everyone includes Anonymous (legacy setting)              | MEDIUM      |
| **AST-REG-WIN-012** | WDigest authentication enabled (cleartext creds in LSASS) | HIGH        |

_(See full check details in implementation)_

---

### Active Directory Policy

**Code:** `src/Asterion/Checks/CrossPlatform/Windows/AdPolicyCheck.cs` (7KB, 198 lines)
**Category:** Windows

| Check ID           | Title                                  | Severity    |
| ------------------ | -------------------------------------- | ----------- |
| **AST-AD-WIN-001** | LDAP signing not required by DC        | HIGH        |
| **AST-AD-WIN-002** | Weak password policy                   | MEDIUM/HIGH |
| **AST-AD-WIN-003** | Domain trusts detected (informational) | INFO        |

---

### Windows Services

**Code:** `src/Asterion/Checks/CrossPlatform/Windows/WinServicesCheck.cs` (10KB, 289 lines)
**Category:** Windows

| Check ID             | Service                                      | Severity |
| -------------------- | -------------------------------------------- | -------- |
| **AST-IIS-WIN-001**  | IIS WebDAV enabled                           | MEDIUM   |
| **AST-IIS-WIN-002**  | IIS anonymous authentication enabled         | LOW      |
| **AST-IIS-WIN-003**  | IIS default welcome page present             | LOW      |
| **AST-IIS-WIN-004**  | IIS HTTPS not configured                     | MEDIUM   |
| **AST-IIS-WIN-005**  | IIS directory browsing enabled               | MEDIUM   |
| **AST-SQL-WIN-001**  | SQL Server outdated version                  | HIGH     |
| **AST-SQL-WIN-002**  | SQL Server mixed mode authentication         | MEDIUM   |
| **AST-SQL-WIN-003**  | SQL 'sa' account enabled                     | HIGH     |
| **AST-EXCH-WIN-001** | Exchange Server requires patches             | HIGH     |
| **AST-SVC-WIN-001**  | Service running as LocalSystem unnecessarily | LOW      |
| **AST-SVC-WIN-003**  | Critical services detected                   | INFO     |

---

### Windows Privilege Escalation

**Code:** `src/Asterion/Checks/CrossPlatform/Windows/PrivEscCheckWin.cs` (15KB, 432 lines)
**Category:** Windows

| Check ID             | Title                                               | Severity |
| -------------------- | --------------------------------------------------- | -------- |
| **AST-PRIV-WIN-001** | Service executable writable by non-admins           | HIGH     |
| **AST-PRIV-WIN-002** | Unquoted service path with spaces                   | MEDIUM   |
| **AST-PRIV-WIN-003** | Service DLL hijacking possible                      | HIGH     |
| **AST-PRIV-WIN-004** | Scheduled task with writable executable             | HIGH     |
| **AST-PRIV-WIN-005** | AlwaysInstallElevated registry keys enabled         | CRITICAL |
| **AST-PRIV-WIN-006** | Weak ACLs on system directories                     | HIGH     |
| **AST-PRIV-WIN-007** | Writable directories in system PATH                 | MEDIUM   |
| **AST-PRIV-WIN-008** | Writable AutoRun registry targets                   | HIGH     |
| **AST-PRIV-WIN-009** | Writable Startup folder                             | MEDIUM   |
| **AST-PRIV-WIN-010** | SeImpersonatePrivilege enabled (Potato attack risk) | HIGH     |

---

## Linux Security Checks

### Linux Firewall

**Code:** `src/Asterion/Checks/CrossPlatform/Linux/LinuxFirewallCheck.cs` (8KB, 223 lines)
**Category:** Linux

| Check ID           | Title                                 | Severity |
| ------------------ | ------------------------------------- | -------- |
| **AST-FW-LNX-001** | UFW/firewalld disabled                | HIGH     |
| **AST-FW-LNX-002** | iptables default policy ACCEPT        | HIGH     |
| **AST-FW-LNX-003** | Permissive firewall rules (0.0.0.0/0) | MEDIUM   |
| **AST-FW-LNX-004** | No active firewall rules              | HIGH     |

---

### SSH Configuration

**Code:** `src/Asterion/Checks/CrossPlatform/Linux/SshConfigCheck.cs` (9KB, 256 lines)
**Category:** Linux

| Check ID            | Title                               | Severity |
| ------------------- | ----------------------------------- | -------- |
| **AST-SSH-LNX-001** | Root login permitted via SSH        | HIGH     |
| **AST-SSH-LNX-002** | Weak SSH cipher/MAC algorithms      | MEDIUM   |
| **AST-SSH-LNX-003** | Password authentication without MFA | MEDIUM   |
| **AST-SSH-LNX-004** | Empty passwords allowed (CRITICAL)  | CRITICAL |
| **AST-SSH-LNX-005** | X11 forwarding enabled              | LOW      |

---

### Samba/NFS Configuration

**Code:** `src/Asterion/Checks/CrossPlatform/Linux/SambaNfsCheck.cs` (7KB, 189 lines)
**Category:** Linux

| Check ID              | Title                                | Severity    |
| --------------------- | ------------------------------------ | ----------- |
| **AST-SAMBA-LNX-001** | Samba share with guest/public access | MEDIUM/HIGH |
| **AST-SAMBA-LNX-002** | SMBv1 enabled in Samba               | HIGH        |
| **AST-NFS-LNX-001**   | NFS export with no_root_squash       | CRITICAL    |
| **AST-NFS-LNX-002**   | NFS world-writable export (\*)(rw)   | HIGH        |

---

### Linux Privilege Escalation

**Code:** `src/Asterion/Checks/CrossPlatform/Linux/PrivEscCheckLinux.cs` (13KB, 378 lines)
**Category:** Linux

| Check ID             | Title                                                               | Severity      |
| -------------------- | ------------------------------------------------------------------- | ------------- |
| **AST-PRIV-LNX-001** | Dangerous SUID binary (vim, python, bash, find, etc.)               | CRITICAL      |
| **AST-PRIV-LNX-002** | SUID in world-writable directory                                    | HIGH          |
| **AST-PRIV-LNX-003** | Insecure sudoers NOPASSWD config                                    | CRITICAL/HIGH |
| **AST-PRIV-LNX-004** | Critical file permissions insecure (/etc/shadow, sudoers, SSH keys) | CRITICAL/HIGH |
| **AST-PRIV-LNX-005** | SUID binary in unusual location                                     | INFO          |
| **AST-PRIV-LNX-006** | Docker socket accessible (container escape to root)                 | CRITICAL/HIGH |
| **AST-PRIV-LNX-007** | Writable systemd unit files (code execution as root on reload)      | HIGH          |
| **AST-PRIV-LNX-008** | Exposed credential files (world-readable .bash_history, .env, etc.) | HIGH          |

---

## Statistics

### Total Checks by Category (v0.2.0)

| Category                  | Checks   | Notes                                             |
| ------------------------- | -------- | ------------------------------------------------- |
| **CrossPlatform Network** | 35+      | + TLS scanner, SYSVOL/GPP check                   |
| **Windows (WinRM)**       | 50+      | + IIS, SQL Server, Exchange, WinRM remote checks  |
| **Linux (SSH)**           | 35+      | + Docker socket, systemd units, cred files (aggr) |
| **Attack Chains**         | 8 rules  | AST-CHAIN-001..008                                |
| **TOTAL**                 | **130+** |                                                   |

### Critical Severity Breakdown

**Linux (7 critical):**

- AST-PRIV-LNX-001: Dangerous SUID binaries (vim, python, bash)
- AST-PRIV-LNX-003: Sudoers NOPASSWD for dangerous commands
- AST-PRIV-LNX-004: /etc/shadow world-readable
- AST-PRIV-LNX-006: Docker socket accessible (container escape)
- AST-SSH-LNX-004: SSH empty passwords allowed
- AST-NFS-LNX-001: NFS no_root_squash
- AST-FTP-002: Anonymous FTP write access

**CrossPlatform Network (5 critical):**

- AST-SMB-001: SMB anonymous access
- AST-RDP-003: BlueKeep vulnerability (CVE-2019-0708)
- AST-DNS-001: DNS zone transfer (AXFR) allowed
- AST-SNMP-002: SNMP write access
- (AST-FTP-002 counted in Linux above)

**Windows (2 critical):**

- AST-PRIV-WIN-005: AlwaysInstallElevated enabled
- AST-FW-WIN-004: Windows Firewall service stopped

### Most Common Findings

Based on typical enterprise environments:

1. **AST-AD-002:** Weak password policy (80% of networks)
2. **AST-SMB-002:** SMB signing not required (70%)
3. **AST-LDAP-001:** Anonymous LDAP bind (60%)
4. **AST-KRB-003:** Kerberoastable service accounts (90% of domains)
5. **AST-SSH-LNX-001:** Root SSH login enabled (50% of Linux hosts)

---

## Check Implementation

### How Checks Are Executed

**1. Orchestrator selects checks based on scan mode:**

```csharp
// src/Asterion/Core/Orchestrator.cs
if (options.Mode == "safe")
{
    // Passive checks only (reconnaissance)
    checks = allChecks.Where(c => c.Mode == CheckMode.Passive);
}
else if (options.Mode == "aggressive")
{
    // All checks including exploitation
    checks = allChecks;
}
```

**2. Each check implements ICheck interface:**

```csharp
// src/Asterion/Checks/ICheck.cs
public interface ICheck
{
    Task<CheckResult> ExecuteAsync(string target, ScanOptions options);
    CheckCategory Category { get; }
    string Name { get; }
}
```

**3. Checks return findings:**

```csharp
// src/Asterion/Models/Finding.cs
public class Finding
{
    public string Id { get; set; }              // AST-SMB-001
    public string Title { get; set; }           // "SMB anonymous access"
    public string Severity { get; set; }        // critical, high, medium, low, info
    public string Confidence { get; set; }      // high, medium, low
    public Evidence? Evidence { get; set; }     // Proof of finding
    public string Recommendation { get; set; }  // How to fix
    public List<string>? References { get; set; }  // CVEs, docs
}
```

---

## Related Documentation

- **CONSENT.md** - Consent token system (required for aggressive mode)
- **ETHICS.md** - Legal and ethical guidelines for security testing
- **DATABASE_GUIDE.md** - Findings storage in SQLite database
- **README.md** - Usage examples and installation
- **ROADMAP.md** - Future check implementations (v0.2.0-v0.4.0)

---

**Last Updated:** May 2026
**Asterion Version:** 0.2.0
**Total Security Checks:** 99
**Code Location:** `src/Asterion/Checks/`
