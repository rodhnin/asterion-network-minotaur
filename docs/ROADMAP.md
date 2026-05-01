# Asterion Development Roadmap

## v0.1.0 ✅ RELEASED

**Release Date:** November 2025
**Status:** ✅ **PRODUCTION READY**

### Features Included

#### Core Network Scanning

- ✅ **Port Scanning**: TCP port scanning with configurable ranges (1-65535)
- ✅ **Service Detection**: Banner grabbing for SMB, RDP, LDAP, SSH, FTP, DNS, SNMP
- ✅ **Target Parsing**: CIDR notation, IP ranges, single IPs, hostnames
- ✅ **Multi-Threading**: Concurrent scanning with 1-20 worker threads
- ✅ **Rate Limiting**: Configurable request throttling (1-20 req/s)
- ✅ **SSH Remote Auditing**: Full Linux system checks via SSH.NET

#### Cross-Platform Network Checks (20+ checks)

- ✅ **SMB/CIFS Security** (AST-SMB-001 to AST-SMB-005):
    - Anonymous/guest share access
    - SMB signing not required
    - SMBv1 enabled detection
    - NTLMv1 authentication allowed
    - Writable shares detection
- ✅ **RDP Security** (AST-RDP-001 to AST-RDP-004):
    - RDP without Network Level Authentication (NLA)
    - Weak RDP encryption levels
    - RDP exposed to internet
    - Default port detection
- ✅ **LDAP/Active Directory** (AST-LDAP-001, AST-AD-001 to AST-AD-006):
    - LDAP anonymous bind
    - LDAP signing not required
    - LDAP channel binding not enforced
    - Weak password policies
    - Password never expires for admin accounts
    - Pre-Windows 2000 compatible access
- ✅ **Kerberos** (AST-KRB-001 to AST-KRB-003):
    - AS-REP roasting vulnerability detection
    - Kerberoasting vulnerable accounts
    - Excessive ticket lifetime
- ✅ **SNMP** (AST-SNMP-001 to AST-SNMP-003):
    - Default community strings
    - SNMPv1/v2c plaintext detection
    - SNMP write access enabled
- ✅ **DNS/NetBIOS** (AST-NET-001 to AST-NET-003):
    - DNS zone transfer (AXFR) allowed
    - LLMNR/NetBIOS poisoning risk
    - mDNS responder enabled

#### Windows-Specific Checks (15+ checks)

- ✅ **Firewall** (AST-FW-001 to AST-FW-003):
    - Windows Firewall disabled or permissive
    - Firewall rules allowing Any-Any traffic
    - Inbound RDP allowed from any source
- ✅ **Registry** (AST-WIN-001 to AST-WIN-004):
    - LM/NTLM authentication settings
    - UAC disabled or weakened
    - AutoAdminLogon enabled
    - LSA protection disabled
- ✅ **Active Directory Policies** (AST-AD-006 to AST-AD-008):
    - Default Domain Controllers GPO modified
    - Unconstrained delegation enabled
    - AdminSDHolder permissions modified
- ✅ **Services & Privileges** (AST-PRV-001 to AST-PRV-004):
    - Service executable writable by non-admin
    - Unquoted service paths
    - AlwaysInstallElevated enabled
    - Weak service permissions

#### Linux-Specific Checks (12+ checks)

- ✅ **Firewall** (AST-LNX-001 to AST-LNX-003):
    - iptables/nftables disabled or permissive
    - Firewall rules allowing all traffic
    - Firewall not persistent across reboots
- ✅ **NFS Security** (AST-NFS-001 to AST-NFS-003):
    - NFS export with no_root_squash
    - NFS export accessible to world
    - NFSv3 in use (no authentication)
- ✅ **SSH Security** (AST-SSH-001 to AST-SSH-004):
    - Root login via SSH permitted
    - Password authentication enabled
    - Weak SSH ciphers/MACs enabled
    - SSH default port in use
- ✅ **Privilege Escalation** (AST-PRV-005 to AST-PRV-008):
    - Dangerous SUID binaries
    - World-writable files in privileged directories
    - Sudo misconfiguration
    - /etc/passwd or /etc/shadow world-readable

#### Infrastructure

- ✅ **Consent Token System**: Ethical scanning with HTTP/.well-known, DNS TXT, or SSH verification
- ✅ **SQLite Database**: Shared Argos Suite database (~/.argos/argos.db)
- ✅ **Dual Reporting**: JSON (machine-readable) and HTML (Minotaur-themed) formats
- ✅ **Professional HTML Reports**: Responsive, self-contained, Minotaur branding (red/orange/purple)
- ✅ **Automatic Secret Redaction**: Logging system prevents credential leaks
- ✅ **Multi-Source Configuration**: YAML defaults + environment variables + CLI overrides
- ✅ **Docker Support**: Production-ready containerized scanning

#### AI-Powered Analysis (3 Providers)

- ✅ **OpenAI GPT-4 Turbo**: Premium quality analysis via Python bridge
- ✅ **Anthropic Claude**: Privacy-focused alternative
- ✅ **Ollama (Local Models)**: 100% offline analysis
- ✅ **Executive Summaries**: Non-technical reports for management
- ✅ **Technical Remediation Guides**: Step-by-step PowerShell/Bash commands
- ✅ **Dual-Tone Mode**: Both executive and technical analysis
- ✅ **Automatic Sanitization**: Zero credentials leaked to AI providers

#### Authentication & Credentials

- ✅ **Basic Authentication**: user:pass or DOMAIN\user:pass
- ✅ **NTLM Hash Authentication**: Pass-the-hash for SMB
- ✅ **Kerberos**: user:pass@REALM (Windows native SSPI)
- ✅ **SSH Credentials**: Remote Linux auditing via SSH.NET

#### Resilience & Error Handling

- ✅ **Connection Error Recovery**: Handles timeouts, DNS failures, refused connections
- ✅ **Database Corruption Recovery**: Automatic backup and recreation
- ✅ **Read-Only Mode**: Graceful degradation when database is locked
- ✅ **Partial Scan Support**: Preserves results even if target goes offline mid-scan
- ✅ **Ctrl+C Handling**: Graceful shutdown with result preservation

#### Developer Experience

- ✅ **Rich CLI Interface**: Colored output, progress tracking, ASCII art Minotaur branding
- ✅ **Verbosity Levels**: `-v` (verbose) for detailed logging
- ✅ **Comprehensive Help**: Built-in documentation with examples
- ✅ **Flexible Deployment**: Native .NET, Docker, or cross-platform

### Performance Benchmarks (v0.1.0)

- **Scan Duration**: 15-90 seconds (depending on target count and ports)
- **Database Efficiency**: Shared with Argos Suite (2.0 MB for 5,000+ findings across all tools)
- **Query Performance**: 5-50ms for complex aggregations
- **Concurrent Target Scanning**: 5-20 simultaneous targets
- **Scalability**: Tested up to 1,000+ targets with linear performance

---

## v0.2.0 ✅ RELEASED — Remote System Auditing & Enhanced Detection

**Theme:** Remote Windows/Linux Auditing + Advanced Network Checks
**Release Date:** May 2026
**Status:** ✅ **PRODUCTION READY**
**Focus:** WinRM support, enhanced remote checks, aggressive mode differentiation, AI enhancements, attack chains, diff reports

---

### 🔍 Remote Windows System Checks (WinRM) ✅ COMPLETED

**Ticket:** AST-FEATURE-001
**Priority:** High
**Status:** ✅ Shipped in v0.2.0 — `WinRmConnectionManager.cs`, `WinRmChecks.cs`, `--winrm` flag

#### Problem Statement

Currently, Windows-specific checks (firewall, registry, services) only work when:

- Running Asterion **on Windows locally** (ASP.NET WMI)
- Running via SSH on Linux targets

Windows remote auditing requires **WinRM (Windows Remote Management)**.

#### Planned Implementation

**1. WinRMConnectionManager.cs**

```csharp
// New class: src/Asterion/Core/WinRMConnectionManager.cs
using System.Management.Automation;
using System.Management.Automation.Runspaces;

public class WinRMConnectionManager
{
    private Runspace _runspace;

    public async Task<bool> ConnectAsync(string target, NetworkCredential credentials)
    {
        var connectionInfo = new WSManConnectionInfo
        {
            ComputerName = target,
            Credential = credentials,
            AuthenticationMechanism = AuthenticationMechanism.Kerberos // or NTLM
        };

        _runspace = RunspaceFactory.CreateRunspace(connectionInfo);
        await Task.Run(() => _runspace.Open());

        return _runspace.RunspaceStateInfo.State == RunspaceState.Opened;
    }

    public async Task<string> ExecutePowerShellAsync(string command)
    {
        using var pipeline = _runspace.CreatePipeline(command);
        var results = await Task.Run(() => pipeline.Invoke());

        return string.Join("\n", results.Select(r => r.ToString()));
    }
}
```

**2. Enhanced Windows Checks with WinRM Support**

```csharp
// Example: WinFirewallCheck.cs
public override async Task<List<Finding>> ExecuteAsync(
    List<string> targets,
    ScanOptions options)
{
    var findings = new List<Finding>();

    foreach (var target in targets)
    {
        // Local check (if running on Windows)
        if (IsLocalTarget(target) && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            findings.AddRange(await CheckLocalFirewallAsync());
        }
        // Remote check via WinRM
        else if (!string.IsNullOrEmpty(options.WinRmCredentials))
        {
            findings.AddRange(await CheckRemoteFirewallViaWinRMAsync(target, options));
        }
        else
        {
            Log.Warning($"Skipping Windows firewall check for {target}: Not local and no WinRM credentials");
        }
    }

    return findings;
}

private async Task<List<Finding>> CheckRemoteFirewallViaWinRMAsync(string target, ScanOptions options)
{
    var findings = new List<Finding>();
    var winrm = new WinRMConnectionManager();

    // Parse credentials: DOMAIN\user:pass
    var creds = ParseCredentials(options.WinRmCredentials);

    if (!await winrm.ConnectAsync(target, creds))
    {
        Log.Error($"Failed to connect to {target} via WinRM");
        return findings;
    }

    // Execute PowerShell command
    var psCommand = "Get-NetFirewallProfile | Select-Object Name, Enabled";
    var result = await winrm.ExecutePowerShellAsync(psCommand);

    // Parse and create findings
    if (result.Contains("Enabled : False"))
    {
        findings.Add(new Finding
        {
            Id = "AST-FW-WIN-001",
            Title = "Windows Firewall disabled",
            Severity = Severity.High,
            Evidence = new Evidence { Type = "powershell", Value = result },
            Target = target
        });
    }

    return findings;
}
```

**3. CLI Integration**

```bash
# New CLI option
ast scan --target 10.0.0.5 --winrm "CORP\admin:P@ssw0rd"

# With Kerberos
ast scan --target dc01.corp.local --kerberos "admin:password@CORP.LOCAL"
```

**4. Configuration**

```yaml
# config/defaults.yaml
authentication:
    winrm:
        auth_mechanism: "kerberos" # or "ntlm"
        timeout: 30
        max_envelope_size: 512000
        use_ssl: true
        skip_ca_check: false # Set to true for self-signed certs
```

#### Checks Enabled by WinRM

- ✅ **WinFirewallCheck** (remote)
- ✅ **WinRegistryCheck** (remote)
- ✅ **AdPolicyCheck** (remote domain queries)
- ✅ **WinServicesCheck** (remote)
- ✅ **PrivEscCheckWin** (remote privilege escalation vectors)

#### Benefits

- **True Remote Auditing**: Scan Windows servers from Linux/macOS
- **Enterprise AD Scanning**: Audit domain controllers without local access
- **Consistent Results**: Same checks work locally and remotely
- **Credential Reuse**: Use same domain credentials for SMB + WinRM

**Target Release:** v0.2.0

---

### 🔍 Enhanced Linux Remote Checks (SSH) ✅ COMPLETED

**Ticket:** AST-FEATURE-002
**Priority:** Medium
**Status:** ✅ Shipped in v0.2.0 — `--ssh-key`, `--sudo-password`, `--bastion` flags

#### Current Limitations

SSH remote checks work, but some improvements needed:

- No SSH key-based authentication (only password)
- No multi-hop SSH (bastion/jump hosts)
- No automatic sudo elevation

#### Planned Enhancements

**1. SSH Key Authentication**

```csharp
// SshConnectionManager.cs enhancement
public async Task<bool> ConnectWithKeyAsync(
    string target,
    string username,
    string privateKeyPath,
    string passphrase = null)
{
    var keyFile = new PrivateKeyFile(privateKeyPath, passphrase);
    var keyAuth = new PrivateKeyAuthenticationMethod(username, keyFile);

    var connectionInfo = new ConnectionInfo(target, username, keyAuth);
    _client = new SshClient(connectionInfo);

    await Task.Run(() => _client.Connect());
    return _client.IsConnected;
}
```

**2. Automatic Sudo Elevation**

```csharp
// Enhanced ExecuteCommandAsync
public async Task<string> ExecuteCommandWithSudoAsync(string command, string sudoPassword)
{
    // Create sudo command with password
    var sudoCommand = $"echo '{sudoPassword}' | sudo -S {command}";

    var result = await _client.RunCommandAsync(sudoCommand);
    return result.Result;
}
```

**3. Multi-Hop SSH (Bastion/Jump Host)**

```yaml
# config/defaults.yaml
ssh:
    jump_hosts:
        - host: bastion.corp.local
          user: jumpuser
          key: ~/.ssh/bastion_key
    final_target:
        host: internal-server.corp.local
        user: admin
        key: ~/.ssh/internal_key
```

```csharp
// Implementation
public async Task<bool> ConnectViaBastionAsync(JumpHostConfig jumpHost, TargetConfig target)
{
    // Connect to bastion
    await ConnectWithKeyAsync(jumpHost.Host, jumpHost.User, jumpHost.Key);

    // Port forward through bastion
    var forwardedPort = new ForwardedPortLocal("127.0.0.1", target.Host, 22);
    _client.AddForwardedPort(forwardedPort);
    forwardedPort.Start();

    // Connect to final target via forwarded port
    await ConnectWithKeyAsync("127.0.0.1", target.User, target.Key);

    return true;
}
```

**4. Improved File Operations**

```csharp
// Enhanced file reading for large config files
public async Task<string> ReadFileChunkedAsync(string remotePath, int maxSize = 10_000_000)
{
    using var sftp = new SftpClient(_client.ConnectionInfo);
    await Task.Run(() => sftp.Connect());

    using var stream = sftp.OpenRead(remotePath);
    using var reader = new StreamReader(stream);

    var buffer = new char[4096];
    var sb = new StringBuilder();
    int charsRead;

    while ((charsRead = await reader.ReadAsync(buffer, 0, buffer.Length)) > 0)
    {
        sb.Append(buffer, 0, charsRead);

        if (sb.Length > maxSize)
        {
            Log.Warning($"File {remotePath} exceeds {maxSize} bytes, truncating");
            break;
        }
    }

    return sb.ToString();
}
```

#### CLI Enhancements

```bash
# SSH key authentication
ast scan --target 10.0.0.25 --ssh-key "admin:~/.ssh/id_rsa"

# With sudo password
ast scan --target 10.0.0.25 --ssh "admin:password" --sudo-password "adminSudo123"

# Via bastion host
ast scan --target internal.corp.local \
  --bastion "bastion.corp.local:jumpuser:~/.ssh/bastion_key" \
  --ssh "admin:~/.ssh/internal_key"
```

**Benefits:**

- **Enterprise SSH Access**: Support for bastion hosts
- **Security**: Key-based authentication preferred over passwords
- **Privilege Escalation**: Automatic sudo elevation for privileged checks
- **Large File Support**: Chunked reading for big config files

**Target Release:** v0.2.0

---

### 🔍 Advanced Target OS Detection ✅ COMPLETED

**Ticket:** AST-FEATURE-003
**Priority:** Medium
**Status:** ✅ Shipped in v0.2.0 — `OsDetector.cs`, Phase 0 detection per target (SSH banner + SMB/RDP port heuristics + ICMP TTL fallback)

#### Problem Statement

Currently, OS-specific checks are registered globally:

- Windows checks run only if **Asterion is running on Windows**
- Linux checks run only if **Asterion is running on Linux**

We need **per-target OS detection** to enable:

- Scanning Windows targets from Linux (via WinRM)
- Scanning Linux targets from Windows (via SSH)
- Mixed-OS environments in single scan

#### Planned Implementation

**1. OS Detection Module**

```csharp
// New: src/Asterion/Core/Utils/OsDetector.cs
public class OsDetector
{
    public async Task<TargetOS> DetectOsAsync(string target)
    {
        // Method 1: SMB detection (Windows)
        if (await IsSmbAvailableAsync(target, 445))
        {
            var smbBanner = await GetSmbBannerAsync(target);
            if (smbBanner.Contains("Windows"))
                return TargetOS.Windows;
        }

        // Method 2: SSH detection (Linux/Unix)
        if (await IsSshAvailableAsync(target, 22))
        {
            var sshBanner = await GetSshBannerAsync(target);
            if (sshBanner.Contains("OpenSSH"))
                return TargetOS.Linux;
        }

        // Method 3: TTL-based detection (fallback)
        var ttl = await GetIcmpTtlAsync(target);
        if (ttl <= 64)
            return TargetOS.Linux;
        else if (ttl <= 128)
            return TargetOS.Windows;

        return TargetOS.Unknown;
    }

    private async Task<string> GetSmbBannerAsync(string target)
    {
        // Connect to SMB port 445 and read banner
        using var client = new TcpClient();
        await client.ConnectAsync(target, 445);

        // SMB negotiation to get OS version
        // (Simplified - real implementation uses SMBLibrary)
        return "Windows Server 2019";
    }

    private async Task<int> GetIcmpTtlAsync(string target)
    {
        // Send ICMP ping and read TTL
        var ping = new Ping();
        var reply = await ping.SendPingAsync(target);

        return reply.Options?.Ttl ?? 0;
    }
}
```

**2. Enhanced Orchestrator with Per-Target OS Detection**

```csharp
// Orchestrator.cs enhancement
public async Task ExecuteScanAsync(ScanOptions options)
{
    var targets = ParseTargets(options.Target);

    // NEW: Detect OS for each target
    var targetOsMap = new Dictionary<string, TargetOS>();

    foreach (var target in targets)
    {
        var os = await _osDetector.DetectOsAsync(target);
        targetOsMap[target] = os;

        Log.Information($"Target {target} detected as: {os}");
    }

    // Register checks dynamically per target
    var checks = new List<ICheck>();

    foreach (var target in targets)
    {
        var os = targetOsMap[target];

        // Always add cross-platform checks
        checks.AddRange(RegisterCrossPlatformChecks());

        // Add OS-specific checks
        if (os == TargetOS.Windows || options.WinRmCredentials != null)
        {
            checks.AddRange(RegisterWindowsChecks());
        }

        if (os == TargetOS.Linux || options.SshCredentials != null)
        {
            checks.AddRange(RegisterLinuxChecks());
        }
    }

    // Execute checks...
}
```

**3. CLI Output**

```bash
$ ast scan --target 10.0.0.0/24 --winrm "CORP\admin:pass" --ssh "root:toor"

[Phase 1/5] Target Discovery
  🔍 10.0.0.5 - Windows Server 2019 (SMB banner)
  🔍 10.0.0.10 - Windows 10 (TTL=128)
  🔍 10.0.0.25 - Linux (SSH banner: Ubuntu 22.04)
  🔍 10.0.0.50 - Unknown (no response)

[Phase 2/5] Registering Checks
  ✨ Cross-Platform: 20 checks
  ✨ Windows (2 targets): 15 checks
  ✨ Linux (1 target): 12 checks

[Phase 3/5] Executing Checks...
```

**4. Configuration**

```yaml
# config/defaults.yaml
os_detection:
    enabled: true
    methods:
        - smb_banner # Windows detection
        - ssh_banner # Linux detection
        - ttl_analysis # Fallback
        - nmap_os_scan # Advanced (if nmap available)

    fallback_behavior: "skip" # or "assume_windows" or "assume_linux"
```

#### Benefits

- **Flexible Scanning**: Scan any OS from any OS
- **Automatic Check Selection**: Right checks for right targets
- **Mixed Environments**: Single scan for Windows + Linux infrastructure
- **Accurate Detection**: 90%+ accuracy with multi-method approach

**Target Release:** v0.2.0

---

### 🚀 Better Aggressive Mode ✅ COMPLETED

**Ticket:** AST-FEATURE-004
**Priority:** High
**Status:** ✅ Shipped in v0.2.0 — `AdAggressiveCheck.cs` (AS-REP, delegation, ACLs, AdminCount, LAPS), Linux aggressive privesc checks (Docker socket, systemd units, cred files)

#### Planned Aggressive Mode Enhancements

**1. Windows/Active Directory Checks**

```yaml
aggressive_checks:
    windows_ad:
        - as_rep_roasting:
              description: "Find users without Kerberos pre-authentication"
              check_id: AST-AD-010
              severity: high
              method: "LDAP query for userAccountControl with DONT_REQ_PREAUTH"

        - unconstrained_delegation:
              description: "Computers/users with unconstrained delegation"
              check_id: AST-AD-011
              severity: critical
              method: "LDAP query for TRUSTED_FOR_DELEGATION"

        - weak_acls:
              description: "Weak ACLs on AD objects (GenericAll, WriteDacl)"
              check_id: AST-AD-012
              severity: high
              method: "LDAP query + ACL analysis"

        - admincount_analysis:
              description: "Users with AdminCount=1 (protected by AdminSDHolder)"
              check_id: AST-AD-013
              severity: info
              method: "LDAP query for adminCount attribute"

        - gpo_analysis:
              description: "GPOs with weak permissions"
              check_id: AST-AD-014
              severity: medium
              method: "SMB enumeration of SYSVOL + ACL check"

        - laps_detection:
              description: "LAPS not implemented (local admin password risk)"
              check_id: AST-AD-015
              severity: medium
              method: "LDAP query for ms-Mcs-AdmPwd attribute"

        - bloodhound_data:
              description: "Export data for BloodHound analysis"
              check_id: AST-AD-016
              severity: info
              method: "LDAP enumeration + relationship mapping"
```

**Implementation Example:**

```csharp
// New: src/Asterion/Checks/AdAggressiveCheck.cs
public class AdAggressiveCheck : BaseCheck
{
    public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
    {
        if (options.Mode != ScanMode.Aggressive)
        {
            Log.Information("Skipping AD aggressive checks (safe mode)");
            return new List<Finding>();
        }

        var findings = new List<Finding>();

        // AS-REP Roasting
        findings.AddRange(await CheckAsRepRoastingAsync(targets, options));

        // Unconstrained Delegation
        findings.AddRange(await CheckUnconstrainedDelegationAsync(targets, options));

        // Weak ACLs
        findings.AddRange(await CheckWeakAclsAsync(targets, options));

        return findings;
    }

    private async Task<List<Finding>> CheckAsRepRoastingAsync(List<string> targets, ScanOptions options)
    {
        var findings = new List<Finding>();

        foreach (var target in targets)
        {
            using var ldap = new LdapConnection(target);
            ldap.Bind(options.AuthCredentials);

            // LDAP filter: userAccountControl with DONT_REQ_PREAUTH (0x400000)
            var filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
            var searchRequest = new SearchRequest("DC=corp,DC=local", filter, SearchScope.Subtree, "sAMAccountName");

            var response = (SearchResponse)await Task.Run(() => ldap.SendRequest(searchRequest));

            foreach (SearchResultEntry entry in response.Entries)
            {
                var username = entry.Attributes["sAMAccountName"][0].ToString();

                findings.Add(new Finding
                {
                    Id = "AST-AD-010",
                    Title = $"AS-REP Roastable user: {username}",
                    Severity = Severity.High,
                    Description = $"User '{username}' does not require Kerberos pre-authentication. Attackers can request AS-REP and crack offline.",
                    Evidence = new Evidence
                    {
                        Type = "ldap",
                        Value = $"sAMAccountName: {username}",
                        Context = "User has DONT_REQ_PREAUTH flag set"
                    },
                    Recommendation = $"1. Enable Kerberos pre-authentication:\n   Set-ADUser {username} -KerberosEncryptionType AES256\n2. Review why pre-auth was disabled\n3. Rotate password if compromise suspected"
                });
            }
        }

        return findings;
    }
}
```

**2. Linux Privilege Escalation Checks**

```yaml
aggressive_checks:
    linux_privesc:
        - ssh_enumeration:
              weak_ciphers: true
              weak_kex_algorithms: true
              compression_enabled: true

        - privilege_escalation:
              suid_binaries:
                  - find
                  - vim
                  - nmap
                  - bash
                  - less
                  - more
              sudo_misconfig:
                  - "NOPASSWD: /bin/bash"
                  - "NOPASSWD: /usr/bin/vi"
              writable_systemd: true
              docker_socket: true

        - kernel_security:
              kernel_version_check: true
              known_exploits:
                  - "DirtyCow"
                  - "PwnKit"
                  - "OverlayFS"
              selinux_disabled: true
              apparmor_disabled: true

        - credential_harvesting:
              bash_history: true
              environment_vars: true
              config_files:
                  - "/home/*/.ssh/config"
                  - "/root/.ssh/config"
                  - "/etc/mysql/my.cnf"
                  - "/var/www/html/.env"
```

**Implementation:**

```csharp
// Enhanced: src/Asterion/Checks/PrivEscCheckLinux.cs
public override async Task<List<Finding>> ExecuteAsync(List<string> targets, ScanOptions options)
{
    var findings = new List<Finding>();

    if (options.Mode == ScanMode.Aggressive)
    {
        // Safe mode checks
        findings.AddRange(await CheckDangerousSuidBinariesAsync(targets, options));
        findings.AddRange(await CheckSudoMisconfigAsync(targets, options));

        // AGGRESSIVE mode additions
        findings.AddRange(await CheckKernelExploitsAsync(targets, options));
        findings.AddRange(await CheckCredentialFilesAsync(targets, options));
        findings.AddRange(await CheckDockerSocketAsync(targets, options));
        findings.AddRange(await CheckWritableSystemdAsync(targets, options));
    }

    return findings;
}

private async Task<List<Finding>> CheckKernelExploitsAsync(List<string> targets, ScanOptions options)
{
    var findings = new List<Finding>();

    foreach (var target in targets)
    {
        var ssh = await GetSshConnectionAsync(target, options);

        // Get kernel version
        var kernelVersion = await ssh.ExecuteCommandAsync("uname -r");

        // Check against known vulnerable versions
        var knownExploits = new Dictionary<string, string>
        {
            { "3.13.0", "DirtyCow (CVE-2016-5195)" },
            { "5.8.0", "OverlayFS (CVE-2021-3493)" },
            { "pkexec", "PwnKit (CVE-2021-4034)" }
        };

        foreach (var exploit in knownExploits)
        {
            if (kernelVersion.Contains(exploit.Key))
            {
                findings.Add(new Finding
                {
                    Id = "AST-PRV-010",
                    Title = $"Kernel vulnerable to {exploit.Value}",
                    Severity = Severity.Critical,
                    Evidence = new Evidence { Value = kernelVersion },
                    Recommendation = "1. Update kernel to latest patched version\n2. Reboot system\n3. Review for signs of compromise"
                });
            }
        }
    }

    return findings;
}
```

**3. Expected Results**

| Mode           | Windows Checks | Linux Checks | Network Checks | Duration | Findings |
| -------------- | -------------- | ------------ | -------------- | -------- | -------- |
| **Safe**       | 15             | 12           | 20             | ~40s     | 30-50    |
| **Aggressive** | 25             | 22           | 20             | ~120s    | 80-150   |

#### Benefits

- **Real Value Differentiation**: Aggressive mode provides significantly more checks
- **Penetration Testing Ready**: Checks commonly used in offensive security
- **Configurable Aggression**: Disable specific aggressive checks via config
- **Respects Consent**: Requires verified consent token

**Target Release:** v0.2.0

---

### 💰 AI Cost Tracking & Budget Limits ✅ COMPLETED

**Ticket:** IMPROV-005 _(Shared with Argos Suite)_
**Priority:** Medium
**Status:** ✅ Shipped in v0.2.0 — `AICostTracker.save_to_db()`, `~/.argos/costs.json`, `--ai-budget` flag, `ai_costs` table in argos.db

#### Configuration

```yaml
# config/defaults.yaml
ai:
    budget:
        enabled: true
        max_cost_per_scan: 0.50 # USD
        max_tokens_per_request: 3000
        warn_threshold: 0.80
        abort_on_exceed: true

    tracking:
        log_costs: true
        cost_report: ~/.argos/costs.json
```

#### Runtime Output

```bash
ast scan --target 10.0.0.0/24 --use-ai

[Phase 6/6] AI Analysis...
  ├─ Executive Summary: 1,400 tokens $0.14
  ├─ Technical Guide: 1,750 tokens $0.18
  └─ Total AI Cost: $0.32 / $0.50 budget (64% used)
```

**Benefits:**

- Cost transparency
- Budget enforcement
- Monthly projections
- Enterprise compliance

**Target Release:** v0.2.0

---

### 🌊 AI Streaming Responses ✅ COMPLETED

**Ticket:** IMPROV-006 _(Shared with Argos Suite)_
**Priority:** Low
**Status:** ✅ Shipped in v0.2.0 — `--ai-stream` flag (OpenAI, Anthropic, Ollama)

#### Current vs Streaming Behavior

**Current:**

```bash
[Phase 6/6] AI Analysis...
  ⏳ Generating insights... (user waits 30+ seconds)
  ✓ Analysis complete
```

**Streaming:**

```bash
[Phase 6/6] AI Hardening Analysis...
  [Executive Summary] Analyzing security posture...
  [Executive Summary] ████████░░ 80% - Assessing risks...
  [Executive Summary] ✓ Complete (2,300 chars in 18s)

  [Technical Guide] Generating remediation steps...
  [Technical Guide] ████░░░░░░ 40% - Apache hardening...
  [Technical Guide] ████████░░ 80% - TLS configuration...
  [Technical Guide] ✓ Complete (4,800 chars in 31s)
```

**Benefits:**

- Improved UX (see progress)
- Reduced perceived latency
- Error detection (know immediately if AI stalls)

**Target Release:** v0.2.0

---

### 📊 Enhanced HTML Reporting ✅ COMPLETED

**Ticket:** IMPROV-002 _(Shared with Argos Suite)_
**Priority:** High
**Status:** ✅ Shipped in v0.2.0 — filter bar, CVE/CWE badges, OWASP badges, compliance badges, attack chains section, AI tabs, Risk Score card

#### Planned Improvements

**1. CVE/CWE Badges for Findings**

```html
<!-- Before -->
<tr>
    <td>AST-SMB-003</td>
    <td>SMBv1 enabled</td>
</tr>

<!-- After -->
<tr>
    <td>AST-SMB-003</td>
    <td>
        SMBv1 enabled
        <span class="badge badge-critical">CVE-2017-0143</span>
        <span class="badge">EternalBlue</span>
    </td>
    <td><a href="https://nvd.nist.gov/vuln/detail/CVE-2017-0143">NVD</a></td>
</tr>
```

**2. Configuration Snippets**

```html
<div class="finding">
    <h4>L SMB Signing Not Required</h4>
    <p>Enable SMB signing to prevent man-in-the-middle attacks</p>

    <!-- Windows (GPO) -->
    <pre><code>Computer Configuration � Policies � Windows Settings � Security Settings � Local Policies � Security Options
Microsoft network server: Digitally sign communications (always) = Enabled</code></pre>

    <!-- Windows (Registry) -->
    <pre><code>reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f</code></pre>

    <!-- Samba (Linux) -->
    <pre><code># /etc/samba/smb.conf
[global]
server signing = mandatory
client signing = mandatory</code></pre>
</div>
```

**3. Findings Grouping**

```javascript
// Filter by severity
[Critical: 12] [High: 8] [Medium: 15] [Low: 5] [Info: 20]

// Group by category
   SMB/CIFS Security (8)
   RDP Security (4)
   Active Directory (12)
   Linux Privilege Escalation (6)
   Network Misconfigurations (10)
```

**Benefits:**

- Actionable insights (copy-paste PowerShell/Bash commands)
- Clear vulnerability correlation (CVE/CWE mapping)
- Better organization (filtering and grouping)

**Target Release:** v0.2.0

---

### 📚 Additional v0.2.0 Features ✅ COMPLETED

#### Multi-Credential File Support ✅

```bash
# Load all credentials from a YAML file
ast scan --target 192.168.1.10 --creds-file credentials.yaml

# credentials.yaml format:
auth: "CORP\\admin:P@ssw0rd"
ssh: "root:toor"
winrm: "admin:P@ssw0rd"
sudo_password: "sudopass"
```

CLI flags always override `--creds-file` values.

#### TLS Scanner ✅

- `TlsScanner.cs` — expired certs, self-signed, TLS 1.0/1.1, weak ciphers (`AST-TLS-001..004`)
- Probes: 443, 8443, 636 (LDAPS), 3389 (RDP), 21 (FTPS), 465/587 (SMTPS)

#### SYSVOL / GPP Credential Check ✅

- `SysvolCheck.cs` — SMB enumeration for Group Policy Preferences `cpassword`, legacy creds
- Finding codes: `AST-SYSVOL-001..003`

#### Attack Chain Correlation ✅

- `AttackChainAnalyzer.cs` — 8 multi-step attack vectors with MITRE technique IDs
- `AST-CHAIN-001..008` appear in JSON `attackChains[]` and HTML report section

#### Diff Reports ✅

- `--diff last` — compare current scan against the previous scan for same target
- `--diff <scan_id>` — compare against a specific past scan
- JSON `diff` object: `refScanId`, `new`, `fixed`, `persisting`

#### AI Agent Mode ✅

- `--ai-agent` — LangChain agent with NVD CVE lookup tool; `agentAnalysis` in JSON

#### AI Compare Mode ✅

- `--ai-compare "openai/gpt-4o-mini,anthropic/claude-3-5-haiku-20241022"` — multi-model comparison; `compareResults[]` in JSON

#### CVE Enrichment ✅

- NVD API v2 + CIRCL fallback; `vulnerabilities[]` per finding with CVE/CWE/CVSS data

#### OWASP + Compliance Mapping ✅

- All `AST-*` codes mapped to OWASP Top 10 2021 + CIS / NIST / PCI DSS

#### LDAP Advanced Queries (Moved to v0.3.0)

- Domain trust enumeration, SPN discovery, group membership, delegation chains
- Complexity warranted deferral to v0.3.0

**Breaking Changes:** Finding code prefixes normalized (e.g. `AST-FW-WIN-*` instead of `AST-FW-*`). All JSON reports validated against updated `schema/report.schema.json`.

---

## v0.3.0 - Enterprise & Interactive Features

**Theme:** Usability, Scale, Conversational AI, and Advanced AD Enumeration
**Target Release:** Q3–Q4 2026
**Focus:** Metasploit-style CLI, interactive DB, LDAP advanced queries, BloodHound export, multi-site scanning

---

### 🛠️ Interactive Config Management (Metasploit-Style)

**Ticket:** IMPROV-009 _(Shared with Argos Suite)_
**Priority:** High

#### Vision

Metasploit-style interactive configuration without YAML editing.

#### Interface

```bash
$ ast --show-options

╔═══════════════════════════════════════════════╗
║         ASTERION CONFIGURATION                ║
╠═══════════════════════════════════════════════╣
║ SCAN SETTINGS                                 ║
╠═══════════════════════════════════════════════╣
║ mode             safe          [safe|aggressive]
║ rate_limit.safe  5.0           req/s          ║
║ rate_limit.aggr  10.0          req/s          ║
║ max_workers      5             threads        ║
║ timeout          10            seconds        ║
╠═══════════════════════════════════════════════╣
║ AI SETTINGS                                   ║
╠═══════════════════════════════════════════════╣
║ ai.provider      openai        [openai|anthropic|ollama]
║ ai.model         gpt-4-turbo   string         ║
║ ai.temperature   0.3           0.0-1.0        ║
╠═══════════════════════════════════════════════╣
║ AUTHENTICATION                                ║
╠═══════════════════════════════════════════════╣
║ auth.winrm       (not set)     DOMAIN\user:pass
║ auth.ssh         (not set)     user:pass      ║
║ auth.kerberos    (not set)     user:pass@REALM║
╠═══════════════════════════════════════════════╣
║ DATABASE                                      ║
╠═══════════════════════════════════════════════╣
║ db.path          ~/.argos/     path           ║
║ db.backup        true           bool          ║
╚═══════════════════════════════════════════════╝
```

#### Modify Settings

```bash
# Set authentication
$ ast --set auth.winrm="CORP\admin:P@ssw0rd"
✓ Updated: auth.winrm = CORP\admin:*** (password hidden)

# Save profile
$ ast --save-profile pentest-corp
✓ Saved profile: pentest-corp
  - auth.winrm: CORP\admin:***
  - auth.kerberos: admin:***@CORP.LOCAL
  - mode: aggressive

# Load profile
$ ast --load-profile pentest-corp
✓ Loaded profile: pentest-corp

# Scan using profile
$ ast scan --target 10.0.0.0/24 --profile pentest-corp
```

**Benefits:**

- No YAML editing
- Credential profiles for different environments
- Runtime switching
- Team collaboration (share profiles)

**Target Release:** v0.3.0

---

### 💾 Interactive Database CLI

**Ticket:** IMPROV-011 _(Shared with Argos Suite)_
**Priority:** Medium

#### Management Commands

```bash
# List recent scans
$ ast db scans list --limit 10
ID   Target              Mode        Status     Findings  Date
125  10.0.0.0/24         aggressive  completed  142       2025-11-17 14:30
124  dc01.corp.local     safe        completed  45        2025-11-16 09:15
123  192.168.1.0/24      safe        completed  32        2025-11-15 18:52

# Show scan details
$ ast db scans show 125
╔═══════════════════════════════════════════════╗
║ SCAN #125                                   ║
╠═══════════════════════════════════════════════╣
║ Target:        10.0.0.0/24                    ║
║ Mode:          aggressive                     ║
║ Status:        completed                      ║
║ Started:       2025-11-17 14:30:12            ║
║ Completed:     2025-11-17 14:35:45            ║
║ Duration:      5m 33s                         ║
╠═══════════════════════════════════════════════╣
║ FINDINGS BY SEVERITY                          ║
╠═══════════════════════════════════════════════╣
║ Critical:      22                             ║
║ High:          35                             ║
║ Medium:        48                             ║
║ Low:           24                             ║
║ Info:          13                             ║
║ TOTAL:         142                            ║
╚═══════════════════════════════════════════════╝

# List critical findings
$ ast db findings critical --limit 20
ID    Scan  Severity   Title                              Target
1234  125   critical   SMBv1 enabled (EternalBlue)        10.0.0.5
1235  125   critical   LDAP signing not required          10.0.0.10
1236  124   critical   AS-REP roastable user: sqlservice  dc01.corp.local

# Search findings
$ ast db findings search "delegation"
ID    Scan  Severity   Title                              Target
890   125   high       Unconstrained delegation: WEB01$   10.0.0.15
891   124   medium     Resource-based delegation found    dc01.corp.local

# Export to CSV
$ ast db findings export --format csv --output findings.csv
✓ Exported 3,542 findings to findings.csv
```

**Benefits:**

- No SQL knowledge required
- Rapid auditing across all Argos Suite tools
- Automation-friendly

**Target Release:** v0.3.0

---

### 💬 Interactive AI Chat

**Ticket:** IMPROV-008 _(Enhanced for Asterion)_
**Priority:** Medium

#### Conversational Vulnerability Analysis

````bash
$ ast chat --scan-id 125

Asterion AI Chat (Scan #125: 10.0.0.0/24)
Type 'exit' to quit, 'help' for commands

You: What are the most critical findings?
AI: I found 22 critical findings in scan #125:

    Top 3 by impact:
    1. SMBv1 enabled on 10.0.0.5 (CVE-2017-0143: EternalBlue)
       - Remote code execution vulnerability
       - Public exploit available
       - Wormable (can spread automatically)

    2. LDAP signing not required on dc01.corp.local
       - Man-in-the-middle attacks possible
       - Credential relay attacks

    3. AS-REP roastable user: sqlservice
       - Offline password cracking possible
       - Weak password detected (cracked in 12 seconds)

You: How do I fix the SMBv1 issue?
AI: To disable SMBv1 on 10.0.0.5:

    **Option 1: PowerShell (Recommended)**
    ```powershell
    # Disable SMBv1
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

    # Verify
    Get-SmbServerConfiguration | Select EnableSMB1Protocol

    # Reboot required
    Restart-Computer
    ```

    **Option 2: Registry (Alternative)**
    ```powershell
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
    ```

    **Option 3: Group Policy (Enterprise)**
    - Computer Configuration - Administrative Templates - MS Security Guide
    - Configure SMBv1 client driver startup = Disabled
    - Configure SMBv1 server = Disabled

You: Is there a BloodHound path for the delegation finding?
AI: Yes, for the unconstrained delegation finding on WEB01$:

    BloodHound query:
    ```cypher
    MATCH (c:Computer {name: "WEB01$"})-[:HasSession]->(u:User)
    WHERE c.unconstraineddelegation = true
    RETURN c, u
    ```

    Attack path:
    WEB01$ (unconstrained delegation) Administrator session DC compromise

    Remediation:
    1. Check if unconstrained delegation is necessary (usually not)
    2. Switch to constrained delegation:
       ```powershell
       Set-ADComputer WEB01$ -TrustedForDelegation $false
       Set-ADComputer WEB01$ -PrincipalsAllowedToDelegateToAccount "HTTP/webapp.corp.local"
       ```
````

**Features:**

- Natural language queries
- PowerShell/Bash command generation
- BloodHound integration
- Attack path explanation
- Step-by-step remediation

**Target Release:** v0.3.0

---

### Additional v0.3.0 Features

#### Multi-Site Scanning

```bash
# Scan multiple networks
ast scan --targets-file networks.txt --output json

# networks.txt format:
10.0.0.0/24      # Production network
192.168.1.0/24   # DMZ
172.16.0.0/16    # Internal

# Aggregate report across all networks
```

#### CI/CD Integration

```yaml
# .github/workflows/asterion-scan.yml
name: Network Security Scan

on:
    schedule:
        - cron: "0 2 * * *" # Daily at 2 AM

jobs:
    scan:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v3

            - name: Run Asterion Scan
              run: |
                  docker run --rm \
                    -v $PWD:/reports \
                    -e WINRM_CREDS="${{ secrets.WINRM_CREDS }}" \
                    asterion:latest \
                    ast scan --target 10.0.0.0/24 --output json

            - name: Upload Results
              uses: actions/upload-artifact@v3
              with:
                  name: asterion-report
                  path: reports/*.json

            - name: Fail on Critical Findings
              run: |
                  CRITICAL=$(jq '.summary.critical' reports/*.json)
                  if [ "$CRITICAL" -gt 0 ]; then
                    echo "::error::Found $CRITICAL critical findings"
                    exit 1
                  fi
```

#### REST API Server

```csharp
// FastAPI-style REST API in ASP.NET Core
[ApiController]
[Route("api/v1/scans")]
public class ScanController : ControllerBase
{
    [HttpPost]
    public async Task<ActionResult<ScanResponse>> StartScan([FromBody] ScanRequest request)
    {
        var scanId = await _orchestrator.StartScanAsync(request.ToScanOptions());

        return Accepted(new { scan_id = scanId, status = "running" });
    }

    [HttpGet("{scanId}")]
    public async Task<ActionResult<ScanStatus>> GetScanStatus(int scanId)
    {
        var status = await _database.GetScanStatusAsync(scanId);

        return Ok(status);
    }

    [HttpGet("{scanId}/findings")]
    public async Task<ActionResult<List<Finding>>> GetFindings(int scanId)
    {
        var findings = await _database.GetFindingsAsync(scanId);

        return Ok(findings);
    }
}
```

**Breaking Changes:** None
**Migration:** Automatic

**Target Release:** v0.3.0

---

## v0.4.0 - Intelligence & Automation

**Theme:** Automated Remediation + ML Detection
**Target Release:** Q1 2027
**Focus:** Auto-remediation, distributed scanning, advanced AI

### Planned Features

#### Automated Remediation

- PowerShell DSC integration for Windows auto-fixing
- Ansible playbook generation for Linux
- Safe auto-patching with approval workflow
- Dry-run mode (simulate fixes without applying)
- Rollback capability

#### ML-Based Detection

- Anomaly detection (unusual AD configurations)
- False positive reduction (learn from user feedback)
- Behavioral analysis (detect lateral movement patterns)
- Custom model training on historical scan data

#### Distributed Scanning

- Worker nodes for large-scale environments (1000+ hosts)
- Redis queue for task distribution
- Master/worker architecture
- Progress aggregation

**Breaking Changes:** Configuration schema v2
**Migration:** Automatic upgrade

**Target Release:** v0.4.0

---

## Pro Track (Commercial Product)

**Target Audience:** Enterprise security teams, MSSPs, SOCs
**Pricing Model:** Subscription-based (per-seat or per-network)

**IN PROCESS**

---

## Community Requests

Vote on features at **[GitHub Discussions](https://github.com/rodhnin/asterion-network-minotaur/discussions)**

**Have an idea?** Open a discussion!

---

## Development Philosophy

Asterion development follows these principles:

1. **🔒 Security First**: Never compromise on ethical safeguards
2. **🔐 Privacy by Design**: No telemetry, local-first data
3. **✅ Quality Over Speed**: Stable releases > frequent bugs
4. **👥 Community Driven**: Listen to enterprise needs
5. **🆓 Open Core Model**: Core features free forever
6. **🧪 Testing First**: No release without comprehensive validation

### Commitments

- ✅ **Quarterly feature releases** with new capabilities
- ✅ **Open development** with public roadmap
- ✅ **Responsive support** on GitHub (48h response)

---

## Get Involved

**Questions about the roadmap?**
Open a discussion: https://github.com/rodhnin/asterion-network-minotaur/discussions

**Want to contribute?**
See CONTRIBUTING.md

**Need a feature urgently?**
Consider Pro Track or sponsor the project

---

_Last updated: May 2026_
_Roadmap version: 2.0 (v0.2.0)_
