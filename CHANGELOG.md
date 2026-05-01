# Changelog

All notable changes to Asterion will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-04

### Added

#### Remote Windows Auditing (WinRM)

- New `WinRmConnectionManager.cs` — pure HTTP/NTLMv2 WinRM client (no external dependencies — custom NTLM Type1/Type2/Type3 + MS-WSMV session encryption)
- New `WinRmChecks.cs` — PowerShell-based remote Windows checks (firewall, registry, services, AD, privesc)
- New CLI flag `--winrm "DOMAIN\user:pass"` — enables remote Windows checks on any target
- Checks enabled via WinRM: firewall profiles, registry keys (NTLMv1/UAC/WDigest/LSA), services (unquoted paths, writable dirs), AD policy (GPO, delegation, IIS, SQL, Exchange)
- WinRM checks produce their own finding codes: `AST-FW-WIN-*`, `AST-REG-WIN-*`, `AST-SVC-WIN-*`, `AST-AD-WIN-*`, `AST-IIS-WIN-*`, `AST-SQL-WIN-*`, `AST-EXCH-WIN-*`, `AST-PRIV-WIN-*`

#### Enhanced SSH Support

- New CLI flag `--ssh-key "user:/path/to/key"` — SSH key-based authentication
- New CLI flag `--sudo-password "pass"` — sudo elevation for privileged Linux checks
- New CLI flag `--bastion "host:user:key"` — multi-hop SSH via jump/bastion host
- SSH checks now use `--sudo-password` for root-level enumeration on non-root accounts

#### OS Detection per Target

- New `OsDetector.cs` — per-target OS detection before check execution
- Detection heuristics: SSH banner (`OpenSSH` → Linux), SMB/RDP ports → Windows, ICMP TTL fallback
- Console output shows detected OS per target during scan (Phase 0)
- Orchestrator routes checks per target OS instead of global host platform

#### Aggressive Mode Enhancements (AD + Linux)

- New `AdAggressiveCheck.cs` — deep Active Directory enumeration (aggressive mode only):
    - `AST-AD-010`: AS-REP Roasting — accounts with `DONT_REQ_PREAUTH`
    - `AST-AD-011`: Unconstrained delegation — `TRUSTED_FOR_DELEGATION`
    - `AST-AD-012`: Weak ACLs — `GenericAll`/`WriteDACL` on AD objects
    - `AST-AD-013`: AdminCount=1 analysis — shadow admin accounts
    - `AST-AD-015`: LAPS not deployed — `ms-Mcs-AdmPwd` attribute absent
- New Linux aggressive checks in `PrivEscCheckLinux.cs`:
    - `AST-PRIV-LNX-006`: Docker socket accessible (`/var/run/docker.sock`)
    - `AST-PRIV-LNX-007`: Writable systemd unit files
    - `AST-PRIV-LNX-008`: Credential files accessible (`.bash_history`, `.env`, `my.cnf`)

#### TLS Scanner

- New `TlsScanner.cs` — cross-platform TLS/SSL security scanner
    - `AST-TLS-001`: Expired certificate
    - `AST-TLS-002`: Self-signed certificate
    - `AST-TLS-003`: TLS 1.0/1.1 enabled (deprecated)
    - `AST-TLS-004`: Weak cipher suites
- Probes ports: 443, 8443, 636 (LDAPS), 3389 (RDP), 21 (FTPS), 465/587 (SMTPS)

#### SYSVOL / GPP Credential Check

- New `SysvolCheck.cs` — SMB enumeration of SYSVOL for Group Policy Preferences passwords
    - `AST-SYSVOL-001`: GPP `cpassword` found in SYSVOL (plaintext-reversible)
    - `AST-SYSVOL-002`: Legacy scheduled task credentials in SYSVOL
    - `AST-SYSVOL-003`: Readable SYSVOL for unauthenticated users

#### Attack Chain Correlation

- New `AttackChainAnalyzer.cs` — correlates individual findings into multi-step attack paths
    - `AST-CHAIN-001`: NTLM Relay → Lateral Movement chain
    - `AST-CHAIN-002`: Kerberoasting → Domain Admin escalation
    - `AST-CHAIN-003`: Unauthenticated AD enumeration → GPP credential harvest
    - `AST-CHAIN-004`: WDigest + weak NTLM → plaintext credential dump
    - `AST-CHAIN-005`: SSH root login + weak ciphers → privileged interception
    - `AST-CHAIN-006`: Cleartext LDAP + no signing → AD credential relay
    - `AST-CHAIN-007`: Local PrivEsc → WDigest dump → Domain compromise
    - `AST-CHAIN-008`: SNMP default community + write access → infrastructure reconfiguration
- Attack chains appear in JSON `attackChains[]` and HTML report section

#### Diff Reports (`--diff`)

- New CLI flag `--diff last` — compare current scan against the last scan for the same target
- New CLI flag `--diff <scan_id>` — compare against a specific scan ID
- JSON output includes `diff` object with `refScanId`, `new`, `fixed`, and `persisting` finding arrays
- HTML report shows diff badges (NEW / FIXED) on findings

#### Multi-Credential File (`--creds-file`)

- New CLI flag `--creds-file /path/to/creds.yaml` — load all credentials from a YAML file
- Supports keys: `auth`, `ssh`, `winrm`, `ssh_key`, `sudo_password`, `bastion`
- CLI flags take precedence over `--creds-file` values when both are specified

#### AI Cost Tracking & Budget

- AI cost tracker now saves per-analysis records to `~/.argos/argos.db` table `ai_costs`
- AI cost summary also appended to `~/.argos/costs.json` (shared Argos Suite file)
- New CLI flag `--ai-budget <float>` — abort AI analysis if estimated cost exceeds the budget
- Cost breakdown shown in CLI output after AI phase: tokens in/out, cost per analysis, total

#### AI Streaming (`--ai-stream`)

- New CLI flag `--ai-stream` — stream AI tokens to stdout in real-time as they are generated
- Works with OpenAI and Anthropic providers (Ollama streaming also supported)

#### AI Agent Mode (`--ai-agent`)

- New CLI flag `--ai-agent` — enables LangChain agent with NVD CVE lookup tool
- Agent performs autonomous CVE searches for detected software versions
- JSON output includes `agentAnalysis` field with agent reasoning trace

#### AI Compare Mode (`--ai-compare`)

- New CLI flag `--ai-compare "provider1/model1,provider2/model2"` — run analysis with multiple models and compare
- JSON output includes `compareResults[]` array with per-model outputs and costs

#### CVE Enrichment

- `scripts/ai_analyzer.py` now enriches findings with CVEs from NVD API v2 + CIRCL fallback
- Findings with known software (openssh, vsftpd, samba, net-snmp, bind, etc.) get `vulnerabilities[]` populated
- CVE data includes: `cve_id`, `title`, `description`, `link`, `cvss_score`, `cwe_id`, `cwe_name`

#### OWASP & Compliance Mapping

- `scripts/ai_analyzer.py` maps every finding to OWASP Top 10 2021 category (`owasp` field)
- Compliance framework mapping: CIS Controls, NIST SP 800-53, PCI DSS (`compliance` field)
- All finding codes `AST-*` mapped to OWASP A01–A09

#### Enhanced HTML Reports

- Filter bar by severity and category (cross-platform / Windows / Linux)
- CVE/CWE badges on findings with `vulnerabilities[]`
- OWASP category badges on all findings
- Compliance framework badges (CIS / NIST / PCI)
- Expandable evidence sections per finding
- Attack chains section with MITRE technique IDs
- AI tabs: Standard / Agent / Compare (tabs shown even when AI not run)
- Risk Score card in overview summary

#### JSON Schema Updates

- `findings[]` now includes: `owasp`, `vulnerabilities[]`, `cvss`, `compliance`
- Top-level report includes: `attackChains[]`, `diff`, `riskScore`
- All reports validated against `schema/report.schema.json`

#### Docker Improvements

- Environment variable standardized to `AI_API_KEY` (replaces separate `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`)
- `docker/docker-compose.yml` updated to use `AI_API_KEY`
- `docker/.env.example` updated accordingly
- `docker/compose.testing.yml` — new file for lab/testing deployments with vulnerable targets

#### Infrastructure / Core

- `ScanOptions.cs` — new fields: `WinRmCredentials`, `SshKeyPath`, `SudoPassword`, `BastionHost`, `DiffMode`, `DiffScanId`, `AiBudget`, `AiStream`, `AiAgent`, `AiCompare`, `CredsFile`
- `Database.cs` — new `InsertAiCostAsync()`, scan HTML path update via `UpdateScanHtmlPathAsync()`
- `ReportBuilder.cs` — diff calculation, attack chain serialization, AI tab scaffolding
- `ai_analyzer.py` — `max_tokens` raised to 6144; `AICostTracker.save_to_db()` added; `AI_API_KEY` is the sole recognized environment variable (no OPENAI_API_KEY / ANTHROPIC_API_KEY fallback)
- Default AI model changed to `gpt-4o-mini-2024-07-18`

### Changed

- Finding codes normalized: Windows-specific checks now use `AST-FW-WIN-*`, `AST-REG-WIN-*`, `AST-PRIV-WIN-*`, `AST-SSH-LNX-*`, `AST-FW-LNX-*`, `AST-NFS-LNX-*`, `AST-SAMBA-LNX-*`, `AST-PRIV-LNX-*` (previously `AST-FW-*`, `AST-WIN-*`, `AST-LNX-*`, `AST-SSH-*`, `AST-NFS-*`, `AST-PRV-*`)
- `LDAP-002` / `LDAP-003` added for channel binding and LDAPS checks
- Windows firewall and registry checks now default to WinRM when not running locally on Windows
- `--output` / `-o` accepts `json`, `html`, `both` (was `json`, `html`)
- All reports now include `riskScore` (float 0–10) computed from finding severity distribution
- Orchestrator now runs OS detection as Phase 0 before dispatching checks

### Fixed

- AI truncation at 2000 tokens — increased to 6144 max output tokens
- HTML report AI tabs showing empty content when `max_tokens` was too low
- WinRM checks silently skipped when no WinRM manager connected — now shows explicit skip message
- Consent SSH verification path on Windows: now correctly checks `C:\Consent\{token}.txt`
- Diff calculation producing false "fixed" findings when baseline scan covered different targets
- DB orphan findings (scan_id=NULL) from aborted scans — cleanup on restart

---

## [0.1.0] - 2025-11

### Added

- Initial release of Asterion Network Security Auditor
- Cross-platform support (Windows x64 + Linux x64 + macOS x64)
- Core CLI with `System.CommandLine` — `scan`, `consent generate`, `consent verify`, `version`
- Port scanning with service banner grabbing
- Target parsing: CIDR notation, IP ranges, single IPs, hostnames, comma-separated lists
- Multi-threading: 1–20 concurrent worker threads
- Rate limiting: 5 req/s (safe), 10 req/s (aggressive)
- **SMB/CIFS Security** (AST-SMB-001..005): anonymous shares, signing, SMBv1/EternalBlue, NTLMv1, writable shares
- **RDP Security** (AST-RDP-001..004): NLA enforcement, encryption level, internet exposure, default port
- **LDAP/Active Directory** (AST-LDAP-001, AST-AD-001..005): anonymous bind, signing, channel binding, password policy, password never expires, pre-Windows 2000 access
- **Kerberos** (AST-KRB-001..003): AS-REP roasting, Kerberoasting, excessive ticket lifetime
- **SNMP** (AST-SNMP-001..003): default community strings, SNMPv1/v2c, write access
- **DNS/NetBIOS** (AST-NET-002..003): LLMNR/NetBIOS poisoning, mDNS service exposure
- **FTP** (AST-FTP-001..003): anonymous access, plaintext protocol, banner disclosure
- **Windows Firewall** (local): disabled profiles, permissive rules, exposed RDP
- **Windows Registry** (local): LM/NTLMv1, UAC, AutoAdminLogon, LSA protection
- **AD Policies** (local): GPO changes, unconstrained delegation, AdminSDHolder
- **Windows Services** (local): writable executables, unquoted paths, AlwaysInstallElevated
- **Linux Firewall** (SSH): iptables/nftables/UFW state
- **NFS Security** (SSH): `no_root_squash`, world-accessible exports, NFSv3
- **SSH Configuration** (SSH): root login, password auth, weak ciphers, default port
- **Linux PrivEsc** (SSH): SUID binaries, world-writable dirs, sudo misconfig, /etc/shadow
- Consent token system: HTTP `/.well-known/`, DNS TXT record, SSH file placement
- JSON + HTML reports (Minotaur theme: red #c0392b / orange / purple)
- SQLite database `~/.argos/argos.db` (shared with Argos Suite, `tool='asterion'`)
- AI analysis via Python bridge (`scripts/ai_analyzer.py`): OpenAI, Anthropic, Ollama
- Docker production deployment (`docker/Dockerfile`, `docker/docker-compose.yml`)
- Serilog structured logging to file and console
- YAML configuration (`config/defaults.yaml`) with ENV + CLI overrides

### Security

- Safe mode by default — all checks are non-intrusive and non-exploiting
- Aggressive mode requires verified consent token before execution
- No credential brute forcing
- No exploitation of vulnerabilities — detection only
- Rate limiting to prevent unintentional DoS

---

## Release Notes

### v0.2.0 — Remote Auditing & Enhanced Detection

**What's New:**

- ✅ WinRM remote Windows checks — audit Windows servers from Linux/macOS
- ✅ SSH key auth + sudo elevation + bastion host support
- ✅ Per-target OS detection (Phase 0) — no more platform-global routing
- ✅ Aggressive AD mode: AS-REP, delegation, weak ACLs, LAPS, AdminCount
- ✅ TLS scanner across 6+ service ports
- ✅ SYSVOL/GPP credential exposure detection
- ✅ Attack chain correlation (8 multi-step vectors with MITRE IDs)
- ✅ Diff reports (`--diff last` / `--diff <id>`) — track security regression
- ✅ Multi-credential YAML file (`--creds-file`)
- ✅ AI cost tracking to DB + costs.json; budget enforcement (`--ai-budget`)
- ✅ AI streaming (`--ai-stream`), agent mode (`--ai-agent`), compare mode (`--ai-compare`)
- ✅ CVE enrichment via NVD API v2 for detected software versions
- ✅ OWASP Top 10 + CIS/NIST/PCI compliance mapping on all findings
- ✅ Enhanced HTML with filter bar, CVE/CWE badges, attack chains, AI tabs
- ✅ Docker container verified with WinRM + SSH + AI end-to-end

### v0.1.0 — MVP Release (November 2025)

First production release. Core network protocol scanning (SMB, RDP, LDAP, Kerberos, SNMP, DNS, FTP), basic Windows/Linux checks via local execution or SSH, consent system, JSON/HTML reports, AI bridge, shared Argos Suite database.

---

## License

MIT License. See `LICENSE` file for details.

---

## Disclaimer

**IMPORTANT:** This tool is for **authorized security testing only**.

- Only scan systems you own or have explicit written permission to test
- Unauthorized access is illegal (CFAA, Computer Misuse Act, and similar laws worldwide)
- The authors assume no liability for misuse
- Always practice responsible disclosure

See `docs/ETHICS.md` for complete ethical guidelines.

---

**Generated:** May 2026
**Version:** 0.2.0
**Status:** Production Release
**Author:** Rodney Dhavid Jimenez Chacin (rodhnin)

[0.2.0]: https://github.com/rodhnin/asterion-network-minotaur/releases/tag/v0.2.0
[0.1.0]: https://github.com/rodhnin/asterion-network-minotaur/releases/tag/v0.1.0
