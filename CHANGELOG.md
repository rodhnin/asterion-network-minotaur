# Changelog

All notable changes to Asterion will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2025-11

### Added

-   🎉 Initial release of Asterion Network Security Auditor
-   Cross-platform support (Windows x64 + Linux x64)
-   Core CLI with `System.CommandLine`
-   Basic host discovery and port scanning
-   SMB/CIFS security checks:
    -   AST-SMB-001: Anonymous share access detection
    -   AST-SMB-002: SMB signing requirement check
    -   AST-SMB-003: SMBv1 protocol detection
    -   AST-SMB-004: NTLMv1 authentication detection
-   RDP security checks:
    -   AST-RDP-001: Network Level Authentication (NLA) enforcement
-   LDAP/Active Directory checks:
    -   AST-LDAP-001: Anonymous bind detection
    -   AST-AD-001: LDAP signing requirement check
-   SNMP security checks:
    -   AST-SNMP-001: Default community string detection
-   DNS checks:
    -   AST-NET-002: LLMNR/NetBIOS detection
-   Consent token system:
    -   HTTP file verification (/.well-known/)
    -   DNS TXT record verification
    -   Token generation and validation
-   JSON report generation (compatible with Argos Suite schema)
-   HTML report generation with Minotaur branding
-   SQLite database integration (shared with Argus/Hephaestus/Pythia)
-   Rate limiting (5 req/s safe mode, 10 req/s aggressive mode)
-   Structured logging with Serilog
-   Configuration via YAML (defaults.yaml)
-   Documentation:
    -   README.md with quick start guide
    -   AI_INTEGRATION.md
    -   CONSENT.md
    -   DATABASE_GUIDE.md
    -   ETHICS.md
    -   NETWORK_CHECKS.md
    -   ROADMAP.md

### Security

-   Safe mode by default (non-intrusive)
-   Aggressive mode requires explicit consent verification
-   No exploitation of vulnerabilities
-   No credential brute forcing
-   Rate limiting to prevent DoS

---

## Release Notes

### v0.1.0 - MVP Release

This is the **Minimum Viable Product** release of Asterion, the fourth and final component of the Argos Suite.

**What's Working:**

-   ✅ Cross-platform execution (Windows/Linux)
-   ✅ Network discovery (CIDR ranges, single hosts, domains)
-   ✅ Core protocol checks (SMB, RDP, LDAP, SNMP, DNS)
-   ✅ JSON/HTML reporting
-   ✅ Database integration with Argos Suite
-   ✅ Consent token system
-   ✅ Ethical scanning (safe mode default)

**Known Limitations:**

-   ⚠️ Windows-specific checks not yet implemented (firewall, registry, AD policies)
-   ⚠️ Linux-specific checks not yet implemented (iptables, Samba configs, SSH hardening)
-   ⚠️ No multi-threading (scans are sequential)
-   ⚠️ AI analysis requires Python bridge (not embedded)
-   ⚠️ No GUI (CLI only)

**Next Steps:**
See [ROADMAP.md](docs/ROADMAP.md) for planned features in v0.2.0 and beyond.

---

## License

This project is licensed under the MIT License. See `LICENSE` file for details.

---

## Disclaimer

**IMPORTANT:** This tool is for **authorized security testing only**.

-   Only scan systems you own or have explicit written permission to test
-   Unauthorized access is illegal (CFAA, Computer Misuse Act, etc.)
-   The authors assume no liability for misuse
-   Always practice responsible disclosure

See `docs/ETHICS.md` for complete ethical guidelines.

---

**Generated:** November 22, 2025  
**Version:** 0.1.0  
**Status:** Production Release  
**Author:** Rodney Dhavid Jimenez Chacin (rodhnin)

[0.1.0]: https://github.com/rodhnin/asterion-network-minotaur/releases/tag/v0.1.0
