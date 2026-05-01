# Ethics & Legal Framework

> **Responsible Security Testing**: Asterion is a powerful network security auditing tool. With great power comes great responsibility. This document outlines the legal and ethical framework for using Asterion safely and responsibly.

## Table of Contents

- [Legal Framework](#legal-framework)
    - [United States](#united-states)
    - [United Kingdom](#united-kingdom)
    - [European Union](#european-union)
    - [Other Jurisdictions](#other-jurisdictions)
- [Ethical Guidelines](#ethical-guidelines)
- [Authorization Requirements](#authorization-requirements)
- [Consent Token System](#consent-token-system)
- [Responsible Disclosure](#responsible-disclosure)
- [Safe vs Aggressive Mode](#safe-vs-aggressive-mode)
- [Red Lines (Never Do This)](#red-lines-never-do-this)
- [Case Studies](#case-studies)
- [Best Practices](#best-practices)
- [Legal Disclaimer](#legal-disclaimer)

---

## Legal Framework

### United States

#### Computer Fraud and Abuse Act (CFAA) - 18 U.S.C.

**Summary:** Federal law criminalizing unauthorized access to computer systems.

**Key Provisions:**

- **(a)(2):** Unauthorized access to obtain information from financial institutions, government systems, or protected computers
- **(a)(5):** Intentional unauthorized access causing damage (including security testing without permission)
- **(a)(7):** Extortion through threats to damage computer systems

**Penalties:**

- First offense: Up to **1 year** imprisonment + fines
- Repeat offenses: Up to **10 years** imprisonment + fines
- Financial damage > $5,000: Up to **20 years** imprisonment

**Relevant Case Law:**

1. **United States v. Morris (1991)** - _First CFAA conviction_
    - Robert Morris released the Morris Worm (1988)
    - Claimed it was "research" to measure internet size
    - Convicted: Intent to access without authorization
    - **Lesson:** Good intentions don't excuse unauthorized access

2. **United States v. Kane (2011)** - _Authorized access + exceeding authorization_
    - Employee accessed competitor's website to gather intelligence
    - Company policy prohibited competitive intelligence gathering
    - Convicted: Exceeding authorized access
    - **Lesson:** Authorization must be explicit, not assumed

3. **United States v. Nosal (2016)** - _"Exceeding authorized access"_
    - Employee accessed company database after resignation
    - Used former colleague's credentials
    - Convicted: Exceeding authorized access
    - **Lesson:** Past authorization doesn't equal current authorization

**Asterion Implications:**

-   - Scanning ANY system without explicit written authorization is illegal
-   - "Bug bounty program exists" ` authorization (must comply with program rules)
-   - "Public-facing service" ` permission to scan
-   - Consent token system provides proof of authorization

**References:**

- [18 U.S.C. 1030 - Full Text](https://www.law.cornell.edu/uscode/text/18/1030)
- [DOJ Computer Crime Manual](hhttps://www.justice.gov/d9/criminal-ccips/legacy/2015/01/14/ccmanual_0.pdf)

---

### United Kingdom

#### Computer Misuse Act 1990

**Summary:** UK law criminalizing unauthorized access to computer systems.

**Key Provisions:**

- **Section 1:** Unauthorized access to computer material (max **2 years**)
- **Section 2:** Unauthorized access with intent to commit further offenses (max **5 years**)
- **Section 3:** Unauthorized modification of computer material (max **10 years**)
- **Section 3ZA:** Unauthorized acts causing serious damage (max **life imprisonment**)

**Notable Cases:**

1. **R v. Lennon (2006)** - _DDoS as "unauthorized modification"_
    - Sent 5 million emails to MP's account (email bomb)
    - Convicted under Section 3 (unauthorized modification)
    - **Lesson:** Rate limiting bypass = unauthorized modification

2. **R v. Mangham (2012)** - _Facebook hack_
    - UK national hacked Facebook to find security flaws
    - Claimed it was "ethical hacking"
    - Sentenced: **8 months** imprisonment
    - **Lesson:** No authorization = crime, even for "security research"

**Asterion Implications:**

- Scanning UK systems without authorization violates CMA 1990
- Aggressive mode (exploitation checks) = unauthorized modification
- Rate limiting bypass = potential Section 3 violation
- Consent token system demonstrates authorization

**References:**

- [Computer Misuse Act 1990 - Full Text](https://www.legislation.gov.uk/ukpga/1990/18/contents)
- [CPS Guidance on Computer Misuse](https://www.cps.gov.uk/legal-guidance/computer-misuse)

---

### European Union

#### General Data Protection Regulation (GDPR)

**Summary:** EU data protection law (applies to processing personal data of EU residents).

**Relevant Articles:**

- **Article 5:** Principles of data processing (lawfulness, fairness, transparency)
- **Article 6:** Lawful basis for processing (consent, legitimate interest)
- **Article 32:** Security of processing (appropriate technical measures)
- **Article 33:** Data breach notification (within **72 hours**)

**Security Testing Implications:**

- Security testing is a "legitimate interest" (Article 6(1)(f))
- Identifying vulnerabilities = fulfilling Article 32 obligations
- Unauthorized scanning = unlawful processing if personal data accessed
- If breach discovered: Must notify DPA within 72 hours

**References:**

- [GDPR Full Text](https://gdpr-info.eu/)
- [ICO Guidance on Security Testing](https://ico.org.uk/for-organisations/guide-to-data-protection/)

#### Network and Information Systems (NIS) Directive

**Summary:** EU cybersecurity law requiring operators of essential services to implement security measures.

**Implications for Security Testing:**

- Operators must conduct regular security assessments
- Security testing is mandatory for essential services
- Unauthorized penetration testing = criminal offense in most EU states

---

### Other Jurisdictions

#### Canada - Criminal Code Section 342.1

**Unauthorized use of computer:** Up to **10 years** imprisonment

#### Australia - Criminal Code Act 1995 (Cth)

**Unauthorized access:** Up to **10 years** imprisonment

#### India - Information Technology Act 2000

**Section 43:** Unauthorized access (civil penalty up to **�1 crore**)
**Section 66:** Computer hacking (up to **3 years** + fine)

#### Japan - Unauthorized Computer Access Law (1999)

**Unauthorized access:** Up to **3 years** or fine up to **�1,000,000**

**Global Principle:** Nearly every jurisdiction criminalizes unauthorized computer access. Always obtain written authorization.

---

## Ethical Guidelines

### Core Principles

1. **Do No Harm**
    - Minimize impact on target systems
    - Avoid service disruption or data loss
    - Respect production environments

2. **Obtain Authorization**
    - Written permission from system owner
    - Clear scope definition (IP ranges, domains)
    - Documented consent (proof of authorization)

3. **Respect Privacy**
    - Don't access personal data unnecessarily
    - Don't exfiltrate sensitive information
    - Follow data minimization principles

4. **Responsible Disclosure**
    - Report vulnerabilities to system owners
    - Allow reasonable time for remediation (90 days typical)
    - Don't publicly disclose until patched

5. **Professional Conduct**
    - Maintain confidentiality
    - Document all actions (audit trail)
    - Follow industry standards (OWASP, SANS, CIS)

### Security Testing Hierarchy

```
╔══════════════════════════════════════════════════════════╗
║ ALWAYS ETHICAL                                           ║
║ - Own systems you control                                ║
║ - Authorized penetration testing engagements             ║
║ - Bug bounty programs (within rules)                     ║
║ - Capture The Flag (CTF) competitions                    ║
║ - Vulnerable-by-design lab environments                  ║
╚══════════════════════════════════════════════════════════╝
                          ↓
╔══════════════════════════════════════════════════════════╗
║ ETHICAL WITH CONSENT                                     ║
║ - Client systems (with written authorization)            ║
║ - Employer systems (with IT approval)                    ║
║ - Research projects (with ethics board approval)         ║
╚══════════════════════════════════════════════════════════╝
                          ↓
╔══════════════════════════════════════════════════════════╗
║ GRAY AREA (Proceed with Extreme Caution)                 ║
║ - Public bug bounty programs (follow rules exactly)      ║
║ - Security research on own purchased products            ║
║ - Disclosure without vendor coordination                 ║
╚══════════════════════════════════════════════════════════╝
                          ↓
╔══════════════════════════════════════════════════════════╗
║ NEVER ETHICAL                                            ║
║ - Unauthorized scanning of third-party systems           ║
║ - Exploitation without permission                        ║
║ - Data exfiltration for personal gain                    ║
║ - Ransomware, extortion, or blackmail                    ║
║ - Selling exploits to malicious actors                   ║
╚══════════════════════════════════════════════════════════╝
```

---

## Authorization Requirements

### Minimum Authorization Documentation

Before running Asterion, you **MUST** have:

1. **Written Authorization** (email, contract, or statement of work)
    - System owner's name and signature
    - Date range for testing
    - Explicit scope (IP ranges, domains, services)
    - Approval for aggressive testing (if applicable)
    - Emergency contact information

2. **Technical Consent Verification**
    - Asterion consent token verified on target domain
    - Proof file saved: `~/.argos/consent_proofs/`
    - Database record: `consent_tokens` table

3. **Scope Definition**
    - **In-Scope:** Explicitly authorized targets
    - **Out-of-Scope:** Third-party services, CDNs, shared hosting
    - **Rules of Engagement:** Testing hours, rate limits, excluded checks

### Example Authorization Letter

```
AUTHORIZATION FOR SECURITY TESTING

Date: January 17, 2025
To: [Your Name/Company]
From: [Client Name/Company]

I, [Authorized Representative], hereby authorize [Your Name/Company] to conduct
security testing of the following systems:

Scope:
- Domain: example.com
- IP Ranges: 192.168.1.0/24, 10.0.0.0/16
- Services: SMB, RDP, LDAP, HTTP/HTTPS, SSH

Testing Period: January 17, 2025 - January 31, 2025

Testing Methods Authorized:
- Passive reconnaissance (safe mode)
- Vulnerability scanning (aggressive mode)
- Exploitation of identified vulnerabilities
- Credential testing (with provided test accounts)

Restrictions:
- Testing hours: Monday-Friday, 9am-5pm EST
- No DoS attacks
- No data exfiltration beyond proof-of-concept
- Immediately report critical vulnerabilities

Emergency Contact:
Name: [IT Manager]
Phone: [Phone Number]
Email: [Email Address]

Signature: ___________________________
Name: [Authorized Representative]
Title: [Chief Information Officer]
Date: January 17, 2025
```

---

## Consent Token System

### Purpose

Asterion's consent token system provides **cryptographic proof of authorization**:

1. **Legal Protection:** Demonstrates due diligence in obtaining consent
2. **Audit Trail:** Proof files stored in `~/.argos/consent_proofs/`
3. **Accident Prevention:** Prevents scanning wrong target due to typos
4. **Rate Limiting:** Enforces responsible scanning practices

### When Consent is Required

| Scenario                      | Consent Required? | Rationale                                        |
| ----------------------------- | ----------------- | ------------------------------------------------ |
| `--mode safe` (passive recon) | No                | Non-intrusive, similar to web browsing           |
| `--mode aggressive`           | Yes               | Exploits vulnerabilities, may disrupt services   |
| `--use-ai` (AI analysis)      | Yes               | Generates detailed reports that may be sensitive |

### Implementation

**See:** `docs/CONSENT.md` for full technical details

**Quick Reference:**

```bash
# 1. Generate token
ast consent generate --domain example.com

# 2. Verify ownership (HTTP, DNS, or SSH)
ast consent verify --method http --domain example.com --token <token>

# 3. Scan (consent automatically checked)
ast scan --mode aggressive --target example.com
```

---

## Responsible Disclosure

### 90-Day Disclosure Timeline (Industry Standard)

```
Day 0:   Vulnerability discovered
Day 1:   Initial report to vendor
Day 7:   Vendor acknowledges receipt
Day 30:  Vendor provides initial assessment
Day 60:  Vendor provides patch timeline
Day 90:  Public disclosure (with or without patch)
```

### Disclosure Process

1. **Report to Vendor**
    - Use official security contact (security@example.com)
    - Provide: CVE details, proof-of-concept, impact assessment
    - Request: Acknowledgment within 7 days

2. **Coordinate Timeline**
    - Agree on disclosure date
    - Typical: 90 days from initial report
    - Critical vulnerabilities: May negotiate shorter timeline

3. **Public Disclosure**
    - After patch available OR 90 days (whichever comes first)
    - Publish technical details, remediation steps
    - Credit vendor for cooperation (if applicable)

### Exceptions (Immediate Disclosure)

- **Active exploitation in the wild**
- **Vendor unresponsive for 90+ days**
- **Vendor refuses to patch**
- **Public safety at risk**

### Asterion Disclosure Workflow

```bash
# 1. Run scan
ast scan --mode aggressive --target example.com -o report.json

# 2. Generate disclosure report
# (Extract critical/high findings from JSON)
jq '.findings[] | select(.severity=="critical" or .severity=="high")' report.json > disclosure.json

# 3. Send to vendor
# Email report.json to security@example.com
# Include: Impact, remediation, 90-day disclosure timeline

# 4. Track disclosure
# Add note to database
sqlite3 ~/.argos/argos.db "UPDATE scans SET notes='Disclosed to vendor 2025-01-17' WHERE scan_id=42;"
```

---

## Safe vs Aggressive Mode

### Safe Mode (Default)

**Characteristics:**

- Passive reconnaissance only
- No exploitation attempts
- No credential testing
- Low rate limiting (5 req/s)
- **No consent token required**

**Techniques:**

- SMB enumeration (shares, version)
- LDAP enumeration (domain users, groups)
- RDP capability detection
- DNS/NetBIOS queries
- Banner grabbing

**Legal Status:** Generally permissible (similar to web browsing)

**Use Cases:**

- Initial reconnaissance
- Asset discovery
- Service enumeration
- Compliance checks

---

### Aggressive Mode

**Characteristics:**

- Active exploitation checks
- Credential validation
- Privilege escalation attempts
- Higher rate limiting (10 req/s)
- **Consent token REQUIRED**

**Techniques:**

- AS-REP roasting (Kerberos pre-auth)
- Kerberoasting (service account extraction)
- SMB relay attacks
- LDAP injection
- Credential spraying
- ACL abuse detection
- Kernel exploit checks

**Legal Status:** Requires explicit authorization

**Use Cases:**

- Penetration testing
- Red team assessments
- Advanced threat simulation
- Compliance audits (PCI-DSS, HIPAA)

---

## Red Lines (Never Do This)

### 1. Unauthorized Access

L **Never** scan systems without written authorization
L **Never** assume "public-facing" = "authorized"
L **Never** test bug bounty programs without reading rules
L **Never** use Asterion for competitive intelligence

### 2. Service Disruption

L **Never** conduct DoS attacks
L **Never** delete or modify data
L **Never** crash production services
L **Never** exceed agreed rate limits

### 3. Data Exfiltration

L **Never** download customer databases
L **Never** exfiltrate personal information
L **Never** sell discovered data
L **Never** use findings for identity theft

### 4. Extortion

L **Never** demand payment for vulnerability information
L **Never** threaten to publish findings
L **Never** offer "remediation services" under duress
L **Never** use findings for blackmail

### 5. Unauthorized Disclosure

L **Never** publish 0-day vulnerabilities without vendor coordination
L **Never** disclose before patch availability
L **Never** share findings with unauthorized parties
L **Never** discuss client findings publicly

---

## Best Practices

### 1. Always Obtain Written Authorization

```
Before running ANY Asterion scan:
� Written authorization from system owner
� Scope clearly defined (IP ranges, domains)
� Consent token verified on target domain
� Emergency contact information documented
� Rules of engagement agreed upon
```

### 2. Use Safe Mode First

```bash
# Always start with safe mode
ast scan --target example.com --mode safe

# Review findings
cat ~/.argos/reports/asterion/example.com_*.json

# Only use aggressive mode if authorized AND necessary
ast scan --target example.com --mode aggressive
```

### 3. Rate Limiting

```yaml
# config/defaults.yaml
scan:
    rate_limit:
        safe_mode: 5.0 # 5 requests/second
        aggressive_mode: 10.0 # 10 requests/second
```

**Best Practice:** Start with lower rates, increase only if needed:

```bash
ast scan --target example.com --rate 1.0  # Conservative
```

### 4. Scope Validation

```bash
# Verify target matches authorization
ast consent verify --method dns --domain example.com --token <token>

# Run scan
ast scan --target example.com --mode aggressive

# L DO NOT scan targets outside authorized scope
ast scan --target competitor.com  # ILLEGAL
```

### 5. Audit Trail

```bash
# All scans logged to database
sqlite3 ~/.argos/argos.db "SELECT * FROM scans WHERE domain='example.com';"

# Consent proofs preserved
ls -lah ~/.argos/consent_proofs/

# Logs available for review
tail -f ~/.argos/logs/asterion.log
```

### 6. Responsible Disclosure

```
After scan completion:
  Review critical/high findings
  Report to vendor security contact
  Allow 90 days for remediation
  Document disclosure in database
  Public disclosure only after patch OR 90 days
```

---

## Legal Disclaimer

**READ CAREFULLY:**

Asterion is a security auditing tool intended for **authorized** security assessments only. The developers of Asterion:

- ❌ **DO NOT** endorse unauthorized computer access
- ❌ **DO NOT** authorize scanning of any systems
- ❌ **DO NOT** provide legal advice
- ❌ **ARE NOT** responsible for your use of this tool

**Your Responsibilities:**

By using Asterion, you agree to:

1. **Obtain Authorization:** Written permission from system owners
2. **Follow Laws:** Comply with CFAA, Computer Misuse Act, and all applicable laws
3. **Accept Liability:** You are solely responsible for legal consequences
4. **Use Ethically:** Follow responsible disclosure and ethical guidelines

**No Warranty:**

Asterion is provided "AS IS" without warranty of any kind. The developers:

- Make no guarantees about accuracy of findings
- Are not liable for service disruptions caused by scanning
- Are not liable for legal consequences of unauthorized use
- Are not liable for damages resulting from use of this tool

**Consult Legal Counsel:**

If you have questions about:

- Whether you have proper authorization
- Legal compliance in your jurisdiction
- Responsible disclosure procedures
- Liability for security testing

**CONSULT A LAWYER** before using Asterion.

---

## Quick Reference Card

```bash
# === AUTHORIZATION CHECKLIST ===
✅ Written authorization obtained
✅ Scope clearly defined
✅ Consent token generated and verified
✅ Emergency contact documented
✅ Testing hours agreed upon

# === SAFE SCANNING WORKFLOW ===
# 1. Verify consent
ast consent verify --method http --domain example.com --token <token>

# 2. Start with safe mode
ast scan --target example.com --mode safe --rate 1.0

# 3. Review findings
cat ~/.argos/reports/asterion/example.com_*.json

# 4. Use aggressive mode only if authorized
ast scan --target example.com --mode aggressive

# === RESPONSIBLE DISCLOSURE ===
# 1. Extract critical findings
jq '.findings[] | select(.severity=="critical")' report.json

# 2. Email to security@example.com
# Subject: Security Vulnerability Report - example.com
# Body: Findings, impact, 90-day disclosure timeline

# 3. Track disclosure
sqlite3 ~/.argos/argos.db "UPDATE scans SET notes='Disclosed 2025-01-17' WHERE scan_id=42;"

# === RED FLAGS (STOP IMMEDIATELY) ===
❌ No written authorization
❌ Scanning outside defined scope
❌ Service disruption observed
❌ Personal data discovered
❌ Legal concerns arise
❌ STOP, consult legal counsel
```

---

**Last Updated:** April 2026
**Asterion Version:** 0.2.0

**REMEMBER:** When in doubt, **DON'T**. Always obtain written authorization before scanning any system you don't own.

**Related Documentation:**

- `docs/CONSENT.md` - Technical consent token system
- `docs/README.md` - Tool capabilities and usage
- `docs/ROADMAP.md` - Future ethical features
