# Consent Token System

> **Ethical Security Auditing**: Asterion implements a robust ownership verification system to prevent unauthorized scanning and ensure compliance with legal and ethical standards.

## Table of Contents

- [Overview](#overview)
- [Why Consent Verification](#why-consent-verification)
- [Token Generation](#token-generation)
- [Verification Methods](#verification-methods)
    - [HTTP File Verification](#http-file-verification)
    - [DNS TXT Record Verification](#dns-txt-record-verification)
    - [SSH File Verification](#ssh-file-verification)
- [Database Storage](#database-storage)
- [CLI Commands](#cli-commands)
- [Implementation Details](#implementation-details)
- [Token Lifecycle](#token-lifecycle)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Overview

The **Consent Token System** is a mandatory ownership verification mechanism required before running:

- `--mode aggressive`: Intrusive scanning with vulnerability exploitation checks
- `--use-ai`: AI-powered analysis that may generate sensitive findings

**Key Features:**

- Three verification methods: HTTP, DNS, SSH
- Token expiration (48 hours by default)
- Cryptographically secure token generation
- Automatic database tracking
- Proof preservation for audit trails
- Shared with Argos Suite database

**Code Location:** `src/Asterion/Core/ConsentValidator.cs` (550 lines)

---

## Why Consent Verification

### Legal Requirements

1. **Computer Fraud and Abuse Act (CFAA)** - US Federal Law
    - Unauthorized access to computer systems is a federal crime
    - "Exceeding authorized access" includes security testing without permission
    - Penalties: Up to 10 years imprisonment + fines

2. **Computer Misuse Act 1990** - UK Law
    - Unauthorized access or modification of computer material
    - Penalties: Up to 2 years imprisonment

3. **Similar Laws Worldwide**
    - Every jurisdiction has computer crime laws
    - Ignorance is not a defense

### Ethical Requirements

Even if you own the target system:

- **Network infrastructure** may be owned by hosting providers
- **Third-party services** may be affected by aggressive scanning
- **Rate limiting** without consent can trigger DDoS protections
- **Exploitation checks** may crash vulnerable services

### When Consent is Required

| Mode                | AI         | Consent Required?                    |
| ------------------- | ---------- | ------------------------------------ |
| `--mode safe`       | No         | No (passive recon only)              |
| `--mode safe`       | `--use-ai` | Yes (AI generates sensitive reports) |
| `--mode aggressive` | No         | Yes (intrusive checks)               |
| `--mode aggressive` | `--use-ai` | Yes (both reasons)                   |

**Implementation:** `src/Asterion/Core/Orchestrator.cs:163-191`

---

## Token Generation

### Format

```
verify-{16 hex characters}
```

**Examples:**

```
verify-a3f8c2d1e9b4f7a6
verify-2e9f8d1c4a7b3e6f
verify-7b4a1d8e2f9c6a3e
```

### Generation Process

1. **Cryptographically Secure Randomness**

    ```csharp
    var randomBytes = RandomNumberGenerator.GetBytes(8); // 8 bytes = 16 hex chars
    var randomHex = Convert.ToHexString(randomBytes).ToLower();
    var token = $"verify-{randomHex}";
    ```

2. **Token Expiration**
    - Default: **48 hours** from generation
    - Configurable: `config/defaults.yaml` � `consent.token_expiry_hours`

3. **Database Storage**
    - Saved to `~/.argos/argos.db` � `consent_tokens` table
    - Status: `PENDING` (verified_at = NULL)
    - Must be verified within 48 hours

**Code:** `src/Asterion/Core/ConsentValidator.cs:43-59`

---

## Verification Methods

### HTTP File Verification

**Recommended Method** - Fastest and most reliable

#### How It Works

1. Create a text file containing **EXACTLY** the token (no spaces, no newlines)
2. Upload to: `https://example.com/.well-known/{token}.txt`
3. Asterion fetches the file via HTTP GET request
4. Compares file content with expected token

#### Path Details

- **Default Path:** `/.well-known/` (RFC 8615 standard)
- **Configurable:** `config/defaults.yaml` → `consent.http_verification_path`
- **Port Support:** Preserves port numbers (e.g., `http://example.com:8080/.well-known/`)

#### Protocol Selection

```
Has Port? → Use HTTP only (skip HTTPS)
No Port?  → Try HTTPS first, fallback to HTTP
```

**Rationale:** Custom ports often use self-signed certificates that fail HTTPS validation

#### Example

```bash
# 1. Generate token
ast consent generate --domain example.com
# Output: verify-a3f8c2d1e9b4f7a6

# 2. Create file
echo -n "verify-a3f8c2d1e9b4f7a6" > verify-a3f8c2d1e9b4f7a6.txt

# 3. Upload to server
scp verify-a3f8c2d1e9b4f7a6.txt user@example.com:/var/www/html/.well-known/

# 4. Verify
ast consent verify --method http --domain example.com --token verify-a3f8c2d1e9b4f7a6
```

#### Common Errors

| Error                    | Cause                     | Solution                            |
| ------------------------ | ------------------------- | ----------------------------------- |
| `404 Not Found`          | File not uploaded         | Check web server path mapping       |
| `Token content mismatch` | Extra whitespace/newlines | Use `echo -n` (no newline)          |
| `SSL certificate error`  | Self-signed certificate   | Use custom port to force HTTP       |
| `Connection timeout`     | Firewall blocking         | Check firewall rules on port 80/443 |

**Code:** `src/Asterion/Core/ConsentValidator.cs:164-220`

---

### DNS TXT Record Verification

**Alternative Method** - No web server required, but slower due to DNS propagation

#### How It Works

1. Add TXT record to domain's DNS zone
2. Asterion performs DNS query for TXT records
3. Checks for record matching: `asterion-verify={token}`
4. Validates against authoritative nameservers

#### DNS TXT Format

```
Host:  example.com
Type:  TXT
Value: asterion-verify=verify-a3f8c2d1e9b4f7a6
```

#### Nameserver Resolution Strategy

```
1. Query domain for NS records (e.g., ns1.example.com, ns2.example.com)
2. Resolve NS hostname to IP address
3. Query authoritative NS directly for TXT records
4. Fallback to system DNS if NS query fails
```

**Why Query Authoritative NS?**

- Avoids stale DNS cache (up to 48 hours)
- Ensures latest TXT record is checked
- Faster verification after DNS update

#### Example

```bash
# 1. Generate token
ast consent generate --domain example.com
# Output: verify-a3f8c2d1e9b4f7a6

# 2. Add TXT record via DNS provider
# Host: example.com
# Value: asterion-verify=verify-a3f8c2d1e9b4f7a6
# TTL: 300 (5 minutes)

# 3. Wait for DNS propagation (5-30 minutes)
dig TXT example.com +short

# 4. Verify
ast consent verify --method dns --domain example.com --token verify-a3f8c2d1e9b4f7a6
```

#### DNS Propagation Time

| DNS Provider           | Typical Propagation   |
| ---------------------- | --------------------- |
| Cloudflare             | 2-5 minutes           |
| Route53 (AWS)          | 5-10 minutes          |
| GoDaddy                | 10-30 minutes         |
| Namecheap              | 15-30 minutes         |
| Traditional registrars | 30 minutes - 24 hours |

#### Port Handling

DNS queries **ignore ports** (DNS doesn't use ports like HTTP does):

```
example.com:8080 � Strips to example.com for DNS lookup
```

#### Common Errors

| Error                              | Cause                  | Solution                         |
| ---------------------------------- | ---------------------- | -------------------------------- |
| `No TXT records found`             | DNS not propagated yet | Wait 5-30 minutes and retry      |
| `Token not found in TXT records`   | Wrong TXT value format | Check prefix: `asterion-verify=` |
| `Domain does not exist (NXDOMAIN)` | Typo in domain name    | Verify domain spelling           |
| `DNS query failed`                 | DNS server unreachable | Check internet connection        |

**Code:** `src/Asterion/Core/ConsentValidator.cs:227-340`

---

### SSH File Verification

**Server Access Method** - For environments where you have SSH access but no web/DNS control

#### How It Works

1. SSH into target server
2. Create file containing token at expected path
3. Asterion connects via SSH and reads file
4. Validates token content

#### File Paths

**Linux:**

```bash
/tmp/consent_{token}
/var/tmp/consent_{token}  # Fallback if /tmp fails
```

**Windows:**

```powershell
C:\Consent\{token}.txt
C:\Temp\consent_{token}.txt  # Fallback
```

#### OS Detection

Asterion runs `uname` command to detect Linux:

```bash
uname  # Exit code 0 + contains "Linux" � Use Linux paths
```

#### Example (Linux)

```bash
# 1. Generate token
ast consent generate --domain example.com
# Output: verify-a3f8c2d1e9b4f7a6

# 2. SSH to server and create file
ssh user@example.com
echo -n "verify-a3f8c2d1e9b4f7a6" > /tmp/consent_verify-a3f8c2d1e9b4f7a6

# 3. Verify from Asterion host
ast consent verify --method ssh --domain example.com --token verify-a3f8c2d1e9b4f7a6 --ssh user:password
```

#### Example (Windows)

```powershell
# 1. SSH to Windows server
ssh administrator@win-server.example.com

# 2. Create consent directory and file
New-Item -ItemType Directory -Path C:\Consent -Force
Set-Content -Path C:\Consent\verify-a3f8c2d1e9b4f7a6.txt -Value "verify-a3f8c2d1e9b4f7a6" -NoNewline

# 3. Verify
ast consent verify --method ssh --domain win-server.example.com --token verify-a3f8c2d1e9b4f7a6 --ssh administrator:password
```

#### SSH Authentication

**Format:** `--ssh user:password`

**Supported authentication methods (v0.2.0):**

- Password: `--ssh user:password`
- Key-based: `--ssh-key user:~/.ssh/id_rsa` (v0.2.0, AST-FEATURE-002)
- Bastion/jump host: `--bastion host:user:password` (v0.2.0, AST-FEATURE-002)

#### Common Errors

| Error                       | Cause                   | Solution                                  |
| --------------------------- | ----------------------- | ----------------------------------------- |
| `SSH authentication failed` | Wrong credentials       | Verify username/password                  |
| `Host unreachable`          | Network/firewall issue  | Check SSH port 22 access                  |
| `Connection refused`        | SSH service not running | Start SSH service on target               |
| `Token file not found`      | Wrong file path         | Check Linux vs Windows paths              |
| `Token content mismatch`    | Extra whitespace        | Use `echo -n` or `Set-Content -NoNewline` |

**Code:** `src/Asterion/Core/ConsentValidator.cs:348-474`

---

## Database Storage

### Schema

**Table:** `consent_tokens` (Shared Argos Suite database: `~/.argos/argos.db`)

```sql
CREATE TABLE IF NOT EXISTS consent_tokens (
    token_id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    method TEXT CHECK(method IN ('http', 'dns', 'ssh')),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    verified_at TEXT DEFAULT NULL,
    proof_path TEXT DEFAULT NULL,  -- Path to saved verification evidence
    expires_at TEXT NOT NULL,       -- Tokens expire after 48h
    notes TEXT
);

CREATE INDEX idx_consent_tokens_domain ON consent_tokens(domain);
CREATE INDEX idx_consent_tokens_token ON consent_tokens(token);
CREATE INDEX idx_consent_tokens_verified ON consent_tokens(verified_at);
```

**Schema Location:** `db/migrate.sql:27-41`

### Token States

```
PENDING    � verified_at = NULL, method = NULL
VERIFIED   � verified_at = ISO 8601 timestamp, method = 'http'|'dns'|'ssh'
EXPIRED    � datetime('now') > expires_at
```

### View: Verified Domains

```sql
CREATE VIEW v_verified_domains AS
SELECT
    domain,
    token,
    method,
    verified_at,
    expires_at,
    CASE
        WHEN datetime('now', 'utc') < expires_at THEN 'valid'
        ELSE 'expired'
    END AS status
FROM consent_tokens
WHERE verified_at IS NOT NULL
ORDER BY verified_at DESC;
```

**Query Example:**

```bash
sqlite3 ~/.argos/argos.db "SELECT * FROM v_verified_domains;"
```

### Automatic Lookup

When you run `ast scan --mode aggressive`, Asterion **automatically** checks database:

```csharp
// src/Asterion/Core/Orchestrator.cs:163-191
if (options.Mode.ToLower() == "aggressive")
{
    var database = new Database(_config);
    var verifiedToken = await database.GetVerifiedConsentTokenAsync(options.Target);

    if (string.IsNullOrEmpty(verifiedToken))
    {
        throw new InvalidOperationException("No verified consent token found");
    }
}
```

**Query Logic:**

```sql
SELECT token
FROM consent_tokens
WHERE LOWER(TRIM(domain)) = LOWER(TRIM(@domain))
  AND verified_at IS NOT NULL
  AND expires_at > @now
ORDER BY verified_at DESC
LIMIT 1;
```

**Code:** `src/Asterion/Core/Database.cs:423-503`

---

## CLI Commands

### Generate Token

```bash
ast consent generate --domain <domain>
```

**Output:**

```
======================================================================
DOMAIN OWNERSHIP VERIFICATION REQUIRED
======================================================================

Domain: example.com
Token: verify-a3f8c2d1e9b4f7a6
Expires: 48 hours from now

┌─ METHOD 1: HTTP File (Recommended)
│
│  1. Create a text file containing EXACTLY this:
│     verify-a3f8c2d1e9b4f7a6
│
│  2. Upload it to:
│     https://example.com/.well-known/verify-a3f8c2d1e9b4f7a6.txt
│
│  3. Verify it's accessible in your browser
│
│  4. Run verification:
│     ast consent verify --method http --domain example.com --token verify-a3f8c2d1e9b4f7a6
└─

┌─ METHOD 2: DNS TXT Record (Alternative)
│
│  1. Add a TXT record to your DNS:
│     Host: example.com
│     Value: asterion-verify=verify-a3f8c2d1e9b4f7a6
│
│  2. Wait for DNS propagation (5-30 minutes)
│
│  3. Run verification:
│     ast consent verify --method dns --domain example.com --token verify-a3f8c2d1e9b4f7a6
└─

┌─ METHOD 3: SSH File (For Server Access)
│
│  1. SSH into the target server and create a file:
│     Linux: /tmp/consent_verify-a3f8c2d1e9b4f7a6
│     Windows: C:\Consent\verify-a3f8c2d1e9b4f7a6.txt
│
│  2. File content (same as above):
│     verify-a3f8c2d1e9b4f7a6
│
│  3. Run verification with SSH credentials:
│     ast consent verify --method ssh --domain example.com --token verify-a3f8c2d1e9b4f7a6 --ssh user:pass
└─

======================================================================
NOTE: You must verify ownership before using --aggressive or --use-ai
======================================================================
```

**Code:** `src/Cli.cs:399-430` + `src/Asterion/Core/ConsentValidator.cs:64-157`

---

### Verify Token

```bash
ast consent verify --method <http|dns|ssh> --domain <domain> --token <token> [--ssh user:pass]
```

**Examples:**

```bash
# HTTP verification
ast consent verify --method http --domain example.com --token verify-a3f8c2d1e9b4f7a6

# DNS verification
ast consent verify --method dns --domain example.com --token verify-a3f8c2d1e9b4f7a6

# SSH verification (requires --ssh)
ast consent verify --method ssh --domain example.com --token verify-a3f8c2d1e9b4f7a6 --ssh admin:password
```

**Success Output:**

```
✓  Consent verification successful!
Proof: https://example.com/.well-known/verify-a3f8c2d1e9b4f7a6.txt
Proof saved: ~/.argos/consent_proofs/example.com_http_20250117_143022.txt
```

**Failure Output:**

```
✓ Consent verification failed
Error: Token file not accessible at example.com/.well-known/verify-a3f8c2d1e9b4f7a6.txt
```

**Code:** `src/Cli.cs:432-525`

---

### Check Verified Domains

```bash
sqlite3 ~/.argos/argos.db "SELECT * FROM v_verified_domains;"
```

**Output:**

```
example.com|verify-a3f8c2d1e9b4f7a6|http|2025-01-15T14:30:22.000Z|2025-01-17T14:30:22.000Z|valid
test.local|verify-2e9f8d1c4a7b3e6f|dns|2025-01-14T09:15:10.000Z|2025-01-16T09:15:10.000Z|valid
```

---

## Implementation Details

### Configuration

**File:** `config/defaults.yaml`

```yaml
consent:
    # Token expiration time (hours)
    token_expiry_hours: 48

    # Token generation (hex length)
    token_hex_length: 16

    # HTTP verification path
    http_verification_path: "/.well-known/"

    # DNS TXT record prefix
    dns_txt_prefix: "asterion-verify="

    # Retry settings for verification
    verification_retries: 3
    verification_retry_delay: 2 # seconds
```

### Proof Preservation

Every successful verification saves evidence to:

```
~/.argos/consent_proofs/{domain}_{method}_{timestamp}.txt
```

**Example Proof File:**

```
Domain: example.com
Token: verify-a3f8c2d1e9b4f7a6
Method: http
Verified: 2025-01-15T14:30:22.123Z
Proof: https://example.com/.well-known/verify-a3f8c2d1e9b4f7a6.txt
```

**Purpose:**

- Audit trail for compliance
- Legal evidence of authorization
- Debugging verification issues

**Code:** `src/Asterion/Core/ConsentValidator.cs:479-503`

---

## Token Lifecycle

```
╔═════════════════════════════════════════════════════════════╗
║ 1. GENERATION                                               ║
║    ast consent generate --domain example.com                ║
║    - Token: verify-a3f8c2d1e9b4f7a6                         ║
║    - Expires: 2025-01-17T14:30:22Z (48h)                    ║
║    - Database: PENDING (verified_at = NULL)                 ║
╚═════════════════════════════════════════════════════════════╝
                          ↓
╔═════════════════════════════════════════════════════════════╗
║ 2. PLACEMENT                                                ║
║    User uploads token to:                                   ║
║    - HTTP: https://example.com/.well-known/{token}.txt      ║
║    - DNS: TXT record asterion-verify={token}                ║
║    - SSH: /tmp/consent_{token}                              ║
╚═════════════════════════════════════════════════════════════╝
                          ↓
╔═════════════════════════════════════════════════════════════╗
║ 3. VERIFICATION                                             ║
║    ast consent verify --method http --domain ...            ║
║    - Asterion fetches/queries token                         ║
║    - Compares with database record                          ║
║    - Updates: verified_at = now(), method = 'http'          ║
║    - Saves proof: ~/.argos/consent_proofs/...               ║
╚═════════════════════════════════════════════════════════════╝
                          ↓
╔═════════════════════════════════════════════════════════════╗
║ 4. USAGE                                                    ║
║    ast scan --mode aggressive --target example.com          ║
║    - Orchestrator checks database automatically             ║
║    - Validates: verified_at NOT NULL AND expires_at > now   ║
║    - Scan proceeds if valid                                 ║
╚═════════════════════════════════════════════════════════════╝
                          ↓
╔═════════════════════════════════════════════════════════════╗
║ 5. EXPIRATION                                               ║
║    After 48 hours:                                          ║
║    - Token becomes invalid                                  ║
║    - Must generate new token for future scans               ║
║    - Old token remains in database for audit trail          ║
╚═════════════════════════════════════════════════════════════╝
```

---

## Security Considerations

### Token Strength

```
Entropy: 64 bits (8 bytes � 8 bits/byte)
Possible tokens: 2^64 = 18,446,744,073,709,551,616
Brute force time (at 1M attempts/sec): 584,942 years
```

**Why 64 bits is sufficient:**

- Token only valid for 48 hours
- Verification requires placement on target domain (proof of ownership)
- Not a password (no offline attack possible)

### Threat Model

**Protected Against:**

- Unauthorized scanning of third-party systems
- Accidental aggressive scans without consent
- AI analysis reports for wrong target
- Token reuse after expiration

**NOT Protected Against:**

- Malicious insider with domain control (they can generate valid token)
- DNS hijacking (attacker controls DNS TXT records)
- Compromised web server (attacker can upload token file)

**Design Philosophy:**

> Consent system proves **ownership**, not **identity**. If attacker controls domain, they can authorize scans. This is intentional - system owner can always authorize testing.

### Token Storage

**Database:**

- Tokens stored in plaintext (they're not secrets)
- Only verifiable by placing on target domain
- No encryption needed (no confidentiality requirement)

**Proof Files:**

- Stored in `~/.argos/consent_proofs/` (chmod 700)
- Contains verification evidence for audit trail
- Should be backed up for compliance records

---

## Troubleshooting

### Error: "No verified consent token found"

**Cause:** Running `--mode aggressive` without consent

**Solution:**

```bash
# 1. Generate token
ast consent generate --domain example.com

# 2. Verify token (choose one method)
ast consent verify --method http --domain example.com --token <token>

# 3. Retry scan
ast scan --mode aggressive --target example.com
```

---

### Error: "Token content mismatch"

**Cause:** Extra whitespace or newlines in token file

**Solution:**

```bash
# BAD (adds newline)
echo "verify-a3f8c2d1e9b4f7a6" > token.txt

# GOOD (no newline)
echo -n "verify-a3f8c2d1e9b4f7a6" > token.txt

# Windows PowerShell
Set-Content -Path token.txt -Value "verify-a3f8c2d1e9b4f7a6" -NoNewline
```

---

### Error: "Domain does not exist (NXDOMAIN)"

**Cause:** DNS resolution failure

**Solution:**

1. Check domain spelling: `dig example.com`
2. Ensure domain has NS records: `dig NS example.com`
3. Try HTTP method instead

---

### Error: "Token expired"

**Cause:** Token older than 48 hours

**Solution:**

```bash
# Generate new token
ast consent generate --domain example.com

# Verify within 48 hours
```

---

### DNS Propagation Taking Too Long

**Solution:**

1. Check TTL on TXT record (set to 300 seconds = 5 minutes)
2. Query authoritative nameserver directly:
    ```bash
    dig TXT example.com @ns1.example.com
    ```
3. Use HTTP method instead (instant verification)

---

### SSH Connection Timeout

**Cause:** Firewall blocking SSH port 22

**Solution:**

1. Check SSH service: `sudo systemctl status sshd`
2. Check firewall rules:

    ```bash
    # Linux
    sudo ufw status

    # Windows
    netsh advfirewall firewall show rule name=all
    ```

3. Allow SSH: `sudo ufw allow 22/tcp`

---

## Related Documentation

- **Legal Framework:** `docs/ETHICS.md` - Computer fraud laws, ethical guidelines
- **Database Guide:** `docs/DATABASE_GUIDE.md` - Argos Suite database schema, queries
- **Roadmap:** `docs/ROADMAP.md` - Future consent system improvements
    - IMPROV-009: Interactive consent CLI with wizard
    - AST-FEATURE-002: SSH key authentication support

---

## Quick Reference Card

```bash
# === WORKFLOW ===
# 1. Generate
ast consent generate --domain example.com

# 2. Place token (choose one):
# HTTP:  Upload to https://example.com/.well-known/{token}.txt
# DNS:   Add TXT record: asterion-verify={token}
# SSH:   Create file: /tmp/consent_{token}

# 3. Verify
ast consent verify --method http --domain example.com --token <token>

# 4. Scan
ast scan --mode aggressive --target example.com

# === DEBUGGING ===
# Check verified domains
sqlite3 ~/.argos/argos.db "SELECT * FROM v_verified_domains;"

# Check proof files
ls -lah ~/.argos/consent_proofs/

# Test HTTP file
curl https://example.com/.well-known/{token}.txt

# Test DNS TXT
dig TXT example.com +short | grep asterion-verify

# === CONFIGURATION ===
# Token expiry, paths, retries
vim config/defaults.yaml  # � consent: section
```

---

_Asterion Version: 0.2.0_

- `src/Asterion/Core/ConsentValidator.cs` - Main implementation
- `src/Asterion/Core/Orchestrator.cs:163-191` - Automatic consent check
- `src/Asterion/Core/Database.cs:423-503` - Database queries
- `src/Cli.cs:90-138` - CLI commands
- `db/migrate.sql:27-41` - Database schema
- `config/defaults.yaml:163-178` - Configuration

---

**Last Updated:** May 2026  
**Asterion Version:** 0.2.0
