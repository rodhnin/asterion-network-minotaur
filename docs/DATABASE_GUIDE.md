# Database Guide

> **Argos Suite Shared Database**: Asterion uses a centralized SQLite database shared across all Argos Suite tools (Argus, Hephaestus, Pythia, Asterion) for unified security posture tracking.

## Table of Contents

-   [Overview](#overview)
-   [Database Location](#database-location)
-   [Schema](#schema)
    -   [Tables](#tables)
    -   [Indexes](#indexes)
    -   [Views](#views)
    -   [Triggers](#triggers)
-   [Data Model](#data-model)
-   [Database Operations](#database-operations)
-   [Queries](#queries)
-   [CLI Interface](#cli-interface)
-   [Migrations](#migrations)
-   [Backup and Restore](#backup-and-restore)
-   [Performance](#performance)
-   [Troubleshooting](#troubleshooting)

---

## Overview

**Database:** SQLite 3.x
**Location:** `~/.argos/argos.db`
**Size:** Typically 5-50 MB (grows with scan history)
**Shared By:**

-   Argus (WordPress/PHP scanner)
-   Hephaestus (Firewall analysis)
-   Pythia (Threat intelligence)
-   Asterion (Network security auditor)

**Why SQLite?**

-   Zero-configuration (no database server required)
-   Cross-platform (works on Windows, Linux, macOS)
-   ACID transactions (data integrity)
-   Fast for < 100k records (typical for security scans)
-   Single file (easy backup and portability)

**Code Location:** `src/Asterion/Core/Database.cs` (684 lines)

---

## Database Location

### Default Path

```bash
~/.argos/argos.db
```

**Expands to:**

-   Linux/macOS: `/home/username/.argos/argos.db`
-   Windows: `C:\Users\Username\.argos\argos.db`

### Configuration

**File:** `config/defaults.yaml`

```yaml
paths:
    database: "~/.argos/argos.db"
```

**Override:**

```bash
# Via config file
ast scan --config /path/to/custom/config.yaml ...

# Via environment variable (if implemented)
export ARGOS_DB_PATH=/custom/path/argos.db
```

---

## Schema

### Tables

#### 1. clients

Stores project/client information for organizing scans.

```sql
CREATE TABLE IF NOT EXISTS clients (
    client_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT NOT NULL,
    contact_email TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    UNIQUE(domain)
);
```

**Purpose:** Organize scans by client/project (multi-tenant support)

**Example:**

```sql
INSERT INTO clients (name, domain, contact_email, notes)
VALUES ('Acme Corp', 'acme.com', 'security@acme.com', 'Quarterly security audit');
```

---

#### 2. consent_tokens

Stores ownership verification tokens (HTTP file, DNS TXT, SSH file).

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
```

**Token States:**

-   `verified_at = NULL` → PENDING (awaiting verification)
-   `verified_at != NULL AND expires_at > now()` → VALID (usable for aggressive scans)
-   `expires_at < now()` → EXPIRED (must regenerate)

**Example:**

```sql
-- Generate token (PENDING state)
INSERT INTO consent_tokens (domain, token, expires_at)
VALUES ('example.com', 'verify-a3f8c2d1e9b4f7a6', '2025-01-19T14:30:22Z');

-- Verify token (VERIFIED state)
UPDATE consent_tokens
SET verified_at = datetime('now', 'utc'),
    method = 'http',
    proof_path = '/home/user/.argos/consent_proofs/example.com_http_20250117_143022.txt'
WHERE token = 'verify-a3f8c2d1e9b4f7a6';
```

**Related Documentation:** `docs/CONSENT.md`

---

#### 3. scans

Stores metadata for each scan execution.

```sql
CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL CHECK(tool IN ('argus', 'hephaestus', 'pythia', 'asterion')),
    client_id INTEGER DEFAULT NULL,
    domain TEXT NOT NULL,
    target_url TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('safe', 'aggressive')),
    started_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    finished_at TEXT DEFAULT NULL,
    status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('running', 'completed', 'failed', 'aborted')),
    report_json_path TEXT,
    report_html_path TEXT,
    summary TEXT,  -- JSON string with counts: {"critical": 0, "high": 1, "medium": 3, ...}
    error_message TEXT DEFAULT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE SET NULL
);
```

**Scan Statuses:**

-   `running` → Scan in progress
-   `completed` → Scan finished successfully
-   `failed` → Scan failed (validation error, network error, etc.)
-   `aborted` → User cancelled scan (Ctrl+C)

**Summary JSON Format:**

```json
{
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8,
    "info": 3
}
```

**Example:**

```sql
INSERT INTO scans (
    tool,
    domain,
    target_url,
    mode,
    started_at,
    finished_at,
    status,
    report_json_path,
    summary
) VALUES (
    'asterion',
    'example.com',
    '192.168.1.0/24',
    'safe',
    '2025-01-17T14:30:22Z',
    '2025-01-17T14:45:10Z',
    'completed',
    '/home/user/.argos/reports/asterion/example.com_20250117_143022.json',
    '{"critical": 2, "high": 5, "medium": 12, "low": 8, "info": 3}'
);
```

**Code:** `src/Asterion/Core/Database.cs:85-172`

---

#### 4. findings

Stores individual vulnerability findings from scans.

```sql
CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_code TEXT NOT NULL,  -- E.g., "AST-SMB-003"
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence TEXT NOT NULL CHECK(confidence IN ('high', 'medium', 'low')),
    evidence_type TEXT,  -- url, header, body, path, screenshot, other
    evidence_value TEXT,
    recommendation TEXT NOT NULL,
    "references" TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);
```

**Finding Codes:** Each tool has unique prefixes:

-   `AST-*` → Asterion (network security)
-   `ARGUS-*` → Argus (WordPress/PHP)
-   `HEPH-*` → Hephaestus (firewall)
-   `PYTH-*` → Pythia (threat intel)

**Example:**

```sql
INSERT INTO findings (
    scan_id,
    finding_code,
    title,
    severity,
    confidence,
    evidence_type,
    evidence_value,
    recommendation,
    "references"
) VALUES (
    42,
    'AST-SMB-003',
    'SMBv1 enabled (EternalBlue vulnerability)',
    'critical',
    'high',
    'protocol_version',
    '{"protocol": "SMBv1", "port": 445, "host": "192.168.1.10"}',
    'URGENT - Disable SMBv1 immediately:\n\nPowerShell:\nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart',
    '["CVE-2017-0143", "CVE-2017-0144", "MS17-010", "https://en.wikipedia.org/wiki/EternalBlue"]'
);
```

**Code:** `src/Asterion/Core/Database.cs:177-239`

---

### Indexes

```sql
-- Clients
CREATE INDEX idx_clients_domain ON clients(domain);

-- Consent Tokens
CREATE INDEX idx_consent_tokens_domain ON consent_tokens(domain);
CREATE INDEX idx_consent_tokens_token ON consent_tokens(token);
CREATE INDEX idx_consent_tokens_verified ON consent_tokens(verified_at);

-- Scans
CREATE INDEX idx_scans_tool ON scans(tool);
CREATE INDEX idx_scans_domain ON scans(domain);
CREATE INDEX idx_scans_started ON scans(started_at);
CREATE INDEX idx_scans_status ON scans(status);

-- Findings
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_code ON findings(finding_code);
```

**Purpose:** Accelerate common queries (domain lookups, time-range filtering, severity sorting)

---

### Views

#### v_recent_scans

Recent scans with summary and finding counts.

```sql
CREATE VIEW v_recent_scans AS
SELECT
    s.scan_id,
    s.tool,
    s.domain,
    s.mode,
    s.started_at,
    s.finished_at,
    s.status,
    c.name AS client_name,
    s.summary,
    COUNT(f.finding_id) AS total_findings
FROM scans s
LEFT JOIN clients c ON s.client_id = c.client_id
LEFT JOIN findings f ON s.scan_id = f.scan_id
GROUP BY s.scan_id
ORDER BY s.started_at DESC;
```

**Usage:**

```sql
SELECT * FROM v_recent_scans LIMIT 10;
```

---

#### v_critical_findings

Critical and high severity findings requiring immediate attention.

```sql
CREATE VIEW v_critical_findings AS
SELECT
    f.finding_id,
    s.tool,
    s.domain,
    s.started_at,
    f.finding_code,
    f.title,
    f.severity,
    f.confidence,
    f.evidence_value,
    f.recommendation
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.severity IN ('critical', 'high')
ORDER BY
    CASE f.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
    END,
    s.started_at DESC;
```

**Usage:**

```sql
SELECT * FROM v_critical_findings LIMIT 20;
```

---

#### v_verified_domains

Domains with valid consent tokens.

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

**Usage:**

```sql
SELECT * FROM v_verified_domains WHERE status = 'valid';
```

---

### Triggers

#### update_clients_timestamp

Auto-updates `updated_at` timestamp when client record is modified.

```sql
CREATE TRIGGER update_clients_timestamp
AFTER UPDATE ON clients
BEGIN
    UPDATE clients SET updated_at = datetime('now', 'utc') WHERE client_id = NEW.client_id;
END;
```

---

## Data Model

### Entity Relationships

```
clients (1) ══════════ (N) scans
                        ║
                        ║ (1)
                        ║
                        ↓
                      (N) findings

consent_tokens (independent, referenced by Orchestrator during scan)
```

**Relationships:**

-   One client can have many scans
-   One scan can have many findings
-   Deleting a client sets `scans.client_id = NULL` (scans preserved)
-   Deleting a scan cascades to findings (findings deleted)

---

## Database Operations

### Initialize Database

**Automatic:** Database and tables created automatically on first run.

```csharp
// src/Asterion/Core/Database.cs:23-34
public Database(Config config)
{
    _config = config;
    _connectionString = $"Data Source={config.Paths.Database}";

    // Ensure database directory exists
    var dbDir = Path.GetDirectoryName(config.Paths.Database);
    if (!string.IsNullOrEmpty(dbDir) && !Directory.Exists(dbDir))
    {
        Directory.CreateDirectory(dbDir);
    }
}
```

**Manual Migration:**

```bash
sqlite3 ~/.argos/argos.db < db/migrate.sql
```

---

### Insert Scan

**Automatic:** Called by Orchestrator at scan completion.

```csharp
// src/Asterion/Core/Database.cs:85-172
var database = new Database(config);
int scanId = await database.InsertScanAsync(report, result, jsonPath, htmlPath);
```

**Scan Status Logic:**

```csharp
// src/Asterion/Core/Database.cs:40-79
private string DetermineStatus(Orchestrator.ScanResult result)
{
    if (result.Success) return "completed";

    var errorLower = result.ErrorMessage.ToLowerInvariant();

    if (errorLower.Contains("cancelled") || errorLower.Contains("interrupted"))
        return "aborted";

    if (errorLower.Contains("consent") || errorLower.Contains("invalid"))
        return "failed";

    return "failed";
}
```

---

### Query Recent Scans

```csharp
// src/Asterion/Core/Database.cs:244-278
var database = new Database(config);
var scans = await database.GetRecentScansAsync(limit: 10);

foreach (var scan in scans)
{
    Console.WriteLine($"{scan["tool"]} - {scan["domain"]} - {scan["status"]}");
}
```

---

### Query Critical Findings

```csharp
// src/Asterion/Core/Database.cs:283-322
var database = new Database(config);
var findings = await database.GetCriticalFindingsAsync(limit: 20);

foreach (var finding in findings)
{
    Console.WriteLine($"{finding["severity"]} - {finding["finding_code"]} - {finding["title"]}");
}
```

---

### Get Verified Consent Token

```csharp
// src/Asterion/Core/Database.cs:423-503
var database = new Database(config);
var token = await database.GetVerifiedConsentTokenAsync("example.com");

if (!string.IsNullOrEmpty(token))
{
    Console.WriteLine($"Verified token found: {token}");
}
```

**Query Logic:**

```sql
SELECT token
FROM consent_tokens
WHERE LOWER(TRIM(domain)) = LOWER(TRIM('example.com'))
  AND verified_at IS NOT NULL
  AND expires_at > datetime('now', 'utc')
ORDER BY verified_at DESC
LIMIT 1;
```

---

## Queries

### Recent Scans by Tool

```sql
SELECT
    scan_id,
    tool,
    domain,
    mode,
    started_at,
    status,
    summary
FROM scans
WHERE tool = 'asterion'
ORDER BY started_at DESC
LIMIT 10;
```

---

### All Findings for a Scan

```sql
SELECT
    finding_code,
    title,
    severity,
    confidence,
    recommendation
FROM findings
WHERE scan_id = 42
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END;
```

---

### Scans by Domain (All Tools)

```sql
SELECT
    scan_id,
    tool,
    mode,
    started_at,
    status,
    summary
FROM scans
WHERE domain = 'example.com'
ORDER BY started_at DESC;
```

**Use Case:** See all security assessments for a domain across Argus, Hephaestus, Pythia, Asterion

---

### Total Findings by Severity (All Time)

```sql
SELECT
    severity,
    COUNT(*) AS count
FROM findings
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END;
```

---

### Failed Scans Requiring Attention

```sql
SELECT
    scan_id,
    tool,
    domain,
    target_url,
    started_at,
    error_message
FROM scans
WHERE status = 'failed'
ORDER BY started_at DESC
LIMIT 20;
```

---

### Expired Consent Tokens

```sql
SELECT
    domain,
    token,
    verified_at,
    expires_at
FROM consent_tokens
WHERE verified_at IS NOT NULL
  AND expires_at < datetime('now', 'utc')
ORDER BY expires_at DESC;
```

**Cleanup:**

```sql
DELETE FROM consent_tokens
WHERE expires_at < datetime('now', 'utc')
  AND datetime(expires_at, '+30 days') < datetime('now', 'utc');  -- Keep for 30 days after expiry
```

---

### Domains Scanned in Last 7 Days

```sql
SELECT
    domain,
    COUNT(*) AS scan_count,
    MAX(started_at) AS last_scan
FROM scans
WHERE started_at > datetime('now', '-7 days')
GROUP BY domain
ORDER BY scan_count DESC;
```

---

## CLI Interface

### Interactive SQL Shell

```bash
sqlite3 ~/.argos/argos.db
```

**Example Session:**

```sql
-- List all tables
.tables

-- Show schema for scans table
.schema scans

-- Recent scans
SELECT * FROM v_recent_scans LIMIT 5;

-- Exit
.quit
```

---

### One-Liner Queries

```bash
# Recent scans
sqlite3 ~/.argos/argos.db "SELECT * FROM v_recent_scans LIMIT 10;"

# Critical findings
sqlite3 ~/.argos/argos.db "SELECT * FROM v_critical_findings;"

# Verified domains
sqlite3 ~/.argos/argos.db "SELECT * FROM v_verified_domains;"

# CSV export
sqlite3 -csv ~/.argos/argos.db "SELECT * FROM findings WHERE severity = 'critical';" > critical.csv
```

---

### Database CLI (Planned - ROADMAP.md IMPROV-011)

**Future Feature:** Metasploit-style interactive database CLI

```bash
ast db

asterion-db > show scans
asterion-db > show findings --severity critical
asterion-db > export scan 42 --format json
asterion-db > search findings "eternalblue"
asterion-db > stats --by-severity
asterion-db > cleanup --older-than 90d
```

**Status:** Planned for v0.3.0

---

## Migrations

### Current Schema Version

**Version:** 1
**File:** `db/migrate.sql`

### Future Migrations

**Pattern:**

```
db/migrate.sql           � v1 (current)
db/migrate_v1_to_v2.sql  � v2 (future)
db/migrate_v2_to_v3.sql  � v3 (future)
```

### Migration Tracking (Planned)

```sql
CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT
);

INSERT INTO schema_version (version, applied_at, description)
VALUES (1, datetime('now', 'utc'), 'Initial schema');
```

---

## Backup and Restore

### Backup

```bash
# Simple copy (database must be idle)
cp ~/.argos/argos.db ~/.argos/backups/argos_$(date +%Y%m%d_%H%M%S).db

# SQLite backup command (safe while database is in use)
sqlite3 ~/.argos/argos.db ".backup ~/.argos/backups/argos_$(date +%Y%m%d_%H%M%S).db"

# Compressed backup
sqlite3 ~/.argos/argos.db ".dump" | gzip > ~/.argos/backups/argos_$(date +%Y%m%d_%H%M%S).sql.gz
```

### Restore

```bash
# From backup file
cp ~/.argos/backups/argos_20250117_143022.db ~/.argos/argos.db

# From SQL dump
gunzip -c ~/.argos/backups/argos_20250117_143022.sql.gz | sqlite3 ~/.argos/argos.db
```

### Automated Backups (Recommended)

```bash
# Cron job (daily at 2 AM)
0 2 * * * sqlite3 ~/.argos/argos.db ".backup ~/.argos/backups/argos_$(date +\%Y\%m\%d).db" && find ~/.argos/backups -name "argos_*.db" -mtime +30 -delete
```

---

## Performance

### Database Size

**Typical Growth:**

-   Empty database: ~100 KB
-   100 scans: ~5 MB
-   1,000 scans: ~50 MB
-   10,000 scans: ~500 MB

**Growth Rate:** ~50 KB per scan (varies with finding count)

### Query Performance

**Fast (< 1ms):**

-   Primary key lookups (`scan_id`, `finding_id`)
-   Indexed domain/token lookups
-   Recent scans (LIMIT 10)

**Medium (1-10ms):**

-   Views with JOINs (`v_recent_scans`, `v_critical_findings`)
-   Full-text search on findings

**Slow (> 10ms):**

-   Unindexed searches (e.g., `WHERE recommendation LIKE '%eternalblue%'`)
-   Large aggregations (e.g., COUNT(\*) on 10k+ findings)

### Optimization Tips

1. **Use Indexes:** Database already has optimal indexes for common queries
2. **LIMIT Results:** Always use LIMIT for large result sets
3. **VACUUM:** Reclaim space after large deletions
    ```bash
    sqlite3 ~/.argos/argos.db "VACUUM;"
    ```
4. **ANALYZE:** Update query optimizer statistics
    ```bash
    sqlite3 ~/.argos/argos.db "ANALYZE;"
    ```

---

## Troubleshooting

### Error: "database is locked"

**Cause:** Another process is writing to the database

**Solution:**

```bash
# Check for processes using database
lsof ~/.argos/argos.db

# Kill stuck processes
kill -9 <PID>

# Retry operation
```

---

### Error: "disk I/O error"

**Cause:** Filesystem permission issue or disk full

**Solution:**

```bash
# Check permissions
ls -lah ~/.argos/argos.db

# Fix permissions
chmod 600 ~/.argos/argos.db
chown $USER ~/.argos/argos.db

# Check disk space
df -h ~
```

---

### Corrupt Database

**Symptoms:**

-   SQLite error messages
-   Incomplete query results
-   Application crashes

**Recovery:**

```bash
# Check database integrity
sqlite3 ~/.argos/argos.db "PRAGMA integrity_check;"

# Dump and restore (if integrity check passes)
sqlite3 ~/.argos/argos.db ".dump" | sqlite3 ~/.argos/argos_fixed.db
mv ~/.argos/argos.db ~/.argos/argos_corrupt.db
mv ~/.argos/argos_fixed.db ~/.argos/argos.db

# Restore from backup (if dump fails)
cp ~/.argos/backups/argos_latest.db ~/.argos/argos.db
```

---

### Large Database Size

**Cleanup old scans (> 90 days):**

```sql
-- Delete old scans (cascades to findings)
DELETE FROM scans
WHERE started_at < datetime('now', '-90 days');

-- Vacuum to reclaim space
VACUUM;
```

**Cleanup expired consent tokens (> 30 days after expiry):**

```sql
DELETE FROM consent_tokens
WHERE expires_at < datetime('now', 'utc')
  AND datetime(expires_at, '+30 days') < datetime('now', 'utc');

VACUUM;
```

---

### Missing Data After Scan

**Cause:** Scan failed before database insert

**Debug:**

```bash
# Check last scans
sqlite3 ~/.argos/argos.db "SELECT * FROM scans ORDER BY started_at DESC LIMIT 5;"

# Check logs
tail -f ~/.argos/logs/asterion.log
```

---

## Related Documentation

-   **ROADMAP.md** - Future database features:

    -   IMPROV-011: Interactive database CLI (v0.3.0)
    -   Database migrations system
    -   Multi-database support (PostgreSQL/MySQL)
    -   Full-text search on findings

-   **CONSENT.md** - Consent token system and database queries

-   **README.md** - Project structure and configuration

---

## Quick Reference Card

```bash
# === DATABASE LOCATION ===
~/.argos/argos.db

# === INTERACTIVE SHELL ===
sqlite3 ~/.argos/argos.db

# === COMMON QUERIES ===
# Recent scans
SELECT * FROM v_recent_scans LIMIT 10;

# Critical findings
SELECT * FROM v_critical_findings;

# Verified domains
SELECT * FROM v_verified_domains WHERE status = 'valid';

# Scans by domain
SELECT * FROM scans WHERE domain = 'example.com' ORDER BY started_at DESC;

# Total findings by severity
SELECT severity, COUNT(*) FROM findings GROUP BY severity;

# === BACKUP ===
sqlite3 ~/.argos/argos.db ".backup ~/.argos/backups/argos_$(date +%Y%m%d).db"

# === MAINTENANCE ===
# Integrity check
sqlite3 ~/.argos/argos.db "PRAGMA integrity_check;"

# Reclaim space
sqlite3 ~/.argos/argos.db "VACUUM;"

# Update statistics
sqlite3 ~/.argos/argos.db "ANALYZE;"

# === CLEANUP ===
# Delete old scans (> 90 days)
sqlite3 ~/.argos/argos.db "DELETE FROM scans WHERE started_at < datetime('now', '-90 days'); VACUUM;"
```

---

**Schema Version:** 1.0  
**Next Update:** v0.3.0 (Interactive CLI - IMPROV-011)
**Tool Version:** Asterion v0.1.0
