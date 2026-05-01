# Asterion Docker Deployment

Complete guide for deploying Asterion Network Security Auditor using Docker.

---

## 📋 Table of Contents

-   [Quick Start](#-quick-start)
-   [Deployment Scripts](#-deployment-scripts)
-   [Manual Deployment](#-manual-deployment)
-   [Configuration](#-configuration)
-   [Usage Examples](#-usage-examples)
-   [Troubleshooting](#-troubleshooting)

---

## 🚀 Quick Start

### Linux/macOS

```bash
cd docker
./deploy.sh
```

### Windows (PowerShell)

```powershell
cd docker
.\deploy.ps1
```

**Deployment Options:**

1. **Production** - Deploy Asterion Scanner
2. **Stop all services**
3. **Remove all containers and data** (reset)

---

## 🔧 Deployment Scripts

Both scripts provide the same functionality with platform-specific implementations.

### Linux/macOS: `deploy.sh`

**Features:**

-   ✅ Automatic Docker/Docker Compose validation
-   ✅ Directory creation with correct permissions
-   ✅ Environment file setup (.env)
-   ✅ Color-coded output
-   ✅ Safe cleanup with confirmations

**Usage:**

```bash
chmod +x deploy.sh
./deploy.sh
```

### Windows: `deploy.ps1`

**Features:**

-   ✅ Docker Desktop validation
-   ✅ Automatic directory creation
-   ✅ Environment file setup (.env)
-   ✅ Color-coded output
-   ✅ Safe cleanup with confirmations

**Usage:**

```powershell
.\deploy.ps1
```

---

## 🛠️ Manual Deployment

If you prefer manual deployment:

### Prerequisites

1. **Docker** 20.10+ ([Install](https://docs.docker.com/get-docker/))
2. **Docker Compose** 2.0+ (included in Docker Desktop)

### Linux/macOS Manual Steps

```bash
cd docker

# Create directories
mkdir -p ../reports ../data ../logs ../workspace ../consent-proofs

# Configure environment
cp .env.example .env
nano .env  # Edit with your API keys (optional)

# Deploy
docker compose up -d

# Verify
docker compose ps
docker compose logs -f asterion
```

### Windows Manual Steps

```powershell
cd docker

# Create directories
New-Item -ItemType Directory -Force ../reports, ../data, ../logs, ../workspace, ../consent-proofs

# Configure environment
Copy-Item .env.example .env
notepad .env  # Edit with your API keys (optional)

# Deploy
docker compose up -d

# Verify
docker compose ps
docker compose logs -f asterion
```

---

## ⚙️ Configuration

### Network Modes

#### Bridge Mode (Default - Windows/macOS)

```yaml
network_mode: bridge
```

-   ✅ Works on all platforms
-   ❌ Cannot scan local network
-   ✅ Can scan external networks

#### Host Mode (Linux Only)

```yaml
network_mode: host
```

-   ✅ Direct access to host network
-   ✅ Can scan local network (192.168.x.x, 10.x.x.x)
-   ❌ Only works on Linux Docker hosts

**To enable host mode on Linux:**

```bash
# Edit .env file
echo "NETWORK_MODE=host" >> .env

# Restart container
docker compose down && docker compose up -d
```

### Volume Mounts

| Container Path | Host Path (from project root) | Purpose                  |
| -------------- | ----------------------------- | ------------------------ |
| `/reports`     | `docker/reports/`             | Scan reports (JSON/HTML) |
| `/data`        | `docker/data/`                | Argos Suite database     |
| `/logs`        | `docker/logs/`                | Application logs         |
| `/workspace`   | `docker/workspace/`           | Temporary files          |

**Note:** Paths shown relative to project root (`asterion-network-minotaur/`).
When running from `docker/` directory, use `./reports/`, `./data/`, etc.

### Resource Limits

Defaults (configurable in `.env`):

-   **CPU**: 2.0 cores (max), 0.5 (reserved)
-   **Memory**: 2GB (max), 512MB (reserved)

**To adjust:**

```bash
# Edit .env file
CPU_LIMIT=4.0
MEMORY_LIMIT=4G

# Restart
docker compose down && docker compose up -d
```

---

## 📚 Usage Examples

### Basic Network Scanning

**Linux/macOS:**

```bash
# Scan network range
docker compose exec asterion dotnet /app/ast.dll scan --target 192.168.1.0/24

# Scan with HTML report
docker compose exec asterion dotnet /app/ast.dll scan --target 10.0.0.5 --output html

# Scan domain
docker compose exec asterion dotnet /app/ast.dll scan --target corp.local
```

**Windows:**

```powershell
# Scan network range
docker compose exec asterion dotnet /app/ast.dll scan --target 192.168.1.0/24

# Scan with HTML report
docker compose exec asterion dotnet /app/ast.dll scan --target 10.0.0.5 --output html

# Scan domain
docker compose exec asterion dotnet /app/ast.dll scan --target corp.local
```

**Note:** Asterion automatically detects Docker environment and saves:

-   Reports to `./reports/` (mounted from `docker/reports/`)
-   Database to `./data/argos.db` (mounted from `docker/data/argos.db`)

### Authenticated Scanning

```bash
# Windows domain authentication (LDAP/Kerberos/SMB)
docker compose exec asterion dotnet /app/ast.dll scan --target dc.corp.local --auth "DOMAIN\admin:P@ssw0rd"

# WinRM remote Windows checks (firewall, registry, services, AD, privesc)
docker compose exec asterion dotnet /app/ast.dll scan --target 192.168.1.10 --winrm "DOMAIN\admin:P@ssw0rd"

# SSH authentication for Linux hosts
docker compose exec asterion dotnet /app/ast.dll scan --target 10.0.0.25 --ssh "root:toor"

# SSH + sudo elevation
docker compose exec asterion dotnet /app/ast.dll scan --target 10.0.0.25 --ssh "admin:pass" --sudo-password "sudopass"

# Full scan: Windows WinRM + auth + AI
docker compose exec -e AI_API_KEY="sk-proj-..." asterion \
  dotnet /app/ast.dll scan --target dc.corp.local \
  --auth "DOMAIN\admin:P@ssw0rd" \
  --winrm "DOMAIN\admin:P@ssw0rd" \
  --use-ai --ai-tone technical -o both -v
```

### AI-Powered Analysis

Requires API key in `.env` file:

```bash
# Edit .env first — one key works for all providers (OpenAI, Anthropic, Ollama)
AI_API_KEY=sk-proj-...   # OpenAI key
# or
AI_API_KEY=sk-ant-...    # Anthropic key

# Run scan with AI analysis
docker compose exec asterion dotnet /app/ast.dll scan --target 10.0.0.0/24 --use-ai --output both

# Pass key at runtime without editing .env
docker compose exec -e AI_API_KEY="sk-proj-..." asterion \
  dotnet /app/ast.dll scan --target 10.0.0.5 --use-ai --ai-tone technical -o both
```

### Accessing Reports

**Linux/macOS:**

```bash
# List reports
ls -lh ../reports/

# View JSON report
cat ../reports/asterion_report_*_*.json | jq

# Open HTML report
xdg-open ../reports/asterion_report_*_*.html
```

**Windows:**

```powershell
# List reports
Get-ChildItem ..\reports\

# View JSON report
Get-Content ..\reports\asterion_report_*_*.json | ConvertFrom-Json

# Open HTML report
Start-Process ..\reports\asterion_report_*_*.html
```

---

## 🐛 Troubleshooting

### Permission Denied Errors (Linux/macOS)

**Problem:** Scanner cannot write to volumes

**Solution:**

```bash
# Fix permissions (run from project root)
# Container runs as root, so directories should be world-writable
sudo chmod -R 777 reports/ data/ logs/ workspace/

# Or make them owned by your user
sudo chown -R $USER:$USER reports/ data/ logs/ workspace/
```

### Container Fails to Start

**Diagnosis:**

```bash
# View logs
docker compose logs asterion

# Check container status
docker compose ps -a
```

**Common Causes:**

-   Missing `.env` file → Copy from `.env.example`
-   Port conflicts → Check if another service uses the same ports
-   Invalid Docker configuration → Verify docker-compose.yml syntax

### Cannot Scan Local Network (Windows/macOS)

**Problem:** Cannot reach local network (192.168.x.x, 10.x.x.x)

**Reason:** Bridge mode on Windows/macOS doesn't allow host network access

**Solutions:**

1. **Use Linux with host mode** (recommended for local network scans)
2. **Scan from host machine** (install Asterion natively)
3. **Use external IP** if scanning from internet

### Out of Memory Errors

**Solution:**

```bash
# Increase memory limit in .env
MEMORY_LIMIT=4G

# Restart
docker compose down && docker compose up -d
```

### AI Analysis Not Working

**Diagnosis:**

```bash
# Check API key is set
docker compose exec asterion env | grep API_KEY

# Test Python bridge
docker compose exec asterion python3 /app/scripts/ai_analyzer.py --help
```

**Solution:**

-   Ensure API key is set in `.env` file
-   Verify API key is valid (not expired)
-   Check network connectivity to AI provider

---

## 🔐 Security Notes

### Container Security

The container runs as **root** inside the container (standard for network security tools), but with **limited capabilities** instead of full privileged mode:

```yaml
cap_add:
    - NET_ADMIN # Network configuration
    - NET_RAW # Raw socket access (ICMP, SYN)
```

**Why root?**

-   Network scanning tools require low-level network access
-   Capabilities like `NET_RAW` require root privileges
-   Safer than `privileged: true` (which gives full host access)
-   Container isolation still provides security

### Capabilities vs Privileged Mode

✅ **Using specific capabilities** (current approach):

-   Only `NET_ADMIN` and `NET_RAW` permissions
-   Cannot access host devices
-   Cannot modify host kernel
-   **Recommended for security tools**

❌ **Using `privileged: true`** (NOT used):

-   Full access to host devices
-   Can modify host kernel
-   Security risk
-   **Avoided in Asterion**

### Ethical Scanning

**IMPORTANT:**

-   ✅ Only scan networks you own
-   ✅ Get written authorization before scanning
-   ❌ Never scan third-party networks without permission
-   ❌ Never exploit discovered vulnerabilities without explicit consent

---

## 📖 Additional Resources

-   **Main README**: [../README.md](../README.md)
-   **AI Integration**: [../docs/AI_INTEGRATION.md](../docs/AI_INTEGRATION.md)
-   **Ethics & Legal**: [../docs/ETHICS.md](../docs/ETHICS.md)
-   **Network Checks**: [../docs/NETWORK_CHECKS.md](../docs/NETWORK_CHECKS.md)

---

## 🤝 Support

For Docker-related issues:

-   **GitHub Issues**: https://github.com/rodhnin/asterion-network-minotaur/issues
-   **Contact**: https://rodhnin.com

---

**Asterion v0.2.0**
