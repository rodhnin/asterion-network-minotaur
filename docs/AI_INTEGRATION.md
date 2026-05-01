# 📘 **Asterion AI Integration Guide**

Asterion uses **LangChain v1.0.0+** to provide intelligent analysis of network security findings through Large Language Models (LLMs).

---

## 📖 **Overview**

The AI assistant generates two types of analysis from scan results:

1. **Executive Summary** (non-technical) - For business stakeholders, managers, C-suite
2. **Technical Remediation Guide** - For developers, system administrators, security engineers

Both are generated from the JSON scan report using carefully crafted prompts and sanitized input.

**Architecture:**

```
Asterion (C#) → JSON Report → Python Bridge (ai_analyzer.py) → LangChain → AI Provider → Enhanced Report
```

---

## 🔧 **Prerequisites**

### Required Dependencies

```bash
# Navigate to Asterion directory
cd ~/asterion-network-minotaur

# Install Python dependencies
pip install -r scripts/requirements.txt

# Or manually:
pip install langchain-core==1.0.0
pip install langchain-openai==1.0.0        # For OpenAI
pip install langchain-anthropic==1.0.0     # For Anthropic
pip install "langchain-ollama>=0.3.0,<0.4.0"  # For Ollama
```

### API Keys

Asterion uses a **single global environment variable** for all providers:

```bash
# For OpenAI or Anthropic (choose one)
export AI_API_KEY="sk-..."         # OpenAI key
# OR
export AI_API_KEY="sk-ant-..."     # Anthropic key

# For Ollama - No API key needed (local)
```

---

## ⚙️ **Configuration**

### Provider Selection

**Edit `config/defaults.yaml` to choose your AI provider:**

```yaml
ai:
    enabled: false # Enable via --use-ai flag
    langchain:
        provider: "openai" # Change to: openai, anthropic, or ollama
        model: "gpt-4o-mini-2024-07-18"
        temperature: 0.3
        max_tokens: 6144
        ollama_base_url: "http://localhost:11434" # For Ollama only
    api_key_env: "AI_API_KEY"
    prompts_dir: "config/prompts"
```

### Provider-Specific Configuration

#### **OpenAI (Default)**

```yaml
ai:
    langchain:
        provider: "openai"
        model: "gpt-4o-mini-2024-07-18" # or gpt-4o, gpt-4-turbo
        temperature: 0.3
        max_tokens: 6144
```

**Set API Key:**

```bash
export AI_API_KEY="sk-proj-..."
```

#### **Anthropic Claude (Privacy-Focused)**

```yaml
ai:
    langchain:
        provider: "anthropic"
        model: "claude-3-5-haiku-20241022" # or claude-3-5-sonnet-20241022, claude-3-opus
        temperature: 0.3
        max_tokens: 6144
```

**Set API Key:**

```bash
export AI_API_KEY="sk-ant-..."
```

#### **Ollama (100% Offline)**

```yaml
ai:
    langchain:
        provider: "ollama"
        model: "llama3.2:latest" # or llama3.2:3b (faster)
        temperature: 0.3
        max_tokens: 6144
        ollama_base_url: "http://localhost:11434"
```

**No API key needed** - fully local.

---

## 🚀 **Usage**

### Basic AI-Enhanced Scan

```bash
# 1. Set provider in config/defaults.yaml (see above)

# 2. Generate consent token (for aggressive mode)
ast consent generate --domain example.com

# 3. Verify consent
ast consent verify --method http --domain example.com --token verify-abc123

# 4. Run scan with AI analysis
ast scan \
  --target 192.168.100.30 \
  --ssh "user:password" \
  --mode safe \
  --use-ai \
  --verbose

# 5. Check enhanced report
open ~/.asterion/reports/asterion_report_192.168.100.30_*.html
```

### AI Tone Options

```bash
# Technical analysis only (default)
ast scan --target 192.168.100.30 --use-ai --ai-tone technical

# Executive summary only
ast scan --target 192.168.100.30 --use-ai --ai-tone non_technical

# Both analyses (comprehensive)
ast scan --target 192.168.100.30 --use-ai --ai-tone both
```

### AI Provider & Model Override

```bash
# Use a specific provider and model
ast scan --target 192.168.100.30 --use-ai --ai-provider anthropic --ai-model claude-3-5-sonnet-20241022

# Use local Ollama
ast scan --target 192.168.100.30 --use-ai --ai-provider ollama --ai-model llama3.2:latest
```

### AI Streaming (Real-Time Output)

```bash
# Stream tokens to console as they are generated
ast scan --target 192.168.100.30 --use-ai --ai-stream -v
```

### AI Agent Mode (NVD CVE Lookup)

```bash
# Agent autonomously searches NVD for CVEs matching detected software
ast scan --target 192.168.100.30 --ssh "root:Toor1234" --use-ai --ai-agent -v

# Check agent analysis in JSON
cat ~/.asterion/reports/asterion_report_*.json | jq '.agentAnalysis'
```

### AI Compare Mode (Multi-Model)

```bash
# Run analysis with two models and compare
ast scan --target 192.168.100.30 \
  --use-ai \
  --ai-compare "openai/gpt-4o-mini-2024-07-18,anthropic/claude-3-5-haiku-20241022"

# Check compare results in JSON
cat ~/.asterion/reports/asterion_report_*.json | jq '.compareResults'
```

### Budget Enforcement

```bash
# Abort AI analysis if it would cost more than $0.05
ast scan --target 192.168.100.20 --winrm "CORP\admin:pass" --use-ai --ai-budget 0.05
```

### HTML Report with AI

```bash
# Generate HTML report with AI analysis
ast scan \
  --target 192.168.100.30 \
  --ssh "root:password" \
  --use-ai \
  --output html \
  --verbose
```

---

## 🐍 **Python Bridge CLI Reference**

Asterion uses `scripts/ai_analyzer.py` as a standalone bridge between C# and LangChain.

### Standalone Usage (For Testing)

```bash
cd ~/asterion-network-minotaur

# Test with existing report
python scripts/ai_analyzer.py \
  --input ~/.asterion/reports/asterion_report_192.168.100.30_20251113_160321.json \
  --output /tmp/enhanced_report.json \
  --provider ollama \
  --model llama3.2:latest \
  --temperature 0.3 \
  --tone both \
  --verbose
```

### CLI Parameters

| Parameter       | Required | Description                                              | Default                  |
| --------------- | -------- | -------------------------------------------------------- | ------------------------ |
| `--input`       | ✅ Yes   | Input JSON report path                                   | -                        |
| `--output`      | ✅ Yes   | Output JSON report path                                  | -                        |
| `--provider`    | ❌ No    | AI provider (`openai`, `anthropic`, `ollama`)            | `openai`                 |
| `--model`       | ❌ No    | Model name                                               | `gpt-4o-mini-2024-07-18` |
| `--temperature` | ❌ No    | Temperature (0.0-1.0)                                    | `0.3`                    |
| `--max-tokens`  | ❌ No    | Max tokens to generate                                   | `6144`                   |
| `--tone`        | ❌ No    | Analysis tone (`technical`, `non_technical`, `both`)     | `technical`              |
| `--scan-id`     | ❌ No    | Scan ID for DB cost tracking                             | -                        |
| `--budget`      | ❌ No    | Abort if estimated cost exceeds this USD amount          | -                        |
| `--stream`      | ❌ No    | Stream tokens to stdout in real-time                     | `false`                  |
| `--agent`       | ❌ No    | Run in LangChain agent mode with NVD CVE lookup tool     | `false`                  |
| `--compare`     | ❌ No    | Comma-separated `provider/model` pairs for multi-compare | -                        |
| `--verbose`     | ❌ No    | Enable debug output                                      | `false`                  |

### Example: Test Ollama Integration

```bash
# 1. Generate a test report (without AI)
ast scan --target 192.168.100.30 --mode safe

# 2. Get report path from output
REPORT_PATH=~/.asterion/reports/asterion_report_192.168.100.30_*.json

# 3. Test AI analysis standalone
python scripts/ai_analyzer.py \
  --input "$REPORT_PATH" \
  --output /tmp/ai_test.json \
  --provider ollama \
  --model llama3.2:3b \
  --tone technical \
  --verbose

# 4. Check results
cat /tmp/ai_test.json | jq '.aiAnalysis'
```

---

## 🔒 **Privacy & Security**

### Data Sanitization

Before sending reports to AI, Asterion **automatically removes** sensitive information:

**What Gets Removed:**

- ✅ Consent tokens (`verify-abc123...`)
- ✅ Bearer tokens and API keys
- ✅ Passwords and credentials (`password=***REDACTED***`)
- ✅ SSH keys and private keys
- ✅ Long evidence snippets (truncated to 500 chars)

**What Gets Sent (Sanitized):**

- Finding IDs and titles
- Severity levels
- Redacted/truncated evidence
- Generic recommendations
- Target IP/hostname (for context)

### Privacy Recommendations

| Concern Level        | Recommended Provider | Why                                             |
| -------------------- | -------------------- | ----------------------------------------------- |
| **High Privacy**     | Ollama (local)       | Data never leaves your machine                  |
| **Moderate Privacy** | Anthropic Claude     | Strong privacy policy, no training on user data |
| **Standard**         | OpenAI GPT-4         | Best analysis quality, standard privacy         |

⚠️ **Note on Ollama:** While 100% private, local models may take **15-30 minutes per analysis** without GPU acceleration.

---

## 📊 **Provider Comparison**

### OpenAI GPT-4 (Default)

**Pros:**

- ✅ Best analysis quality
- ✅ Extensive network security knowledge
- ✅ Fast response (60–80s total including CVE enrichment)
- ✅ Handles complex multi-finding reports

**Cons:**

- ❌ Requires internet
- ❌ Costs money (~$0.004–0.009/scan with gpt-4o-mini)
- ❌ Data sent to OpenAI servers

**Best For:** Production reports, client deliverables, complex findings

---

### Anthropic Claude

**Pros:**

- ✅ Strong technical reasoning
- ✅ Good with code/config analysis
- ✅ Privacy-focused company
- ✅ Competitive pricing

**Cons:**

- ❌ Requires internet
- ❌ Costs money (~$0.01–0.03/scan with claude-3-5-haiku)
- ❌ Similar speed to GPT-4 (50–90s total)

**Best For:** Technical deep-dives, code-heavy findings, EU clients (GDPR)

---

### Ollama (Local Models)

**Pros:**

- ✅ 100% offline operation
- ✅ Complete privacy (no data leaves machine)
- ✅ Free (no API costs)
- ✅ No internet required

**Cons:**

- ❌ **Very slow without GPU** (15-30 min per analysis)
- ❌ Lower quality analysis (may miss nuances)
- ❌ May struggle with complex reports
- ❌ Requires local setup

**Best For:** Sensitive environments, air-gapped networks, learning/testing

---

### Performance Comparison

| Provider                         | Technical Analysis | Total Time  | Quality    |
| -------------------------------- | ------------------ | ----------- | ---------- |
| **OpenAI gpt-4o-mini** (default) | ~60–80s            | **~60–80s** | ⭐⭐⭐⭐   |
| **OpenAI gpt-4o**                | ~40–60s            | **~40–60s** | ⭐⭐⭐⭐⭐ |
| **Anthropic claude-3-5-haiku**   | ~50–70s            | **~50–70s** | ⭐⭐⭐⭐   |
| **Anthropic claude-3-5-sonnet**  | ~60–90s            | **~60–90s** | ⭐⭐⭐⭐⭐ |
| **Ollama (CPU)**                 | ~15min             | **~30min**  | ⭐⭐⭐     |
| **Ollama (GPU)**                 | ~45s               | **~75s**    | ⭐⭐⭐     |

_Based on real scans: 29–34 findings with full CVE enrichment context (~40–46k input tokens)._

---

## 🦙 **Ollama Setup Guide**

For **100% offline operation** with local models:

### Installation

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Start Ollama server
ollama serve &

# 3. Pull a model
ollama pull llama3.2  # 2 GB

# 4. Verify installation
ollama list

# Expected Output:
# NAME                ID              SIZE
# llama3.2:latest     a80c4f17acd5    2 GB
```

### Configuration

**Edit `config/defaults.yaml`:**

```yaml
ai:
    langchain:
        provider: "ollama"
        model: "llama3.2:latest"
        temperature: 0.3
        max_tokens: 6144
        ollama_base_url: "http://localhost:11434"
```

### Test Integration

```bash
# Run a quick scan with AI
ast scan \
  --target localhost \
  --mode safe \
  --use-ai \
  --ai-tone technical \
  --verbose

# Watch progress in logs
# Expected: "ℹ️ Invoking AI model... (this may take a while)"
# Wait time: ~15 minutes (CPU) or ~45 seconds (GPU)
```

### Recommended Models

| Model             | Size  | Speed (CPU)     | Quality  | Best For      |
| ----------------- | ----- | --------------- | -------- | ------------- |
| `llama3.2:latest` | 4.7GB | Slow (~15min)   | ⭐⭐⭐⭐ | Production    |
| `llama3.2:3b`     | 2.0GB | Faster (~10min) | ⭐⭐⭐   | Testing       |
| `mistral:latest`  | 4.1GB | Slow (~14min)   | ⭐⭐⭐⭐ | Code analysis |
| `phi3:latest`     | 2.2GB | Fastest (~8min) | ⭐⭐     | Quick tests   |

---

## 📝 **Custom Prompts**

Prompts are stored in `config/prompts/`:

### Technical Prompt (`technical.txt`)

**Purpose:** Generate step-by-step remediation guide for security engineers

**Structure:**

- Risk assessment
- Command examples
- Verification methods
- Testing procedures

**Edit to customize:**

```bash
nano config/prompts/technical.txt
```

---

### Non-Technical Prompt (`non_technical.txt`)

**Purpose:** Generate executive summary for business stakeholders

**Structure:**

- Business impact
- Plain language explanations
- Executive actions
- Timeline recommendations

**Edit to customize:**

```bash
nano config/prompts/non_technical.txt
```

---

## 🐛 **Troubleshooting**

### Common Issues

#### ❌ "AI_API_KEY environment variable not set"

**Solution:**

```bash
# Insert
export AI_API_KEY="sk-proj-..."

# Verify
echo $AI_API_KEY

# Make permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export AI_API_KEY="sk-..."' >> ~/.bashrc
source ~/.bashrc
```

---

#### ❌ "Ollama server not responding at http://localhost:11434"

**Solution:**

```bash
# Check if Ollama is running
ps aux | grep ollama

# Start Ollama server
ollama serve &

# Verify it's listening
curl http://localhost:11434/api/tags

# Expected Output:
# {"models":[{"name":"llama3.2:latest",...}]}
```

---

#### ❌ "Model 'llama3.2:latest' not found in Ollama"

**Solution:**

```bash
# List available models
ollama list

# Pull the model
ollama pull llama3.2

# Verify
ollama list | grep llama3.2:latest
```

---

#### ❌ "HTTPConnectionPool: Read timed out"

**Cause:** Ollama taking too long (model is slow or system is underpowered)

**Solutions:**

```bash
# Option 1: Use smaller/faster model
ollama pull llama3.2:3b
# Update config/defaults.yaml: model: "llama3.2:3b"

# Option 2: Use GPU acceleration (if available)
# Ollama auto-detects NVIDIA GPUs

# Option 3: Increase timeout (already 1800s / 30 min)
# Edit scripts/ai_analyzer.py line ~175:
# timeout=1800 → timeout=3600 (1 hour)

# Option 4: Switch to cloud provider
export AI_API_KEY="sk-proj-..."
# Edit config/defaults.yaml: provider: "openai"
```

---

#### ❌ "Python bridge failed (exit code 1)"

**Solution:**

```bash
# Test Python bridge standalone
python scripts/ai_analyzer.py \
  --input ~/.asterion/reports/asterion_report_*.json \
  --output /tmp/test.json \
  --provider ollama \
  --verbose

# Check for missing dependencies
pip install -r scripts/requirements.txt --upgrade

# Check Python version (3.8+ required)
python --version
```

---

## 💰 **Cost Management**

### Token Usage Estimates

Based on real scans with `gpt-4o-mini-2024-07-18` (default model):

| Report Size          | Input Tokens | Output Tokens | Total Tokens | Cost (gpt-4o-mini) |
| -------------------- | ------------ | ------------- | ------------ | ------------------ |
| Small (12 findings)  | ~16,000      | ~3,000        | ~19,000      | ~$0.004            |
| Medium (29 findings) | ~40,000      | ~2,400        | ~42,000      | ~$0.007            |
| Large (34 findings)  | ~46,000      | ~3,200        | ~49,000      | ~$0.009            |

_Based on `--ai-tone technical` (single analysis). Using `--ai-tone both` approximately doubles cost._

> **Note:** Input tokens are high because CVE enrichment + OWASP/compliance mapping data is included in the prompt context per finding. This ensures the AI has full context for accurate remediation guidance.

### AI Cost Tracking

AI costs are automatically recorded in two places:

```bash
# 1. Shared Argos Suite costs file
cat ~/.argos/costs.json

# 2. Database table (per-analysis breakdown)
sqlite3 ~/.argos/argos.db "SELECT scan_id, provider, model, analysis_type, input_tokens, output_tokens, cost_usd FROM ai_costs ORDER BY cost_id DESC LIMIT 10;"
```

### Budget Enforcement

```bash
# Abort if AI analysis would cost more than $0.05
ast scan --target 192.168.100.20 --winrm "CORP\admin:pass" --use-ai --ai-budget 0.05
```

### Cost Reduction Tips

```bash
# 1. Use single analysis (50% cost reduction)
ast scan --target 192.168.100.30 --use-ai --ai-tone technical

# 2. Use cheaper model
# Edit config/defaults.yaml:
# OpenAI: model: "gpt-3.5-turbo"  # ~70% cheaper
# Anthropic: model: "claude-3-haiku"  # ~80% cheaper

# 3. Use Ollama for testing (100% free)
# Edit config/defaults.yaml: provider: "ollama"

# 4. Reduce rate limit (fewer findings = lower cost)
ast scan --target 192.168.100.30 --rate 2.0 --use-ai
```

---

## ✅ **Best Practices**

### 1. Choose Right Provider for Context

| Scenario         | Recommended Provider | Reason                     |
| ---------------- | -------------------- | -------------------------- |
| Client reports   | OpenAI GPT-4         | Best quality, professional |
| Internal testing | Ollama               | Free, private              |
| Quick analysis   | OpenAI GPT-3.5-turbo | Fast & cheap               |
| Sensitive data   | Ollama               | 100% offline               |
| EU/GDPR clients  | Anthropic Claude     | Privacy-focused            |
| Budget-conscious | Ollama               | Free (local)               |

---

### 2. Review AI Output

**Always verify:**

- ✅ Technical commands are correct for target OS
- ✅ Version numbers match actual findings
- ✅ Remediation steps are complete and tested
- ✅ No hallucinated CVEs or references
- ✅ Risk assessments align with severity

---

### 3. Optimize for Your Use Case

```bash
# Production (Quality)
ast scan --target prod.example.com --use-ai --ai-tone both --output html

# Development (Speed)
ast scan --target dev.example.com --use-ai --ai-tone technical

# Testing (Privacy)
# Set provider: "ollama" in config/defaults.yaml
ast scan --target staging.example.com --use-ai
```

---

## 📚 **Examples**

### Example 1: Full Scan with AI (OpenAI)

```bash
# 1. Configure OpenAI
export AI_API_KEY="sk-proj-..."
nano config/defaults.yaml
# Set: provider: "openai", model: "gpt-4o-mini-2024-07-18"

# 2. Generate consent
ast consent generate --domain example.com

# 3. Verify consent
ast consent verify --method http --domain example.com --token verify-abc123

# 4. Run comprehensive scan
ast scan \
  --target 192.168.100.30 \
  --ssh "admin:password" \
  --mode aggressive \
  --use-ai \
  --ai-tone both \
  --output html \
  --verbose

# 5. Check results
open ~/.asterion/reports/asterion_report_192.168.100.30_*.html
```

**Expected Output:**

```
[17:03:21] Scan completed in 6.95s
[17:03:21] Total findings: 26 (5C/7H/7M/3L/4I)
[17:03:22] Generating BOTH technical and non-technical analyses...
[17:04:02] ✓ Technical analysis completed in 39.5s
[17:04:42] ✓ Executive summary completed in 40.1s
[17:04:43] ✓ AI analysis generated successfully
[17:04:43]   Provider: openai
[17:04:43]   Model: gpt-4o-mini-2024-07-18
[17:04:43]   Cost: $0.014 (49,200 tokens)
[17:04:43] ✓ HTML report saved
```

---

### Example 2: Quick Test with Ollama

```bash
# 1. Setup Ollama
ollama pull llama3.2:latest  # Faster model

# 2. Configure Asterion
nano config/defaults.yaml
# Set: provider: "ollama", model: "llama3.2:latest"

# 3. Run quick scan (technical only)
ast scan \
  --target localhost \
  --mode safe \
  --use-ai \
  --ai-tone technical \
  --verbose

# 4. Wait patiently (10-15 minutes on CPU)
# ℹ️ Invoking AI model... (this may take a while)
```

---

### Example 3: Standalone Python Bridge Test

```bash
# 1. Run a scan without AI
ast scan --target 192.168.100.30 --mode safe

# 2. Get report path
REPORT=$(ls -t ~/.asterion/reports/*.json | head -1)
echo "Testing with: $REPORT"

# 3. Test AI analysis standalone
python scripts/ai_analyzer.py \
  --input "$REPORT" \
  --output /tmp/ai_test.json \
  --provider ollama \
  --model llama3.2:3b \
  --tone both \
  --verbose

# 4. Check AI analysis
cat /tmp/ai_test.json | jq '.aiAnalysis.technicalRemediation' | head -50
```

---

## 📖 **Additional Resources**

- 📚 [LangChain v1.0 Documentation](https://python.langchain.com/docs/)
- 🤖 [OpenAI Platform](https://platform.openai.com/)
- 🔍 [Anthropic Claude](https://docs.anthropic.com/)
- 🦙 [Ollama Documentation](https://ollama.com/)
- 🐂 [Asterion GitHub](https://github.com/rodhnin/asterion-network-minotaur)

---

## 🆘 **Support**

For AI-related issues:

- **GitHub Issues:** https://github.com/rodhnin/asterion-network-minotaur/issues
- **Contact:** https://rodhnin.com
- **Tag:** `ai-integration` in issue title

---

**Last Updated:** May 2026
**Asterion Version:** 0.2.0
**LangChain Version:** 1.0.0+
