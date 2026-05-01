#!/usr/bin/env python3
"""
AI Analysis Bridge for Asterion Network Security Auditor
Part of the Argos Security Suite

v0.2.0 features:
- IMPROV-005: Cost tracking and budget enforcement (AICostTracker, PRICING_TABLE)
- IMPROV-006: Streaming output (--stream flag)
- IMPROV-007: Multi-LLM comparison mode (--compare flag)
- IMPROV-008: Agent mode with NVD CVE lookup for network services (--agent flag)

AI flows:
  Standard:  prompt | llm | parser  (technical + non_technical, cost tracked)
  Streaming: chain.stream() → tokens to stdout in real-time
  Agent:     manual tool-call loop with NVD tools adapted for network security
  Compare:   ThreadPoolExecutor → multiple providers in parallel

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import argparse
import copy
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

try:
    from langchain_core.prompts import PromptTemplate
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.messages import HumanMessage, SystemMessage
    HAS_LANGCHAIN_CORE = True
except ImportError as e:
    print(f"ERROR: Missing langchain-core: {e}", file=sys.stderr)
    print("Install with: pip install langchain-core>=1.0.0", file=sys.stderr)
    sys.exit(1)

try:
    from langchain_openai import ChatOpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

try:
    from langchain_anthropic import ChatAnthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

try:
    from langchain_ollama import ChatOllama, OllamaLLM
    HAS_OLLAMA = True
except ImportError:
    try:
        from langchain_community.chat_models import ChatOllama
        from langchain_community.llms import Ollama as OllamaLLM
        HAS_OLLAMA = True
    except ImportError:
        HAS_OLLAMA = False

# CVE enrichment and OWASP mapping (same scripts/ directory)
_SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(_SCRIPT_DIR))

try:
    from cve_lookup import enrich_findings
    HAS_CVE_LOOKUP = True
except ImportError:
    HAS_CVE_LOOKUP = False

try:
    from owasp import enrich_findings_with_owasp
    HAS_OWASP = True
except ImportError:
    HAS_OWASP = False

try:
    from compliance import enrich_findings_with_compliance
    HAS_COMPLIANCE = True
except ImportError:
    HAS_COMPLIANCE = False


# =============================================================================
# IMPROV-005: Pricing Table (identical to Hephaestus/Argus — shared Argos Suite)
# =============================================================================

PRICING_TABLE = {
    'openai': {
        'gpt-4o-mini-2024-07-18':    {'input': 0.15,  'output': 0.60},   # Default (cheap, fast)
        'gpt-4o-2024-11-20':         {'input': 2.50,  'output': 10.00},
        'gpt-4o-2024-08-06':         {'input': 2.50,  'output': 10.00},
        'gpt-4-turbo-preview':       {'input': 10.00, 'output': 30.00},
        'gpt-4-turbo':               {'input': 10.00, 'output': 30.00},
        'gpt-4':                     {'input': 30.00, 'output': 60.00},
        'gpt-3.5-turbo':             {'input': 0.50,  'output': 1.50},
    },
    'anthropic': {
        'claude-3-5-sonnet-20241022': {'input': 3.00,  'output': 15.00},
        'claude-3-5-haiku-20241022':  {'input': 0.80,  'output': 4.00},
        'claude-3-opus-20240229':     {'input': 15.00, 'output': 75.00},
        'claude-3-sonnet-20240229':   {'input': 3.00,  'output': 15.00},
        'claude-3-haiku-20240307':    {'input': 0.25,  'output': 1.25},
    },
    'ollama': {},  # Local models — no cost
}


# =============================================================================
# IMPROV-005: Cost Tracker (same pattern as Hephaestus/Argus — shared Argos Suite)
# =============================================================================

class AIAuthError(Exception):
    """Raised when the AI provider rejects the API key (HTTP 401 / invalid_api_key).
    Signals to the CLI entry point to exit with code 2 so C# can show an actionable message.
    """
    def __init__(self, provider: str, detail: str):
        self.provider = provider
        self.detail   = detail
        super().__init__(f"Authentication failed for provider '{provider}': {detail}")


class AICostTracker:
    """
    Tracks AI token usage and costs across a scan session.
    Calculates costs from PRICING_TABLE, enforces budget limits,
    and persists results to ~/.argos/costs.json (shared with Argus/Hephaestus).
    """

    def __init__(
        self,
        budget_usd: Optional[float] = None,
        warn_threshold: float = 0.8,
        abort_on_exceed: bool = False,
    ):
        self._budget         = budget_usd if budget_usd and budget_usd > 0 else None
        self._warn_threshold = warn_threshold
        self._abort_on_exceed = abort_on_exceed
        self._breakdown: Dict[str, Dict] = {}
        self._total_cost: float = 0.0
        self._total_input: int = 0
        self._total_output: int = 0

    def calculate_cost(
        self, provider: str, model: str, input_tokens: int, output_tokens: int
    ) -> float:
        """Calculate USD cost for a given token usage. Returns 0.0 for unknown models."""
        pricing = PRICING_TABLE.get(provider, {}).get(model)
        if not pricing:
            if provider != 'ollama':
                print(
                    f"  WARNING: No pricing data for {provider}/{model} — cost recorded as $0.00",
                    file=sys.stderr,
                )
            return 0.0
        cost = (input_tokens * pricing['input'] + output_tokens * pricing['output']) / 1_000_000
        return round(cost, 6)

    def record(
        self,
        label: str,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        duration_s: float,
    ) -> float:
        """Record a completed analysis call. Returns the cost for this call."""
        cost = self.calculate_cost(provider, model, input_tokens, output_tokens)
        self._breakdown[label] = {
            'input_tokens':  input_tokens,
            'output_tokens': output_tokens,
            'cost_usd':      cost,
            'duration_s':    round(duration_s, 2),
        }
        self._total_cost   += cost
        self._total_input  += input_tokens
        self._total_output += output_tokens
        return cost

    def check_budget(self) -> Tuple[bool, bool, bool]:
        """
        Check budget status after latest accumulation.

        Returns:
            (within_budget, at_warning_threshold, should_abort)
        """
        if not self._budget:
            return True, False, False

        warn_at  = self._budget * self._warn_threshold
        exceeded = self._total_cost >= self._budget
        at_warn  = self._total_cost >= warn_at

        should_abort = exceeded and self._abort_on_exceed
        return not exceeded, at_warn, should_abort

    def print_summary(self):
        """Print cost breakdown to stderr after analysis."""
        if not self._breakdown:
            return
        print("", file=sys.stderr)
        print("  AI Cost Summary:", file=sys.stderr)
        for label, info in self._breakdown.items():
            total_tokens = info['input_tokens'] + info['output_tokens']
            print(
                f"    {label}: {total_tokens:,} tokens "
                f"(in={info['input_tokens']:,} out={info['output_tokens']:,}) "
                f"-> ${info['cost_usd']:.4f}  [{info['duration_s']:.1f}s]",
                file=sys.stderr,
            )
        total_tokens = self._total_input + self._total_output
        print(f"    Total: {total_tokens:,} tokens -> ${self._total_cost:.4f}", file=sys.stderr)
        if self._budget:
            used_pct = (self._total_cost / self._budget) * 100
            print(
                f"    Budget: ${self._total_cost:.4f} / ${self._budget:.4f} ({used_pct:.0f}% used)",
                file=sys.stderr,
            )

    def save_to_file(self, scan_id: Optional[int], provider: str, model: str):
        """Append cost record to ~/.argos/costs.json (shared with Argus/Hephaestus)."""
        costs_path = Path.home() / '.argos' / 'costs.json'
        costs_path.parent.mkdir(parents=True, exist_ok=True)

        record = {
            'scan_id':        scan_id,
            'timestamp':      datetime.now(timezone.utc).isoformat(),
            'tool':           'asterion',
            'provider':       provider,
            'model':          model,
            'breakdown':      self._breakdown,
            'total_cost_usd': round(self._total_cost, 6),
            'total_tokens':   self._total_input + self._total_output,
            'duration_s':     sum(v.get('duration_s', 0) for v in self._breakdown.values()),
        }

        try:
            if costs_path.exists():
                with costs_path.open('r', encoding='utf-8') as fh:
                    data = json.load(fh)
            else:
                data = {'scans': [], 'totals': {}}

            data['scans'].append(record)

            all_costs = [s['total_cost_usd'] for s in data['scans']]
            total_cost = sum(all_costs)
            n = len(data['scans'])
            data['totals'] = {
                'total_scans':        n,
                'total_cost_usd':     round(total_cost, 4),
                'avg_cost_per_scan':  round(total_cost / n, 6) if n else 0.0,
                'monthly_projection': round((total_cost / max(n, 1)) * 30, 4),
            }

            with costs_path.open('w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2)

            print(f"  Cost record saved to {costs_path}", file=sys.stderr)

        except Exception as e:
            print(f"  WARNING: Could not save cost record: {e}", file=sys.stderr)

    def save_to_db(self, scan_id: Optional[int], provider: str, model: str):
        """Insert per-analysis cost rows into ~/.argos/argos.db ai_costs table."""
        import sqlite3
        db_path = Path.home() / '.argos' / 'argos.db'
        if not db_path.exists():
            return
        try:
            conn = sqlite3.connect(str(db_path))
            try:
                for analysis_type, rec in self._breakdown.items():
                    conn.execute(
                        """
                        INSERT INTO ai_costs
                            (scan_id, provider, model, analysis_type,
                             input_tokens, output_tokens, total_tokens,
                             cost_usd, duration_s)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scan_id,
                            provider,
                            model,
                            analysis_type,
                            rec.get('input_tokens', 0),
                            rec.get('output_tokens', 0),
                            rec.get('input_tokens', 0) + rec.get('output_tokens', 0),
                            round(rec.get('cost_usd', 0.0), 8),
                            round(rec.get('duration_s', 0.0), 2),
                        ),
                    )
                conn.commit()
                print(f"  Cost record saved to argos.db (scan_id={scan_id})", file=sys.stderr)
            finally:
                conn.close()
        except Exception as e:
            print(f"  WARNING: Could not save cost to DB: {e}", file=sys.stderr)

    @property
    def total_cost(self) -> float:
        return self._total_cost

    @property
    def breakdown(self) -> Dict:
        return dict(self._breakdown)


# =============================================================================
# IMPROV-008: Agent Tools (network-security focused, adapted from Hephaestus)
# =============================================================================

def _make_nvd_tool():
    """Create a NVD CVE lookup tool."""
    try:
        from langchain_core.tools import tool
        import requests as _requests

        @tool
        def lookup_nvd_cve(cve_id: str) -> str:
            """
            Look up CVE details from the National Vulnerability Database (NVD).
            Input: a CVE identifier like CVE-2023-12345.
            Returns severity, CVSS score, and description.
            """
            try:
                resp = _requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={'cveId': cve_id.strip()},
                    timeout=10,
                    headers={'User-Agent': 'Asterion-Network-Scanner/0.2.0'},
                )
                if resp.status_code != 200:
                    return f"NVD lookup failed (HTTP {resp.status_code})"

                data  = resp.json()
                vulns = data.get('vulnerabilities', [])
                if not vulns:
                    return f"No NVD record found for {cve_id}"

                cve      = vulns[0].get('cve', {})
                desc_en  = next(
                    (d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'),
                    'No description',
                )
                metrics  = cve.get('metrics', {})
                cvss_v3  = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
                score    = 'N/A'
                severity = 'N/A'
                if cvss_v3:
                    d      = cvss_v3[0].get('cvssData', {})
                    score  = d.get('baseScore', 'N/A')
                    severity = d.get('baseSeverity', 'N/A')
                published = cve.get('published', 'N/A')[:10]
                return (
                    f"CVE: {cve_id}\n"
                    f"Severity: {severity} (CVSS {score})\n"
                    f"Published: {published}\n"
                    f"Description: {desc_en[:500]}"
                )
            except Exception as e:
                return f"NVD lookup error for {cve_id}: {e}"

        return lookup_nvd_cve
    except ImportError:
        return None


def _make_network_vuln_tool():
    """
    Create a network service vulnerability search tool using NVD.
    Searches for CVEs in network services: Samba, OpenSSH, Kerberos, SNMP, LDAP, FTP, RDP.
    """
    try:
        from langchain_core.tools import tool
        import requests as _requests

        @tool
        def search_network_service_vulns(service_name: str) -> str:
            """
            Search NVD for known vulnerabilities in a network service or protocol.
            Input: service name and version, e.g. 'Samba 4.15.0', 'OpenSSH 8.9', 'vsftpd 3.0.5'.
            Returns recent CVEs, severity scores, and affected versions.
            """
            try:
                resp = _requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={
                        'keywordSearch':  service_name.strip(),
                        'resultsPerPage': 5,
                        'pubStartDate':   '2020-01-01T00:00:00.000',
                    },
                    timeout=10,
                    headers={'User-Agent': 'Asterion-Network-Scanner/0.2.0'},
                )
                if resp.status_code != 200:
                    return f"NVD search failed (HTTP {resp.status_code})"

                data  = resp.json()
                vulns = data.get('vulnerabilities', [])
                total = data.get('totalResults', 0)
                if not vulns:
                    return f"No NVD records found for '{service_name}'"

                lines = [
                    f"NVD results for '{service_name}': {total} total CVEs "
                    f"(showing top {len(vulns)})"
                ]
                for item in vulns:
                    cve     = item.get('cve', {})
                    cve_id  = cve.get('id', 'N/A')
                    desc_en = next(
                        (d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'),
                        'No description',
                    )
                    metrics = cve.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
                    score   = 'N/A'
                    sev     = 'N/A'
                    if cvss_v3:
                        d     = cvss_v3[0].get('cvssData', {})
                        score = d.get('baseScore', 'N/A')
                        sev   = d.get('baseSeverity', 'N/A')
                    pub = cve.get('published', 'N/A')[:10]
                    lines.append(f"  [{cve_id}] {sev} (CVSS {score}) [{pub}]: {desc_en[:200]}")

                return '\n'.join(lines)

            except Exception as e:
                return f"Network service vulnerability search error: {e}"

        return search_network_service_vulns
    except ImportError:
        return None


# =============================================================================
# Main AI Analyzer
# =============================================================================

class AsterionAIAnalyzer:
    """
    LangChain v1.0.0 AI analyzer for Asterion network security reports.
    Uses LCEL (LangChain Expression Language) exclusively.

    v0.2.0 features:
    - IMPROV-005: Cost tracking and budget enforcement
    - IMPROV-006: Streaming output
    - IMPROV-007: Multi-LLM comparison mode
    - IMPROV-008: Agent mode with NVD CVE lookup for network services
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o-mini-2024-07-18",
        temperature: float = 0.3,
        max_tokens: int = 6144,
        tone: str = "technical",
        streaming: bool = False,
        cost_tracker: Optional[AICostTracker] = None,
    ):
        if not HAS_LANGCHAIN_CORE:
            raise ImportError("langchain-core required. Install: pip install langchain-core>=1.0.0")

        self.provider     = provider.lower()
        self.model        = model
        self.temperature  = temperature
        self.max_tokens   = max_tokens
        self.tone         = tone.lower()
        self.streaming    = streaming
        self.cost_tracker = cost_tracker

        self._sync_api_keys()
        self.llm           = self._create_llm()
        self.output_parser = StrOutputParser()
        self.prompt_text   = self._load_prompt_template()

        print(f"✓ AI analyzer initialized: {self.provider}/{self.model}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Initialization helpers
    # ------------------------------------------------------------------

    def _sync_api_keys(self):
        """No-op: AI_API_KEY is the only supported key variable."""
        pass

    def _validate_api_key(self):
        if self.provider in ("openai", "anthropic"):
            if not os.getenv("AI_API_KEY"):
                raise ValueError(
                    f"API key not found for {self.provider}. "
                    f"Set AI_API_KEY environment variable: export AI_API_KEY='your-key'"
                )

    def _create_llm(self):
        """Create LangChain LLM instance based on provider."""
        self._validate_api_key()

        if self.provider == "openai":
            if not HAS_OPENAI:
                raise ImportError("Install: pip install langchain-openai>=1.0.0")
            return ChatOpenAI(
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                streaming=self.streaming,
                api_key=os.getenv("AI_API_KEY"),
            )

        elif self.provider == "anthropic":
            if not HAS_ANTHROPIC:
                raise ImportError("Install: pip install langchain-anthropic>=1.0.0")
            return ChatAnthropic(
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                timeout=60,
                max_retries=2,
                streaming=self.streaming,
                api_key=os.getenv("AI_API_KEY"),
            )

        elif self.provider == "ollama":
            if not HAS_OLLAMA:
                raise ImportError("Install: pip install langchain-ollama>=0.3.0")
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            try:
                import requests
                resp = requests.get(f"{base_url}/api/tags", timeout=5)
                if resp.status_code != 200:
                    raise ConnectionError(f"Ollama not responding at {base_url}")
                model_names = [m['name'] for m in resp.json().get('models', [])]
                if self.model not in model_names:
                    available = ', '.join(model_names) or 'none'
                    raise ValueError(
                        f"Model '{self.model}' not found in Ollama.\n"
                        f"Available: {available}\n"
                        f"Pull it: ollama pull {self.model}"
                    )
            except requests.exceptions.RequestException as e:
                raise ConnectionError(
                    f"Cannot connect to Ollama at {base_url}.\n"
                    f"Start it: ollama serve\n"
                    f"Error: {e}"
                )
            print(f"✓ Validated Ollama model: {self.model}", file=sys.stderr)
            try:
                return ChatOllama(
                    model=self.model,
                    base_url=base_url,
                    temperature=self.temperature,
                    num_predict=self.max_tokens,
                    num_ctx=8192,
                    repeat_penalty=1.1,
                    top_k=40,
                    top_p=0.9,
                    timeout=1800,
                    verbose=False,
                )
            except Exception:
                return OllamaLLM(
                    model=self.model,
                    base_url=base_url,
                    temperature=self.temperature,
                    num_predict=self.max_tokens,
                    num_ctx=8192,
                    verbose=False,
                )
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def _load_prompt_for_tone(self, tone: str) -> str:
        """Load a specific prompt template by tone name."""
        filename = f"{tone}.txt"
        search_paths = [
            Path("config/prompts") / filename,
            Path(__file__).parent.parent / "config" / "prompts" / filename,
            Path.cwd() / "config" / "prompts" / filename,
        ]
        for path in search_paths:
            if path.exists():
                content = path.read_text(encoding='utf-8')
                print(f"✓ Loaded prompt from {path}", file=sys.stderr)
                return content
        raise FileNotFoundError(f"Prompt template not found: {filename}")

    def _load_prompt_template(self) -> str:
        """Load prompt template from config/prompts/.
        For tone='both', loads 'technical.txt' as the default;
        analyze_both() loads non_technical.txt separately.
        """
        load_tone = self.tone if self.tone != 'both' else 'technical'
        return self._load_prompt_for_tone(load_tone)

    # ------------------------------------------------------------------
    # Report sanitization
    # ------------------------------------------------------------------

    def sanitize_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize report before sending to AI provider.
        Removes consent tokens, private keys, certificates, credentials,
        and truncates long evidence.
        """
        sanitized = copy.deepcopy(report)
        sanitized.pop('consent', None)

        for finding in sanitized.get('findings', []):
            evidence = finding.get('evidence', {})
            if not evidence:
                continue

            val = evidence.get('value', '')
            if not val:
                continue

            # Redact tokens & credentials
            val = re.sub(r'verify-[a-f0-9]{16}', '[REDACTED-TOKEN]', val, flags=re.IGNORECASE)
            val = re.sub(r'Bearer\s+[A-Za-z0-9\-_\.]+', '[REDACTED-TOKEN]', val, flags=re.IGNORECASE)
            val = re.sub(r'sk-[A-Za-z0-9]{48}', '[REDACTED-TOKEN]', val, flags=re.IGNORECASE)
            val = re.sub(r'(password["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]', val, flags=re.IGNORECASE)
            val = re.sub(r'(api[_-]?key["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]', val, flags=re.IGNORECASE)
            val = re.sub(r'(secret["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]', val, flags=re.IGNORECASE)

            # Redact private keys and certificates
            val = re.sub(
                r'(-----BEGIN.*?PRIVATE KEY-----)(.*?)(-----END.*?PRIVATE KEY-----)',
                r'\1\n[REDACTED]\n\3', val, flags=re.DOTALL | re.IGNORECASE,
            )
            val = re.sub(
                r'(-----BEGIN CERTIFICATE-----)(.*?)(-----END CERTIFICATE-----)',
                r'\1\n[REDACTED]\n\3', val, flags=re.DOTALL | re.IGNORECASE,
            )

            # Truncate long evidence
            max_len = 500
            if len(val) > max_len:
                val = val[:max_len] + '... [truncated]'

            evidence['value'] = val

        # Inject computed total
        if 'summary' in sanitized:
            total = sum(v for k, v in sanitized['summary'].items() if not k.startswith('_'))
            sanitized['summary']['_total_findings'] = total

        return sanitized

    # ------------------------------------------------------------------
    # IMPROV-005/006: Core invoke with cost tracking + streaming
    # ------------------------------------------------------------------

    def _invoke_with_tracking(
        self,
        prompt_template: PromptTemplate,
        inputs: Dict,
        label: str,
    ) -> str:
        """
        Invoke a prompt + LLM chain with token tracking.
        IMPROV-005: captures usage_metadata for cost calculation.
        IMPROV-006: streams output when self.streaming is True.
        """
        if self.cost_tracker:
            within, at_warn, should_abort = self.cost_tracker.check_budget()
            if should_abort:
                raise RuntimeError(
                    f"AI budget exceeded: "
                    f"${self.cost_tracker.total_cost:.4f} >= "
                    f"${self.cost_tracker._budget:.4f}. Aborting."
                )
            if at_warn:
                print(
                    f"  WARNING: AI cost at "
                    f"${self.cost_tracker.total_cost:.4f} / "
                    f"${self.cost_tracker._budget:.4f} (80% threshold reached)",
                    file=sys.stderr,
                )

        start = time.time()

        if self.streaming:
            text     = self._stream_output(prompt_template, inputs, label)
            duration = time.time() - start
            # Estimate tokens from text length when streaming
            input_tokens  = 0
            output_tokens = max(1, len(text) // 4)
        else:
            text, input_tokens, output_tokens = self._invoke_and_capture(prompt_template, inputs)
            duration = time.time() - start

        if self.cost_tracker:
            cost = self.cost_tracker.record(
                label, self.provider, self.model,
                input_tokens, output_tokens, duration,
            )
            print(
                f"  {label}: {input_tokens + output_tokens:,} tokens -> ${cost:.4f}  [{duration:.1f}s]",
                file=sys.stderr,
            )

        return text

    def _invoke_and_capture(
        self,
        prompt_template: PromptTemplate,
        inputs: Dict,
    ) -> Tuple[str, int, int]:
        """Standard invoke; extracts token usage from AIMessage metadata."""
        chain_to_llm = prompt_template | self.llm
        ai_message   = chain_to_llm.invoke(inputs)
        text         = self.output_parser.invoke(ai_message)

        usage = getattr(ai_message, 'usage_metadata', None) or {}
        input_tokens  = usage.get('input_tokens',  0)
        output_tokens = usage.get('output_tokens', 0)

        if not input_tokens and not output_tokens:
            resp_meta = getattr(ai_message, 'response_metadata', {}) or {}
            usage2 = resp_meta.get('usage', resp_meta.get('token_usage', {}))
            input_tokens  = usage2.get('input_tokens',  usage2.get('prompt_tokens',     0))
            output_tokens = usage2.get('output_tokens', usage2.get('completion_tokens', 0))

        # Ollama / unknown providers: estimate from output length
        if not input_tokens and not output_tokens:
            output_tokens = max(1, len(text) // 4)

        return text.strip(), input_tokens, output_tokens

    def _stream_output(
        self,
        prompt_template: PromptTemplate,
        inputs: Dict,
        label: str,
    ) -> str:
        """
        IMPROV-006: Stream LLM output token-by-token to stdout for real-time display.
        C# reads stdout via OutputDataReceived when --stream is active.
        Falls back to non-streaming on any exception.
        """
        print(f"  [{label}] streaming...", file=sys.stderr, flush=True)

        chain  = prompt_template | self.llm | self.output_parser
        chunks = []

        try:
            for chunk in chain.stream(inputs):
                token = chunk if isinstance(chunk, str) else getattr(chunk, 'content', str(chunk))
                chunks.append(token)
                sys.stdout.write(token)
                sys.stdout.flush()
        except Exception as e:
            print(f"\n  Streaming failed ({e}), retrying without streaming...", file=sys.stderr)
            try:
                result = (prompt_template | self.llm | self.output_parser).invoke(inputs)
                return result.strip()
            except Exception as e2:
                raise RuntimeError(f"Both streaming and non-streaming failed: {e2}")

        sys.stdout.write('\n')
        sys.stdout.flush()
        return ''.join(chunks).strip()

    # ------------------------------------------------------------------
    # Analysis methods
    # ------------------------------------------------------------------

    def _format_context(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Format report data for prompt templates."""
        findings = report.get("findings", [])
        summary  = report.get("summary", {})
        sanitized = self.sanitize_report(report)
        return {
            "tool":            report.get("tool", "asterion"),
            "version":         report.get("version", "0.2.0"),
            "target":          report.get("target", "unknown"),
            "mode":            report.get("mode", "safe"),
            "date":            report.get("date", datetime.now(timezone.utc).isoformat()),
            "findings_count":  len(findings),
            "critical_count":  summary.get("critical", 0),
            "high_count":      summary.get("high", 0),
            "medium_count":    summary.get("medium", 0),
            "low_count":       summary.get("low", 0),
            "info_count":      summary.get("info", 0),
            "findings_json":   json.dumps(sanitized.get("findings", []), indent=2),
        }

    def analyze_technical(self, report: Dict[str, Any]) -> str:
        """Generate technical remediation guide."""
        print(f"  Generating technical remediation ({self.provider}/{self.model})...", file=sys.stderr)
        prompt = PromptTemplate(
            input_variables=["target", "mode", "date", "findings_count",
                             "critical_count", "high_count", "medium_count",
                             "low_count", "info_count", "findings_json"],
            template=self.prompt_text,
        )
        try:
            return self._invoke_with_tracking(prompt, self._format_context(report), label="technical")
        except RuntimeError as e:
            return f"[Technical analysis aborted: {e}]"
        except Exception as e:
            return self._error_message("technical", e)

    def analyze_non_technical(self, report: Dict[str, Any]) -> str:
        """Generate executive summary for non-technical stakeholders."""
        print(f"  Generating executive summary ({self.provider}/{self.model})...", file=sys.stderr)
        prompt = PromptTemplate(
            input_variables=["target", "mode", "date", "findings_count",
                             "critical_count", "high_count", "medium_count",
                             "low_count", "info_count", "findings_json"],
            template=self.prompt_text,
        )
        try:
            return self._invoke_with_tracking(prompt, self._format_context(report), label="non_technical")
        except RuntimeError as e:
            return f"[Executive summary aborted: {e}]"
        except Exception as e:
            return self._error_message("non_technical", e)

    def analyze_both(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate both technical and non-technical analyses.
        self.prompt_text already holds 'technical' template (loaded in __init__ for tone='both').
        Load 'non_technical' template separately for the executive summary.
        """
        # Technical analysis uses self.prompt_text (technical.txt)
        tech_result = self.analyze_technical(report)

        # Non-technical analysis: temporarily swap prompt_text to non_technical template
        original_prompt = self.prompt_text
        try:
            self.prompt_text = self._load_prompt_for_tone('non_technical')
            non_tech_result = self.analyze_non_technical(report)
        finally:
            self.prompt_text = original_prompt

        return {
            'executiveSummary':     non_tech_result,
            'technicalRemediation': tech_result,
            'generatedAt':          datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'modelUsed':            f"{self.provider}/{self.model}",
            'tone':                 'both',
        }

    def _error_message(self, analysis_type: str, error: Exception) -> str:
        error_str = str(error)

        # Detect authentication / API key errors — these are fatal, not partial failures.
        # Raise AIAuthError so the CLI exits with code 2 and C# shows an actionable message.
        is_auth_error = (
            "401" in error_str
            or "invalid_api_key" in error_str
            or "Incorrect API key" in error_str
            or "authentication_error" in error_str
            or "invalid_authorization" in error_str
            or ("403" in error_str and "Forbidden" in error_str)
        )
        if is_auth_error:
            print(f"\n[ERROR] AI provider rejected the API key (authentication failed)", file=sys.stderr)
            print(f"  Provider : {self.provider}", file=sys.stderr)
            print(f"  Model    : {self.model}", file=sys.stderr)
            print(f"  Detail   : {error_str[:200]}", file=sys.stderr)
            print(f"  Fix      : export AI_API_KEY='<correct-key>'", file=sys.stderr)
            if self.provider == 'openai':
                print(f"  Keys     : https://platform.openai.com/account/api-keys", file=sys.stderr)
            elif self.provider == 'anthropic':
                print(f"  Keys     : https://console.anthropic.com/settings/keys", file=sys.stderr)
            raise AIAuthError(self.provider, error_str[:200])

        if self.provider == 'ollama':
            return (
                f"[Ollama {analysis_type} analysis failed: {error}\n"
                f"Troubleshooting: 1) ollama serve  2) ollama list  "
                f"3) ollama pull {self.model}]"
            )
        elif self.provider == 'anthropic':
            return f"[Anthropic {analysis_type} analysis failed: {error} — check AI_API_KEY]"
        return f"[AI {analysis_type} analysis unavailable ({self.provider}): {error}]"

    # ------------------------------------------------------------------
    # IMPROV-007: Multi-LLM comparison mode
    # ------------------------------------------------------------------

    def compare_providers(
        self,
        report: Dict[str, Any],
        providers_config: List[Dict[str, str]],
        tone: str = 'both',
        streaming: bool = False,
    ) -> Dict[str, Any]:
        """
        Run analysis through multiple providers in parallel.
        IMPROV-007: Multi-LLM comparison mode.

        Args:
            providers_config: list of {'provider': str, 'model': str}
            tone: 'technical', 'non_technical', or 'both'

        Returns:
            Dict with comparison_mode, providers_compared, results, cost_by_provider
        """
        results     = {}
        cost_totals = {}

        def _analyze_one(prov_cfg: Dict) -> Tuple[str, Dict]:
            prov_label = f"{prov_cfg['provider']}/{prov_cfg['model']}"
            try:
                tracker  = AICostTracker()
                analyzer = AsterionAIAnalyzer(
                    provider=prov_cfg['provider'],
                    model=prov_cfg['model'],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    tone=tone if tone != 'both' else 'technical',
                    streaming=streaming,
                    cost_tracker=tracker,
                )

                if tone == 'technical':
                    result = {'technicalRemediation': analyzer.analyze_technical(report)}
                elif tone == 'non_technical':
                    result = {'executiveSummary': analyzer.analyze_non_technical(report)}
                else:
                    result = analyzer.analyze_both(report)

                cost_totals[prov_label] = tracker.total_cost
                return prov_label, result

            except Exception as e:
                print(f"  Compare: {prov_cfg['provider']} failed: {e}", file=sys.stderr)
                return prov_label, {'error': str(e)}

        with ThreadPoolExecutor(max_workers=len(providers_config)) as executor:
            futures = [executor.submit(_analyze_one, pc) for pc in providers_config]
            for future in as_completed(futures):
                label, result = future.result()
                results[label] = result

        return {
            'comparison_mode':    True,
            'providers_compared': list(results.keys()),
            'results':            results,
            'cost_by_provider':   cost_totals,
            'generated_at':       datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        }

    # ------------------------------------------------------------------
    # IMPROV-008: Agent with NVD tools for network security
    # ------------------------------------------------------------------

    def analyze_with_agent(self, report: Dict[str, Any]) -> str:
        """
        Run AI agent with external tools for enhanced network security analysis.
        IMPROV-008: Manual tool-calling loop with NVD CVE lookup and
        network service vulnerability search.

        Tools:
          - lookup_nvd_cve             : NVD CVE database by CVE ID
          - search_network_service_vulns: NVD product search for network services

        Loop:
          1. LLM receives sanitized report + system prompt
          2. If LLM returns tool_calls → execute each → append ToolMessage → re-invoke
          3. When LLM returns no tool_calls → final answer
        """
        try:
            from langchain_core.messages import ToolMessage
        except ImportError:
            raise ImportError("langchain-core 1.0.0 required for agent mode")

        # Build tool list
        tools = []
        nvd_tool = _make_nvd_tool()
        if nvd_tool:
            tools.append(nvd_tool)
        net_tool = _make_network_vuln_tool()
        if net_tool:
            tools.append(net_tool)

        sanitized   = self.sanitize_report(report)
        report_json = json.dumps(sanitized, indent=2)

        agent_system = (
            "You are a senior network security engineer analyzing an Asterion scan report. "
            "Asterion audits Windows AD, SMB, RDP, LDAP, Kerberos, SNMP, DNS, FTP, NFS, and SSH.\n\n"
            "You have two tools to enrich your analysis with live NVD data.\n\n"
            "STEP 1 — TOOL USE (required before writing):\n"
            "  a) For each critical/high finding that references a CVE ID, call "
            "lookup_nvd_cve with that CVE ID to get CVSS score and description.\n"
            "  b) For each network service version disclosed (e.g. 'Samba 4.15.0', "
            "'OpenSSH 8.9', 'vsftpd 3.0.5', 'Microsoft DNS'), call "
            "search_network_service_vulns with the service name and version to find "
            "known vulnerabilities.\n"
            "  c) Perform ALL tool calls before writing your final analysis.\n\n"
            "STEP 2 — WRITE ANALYSIS with these sections:\n"
            "  ### Executive Summary (2-3 sentences)\n"
            "  ### Critical & High Findings (enriched with NVD CVSS scores)\n"
            "  ### Network Service Vulnerabilities (CVEs for disclosed versions)\n"
            "  ### Active Directory & Authentication Risks\n"
            "  ### Prioritized Remediation (numbered, most critical first with config snippets)\n\n"
            "RULES:\n"
            "- Cover ALL critical and high findings\n"
            "- Include real CVSS scores from NVD where available\n"
            "- Be specific: include service versions, CVE IDs, finding codes (AST-*)\n"
            "- Provide PowerShell (Windows), GPO paths, and sshd_config/smb.conf snippets\n"
            "- Do not repeat the raw JSON data\n"
        )

        start = time.time()

        llm_with_tools = self.llm.bind_tools(tools) if tools else self.llm
        tools_by_name  = {t.name: t for t in tools}

        messages = [
            SystemMessage(content=agent_system),
            HumanMessage(content=report_json),
        ]

        max_iterations = 10
        iteration      = 0
        text           = ""

        try:
            while iteration < max_iterations:
                iteration += 1
                response   = llm_with_tools.invoke(messages)
                messages.append(response)

                tool_calls = getattr(response, 'tool_calls', []) or []

                if not tool_calls:
                    text = getattr(response, 'content', '') or ''
                    break

                print(f"  Agent iteration {iteration}: {len(tool_calls)} tool call(s)", file=sys.stderr)
                for tc in tool_calls:
                    tool_name    = tc.get('name', '')
                    tool_args    = tc.get('args', {})
                    tool_call_id = tc.get('id', '')

                    if tool_name in tools_by_name:
                        try:
                            tool_output = str(tools_by_name[tool_name].invoke(tool_args))
                        except Exception as te:
                            tool_output = f"Tool error: {te}"
                    else:
                        tool_output = f"Unknown tool: {tool_name}"

                    messages.append(
                        ToolMessage(content=tool_output, tool_call_id=tool_call_id)
                    )
            else:
                messages.append(
                    HumanMessage(content="Please provide your final security analysis based on the information gathered.")
                )
                final = llm_with_tools.invoke(messages)
                text  = getattr(final, 'content', '') or ''

        except Exception as e:
            raise RuntimeError(f"Agent analysis failed: {e}")

        duration = time.time() - start

        if self.cost_tracker:
            estimated_in  = len(report_json) // 4
            estimated_out = max(1, len(text) // 4)
            self.cost_tracker.record(
                'agent', self.provider, self.model,
                estimated_in, estimated_out, duration,
            )
            print(f"  Agent completed in {duration:.1f}s (estimated cost tracked)", file=sys.stderr)

        return text.strip()


# =============================================================================
# Convenience entry point
# =============================================================================

def _persist_and_summarize(
    cost_tracker: AICostTracker,
    provider: str,
    model: str,
    scan_id: Optional[int] = None,
):
    """Print cost summary and persist to ~/.argos/costs.json and argos.db."""
    cost_tracker.print_summary()
    cost_tracker.save_to_file(scan_id, provider, model)
    cost_tracker.save_to_db(scan_id, provider, model)


def analyze_report(
    report: Dict[str, Any],
    provider: str = "openai",
    model: str = "gpt-4o-mini-2024-07-18",
    temperature: float = 0.3,
    max_tokens: int = 6144,
    tone: str = "both",
    streaming: bool = False,
    budget: Optional[float] = None,
    scan_id: Optional[int] = None,
    compare_providers_cfg: Optional[List[Dict[str, str]]] = None,
    use_agent: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Main entry point for C# subprocess calls.

    Returns a dict that maps to the JSON output file, with keys:
      executiveSummary, technicalRemediation, generatedAt, modelUsed, tone,
      agentAnalysis (if agent mode),
      compareResults (if compare mode),
      cost { total_usd, provider, model, breakdown }
    """
    try:
        cost_tracker = AICostTracker(budget_usd=budget, warn_threshold=0.8, abort_on_exceed=False)

        if budget and budget > 0:
            print(f"  AI budget: ${budget:.4f}", file=sys.stderr)

        # ── Enrich findings with OWASP + CVE data before AI analysis ──────────
        # OWASP mapping is instant (dict lookup). CVE enrichment applies hard-coded
        # KNOWN_CVES and optionally dynamic NVD when version strings are in evidence.
        findings = report.get("findings", [])
        if findings:
            if HAS_OWASP:
                enrich_findings_with_owasp(findings)
                owasp_count = sum(1 for f in findings if "owasp" in f)
                print(f"  OWASP enrichment: {owasp_count}/{len(findings)} findings mapped", file=sys.stderr)
            if HAS_COMPLIANCE:
                enrich_findings_with_compliance(findings)
                comp_count = sum(1 for f in findings if "compliance" in f)
                print(f"  Compliance enrichment: {comp_count}/{len(findings)} findings mapped (CIS/NIST/PCI)", file=sys.stderr)
            if HAS_CVE_LOOKUP:
                enrich_findings(findings)   # NVD keyword search + CPE lookup (pure API, no hardcoded CVEs)
                cve_count = sum(1 for f in findings if f.get("vulnerabilities"))
                print(f"  CVE enrichment: {cve_count}/{len(findings)} findings enriched", file=sys.stderr)

        if compare_providers_cfg:
            print(
                f"\n  Compare mode: {len(compare_providers_cfg)} providers",
                file=sys.stderr,
            )
            if use_agent:
                print(
                    "  WARNING: --ai-agent ignored in compare mode "
                    "(agent requires single provider context)",
                    file=sys.stderr,
                )

            # Use primary analyzer just for compare_providers()
            primary_analyzer = AsterionAIAnalyzer(
                provider=provider, model=model, temperature=temperature,
                max_tokens=max_tokens, tone=tone,
                streaming=streaming, cost_tracker=cost_tracker,
            )
            compare_result = primary_analyzer.compare_providers(
                report, compare_providers_cfg, tone=tone, streaming=streaming,
            )

            # Aggregate cost from all providers
            compare_total = sum(compare_result.get('cost_by_provider', {}).values())

            result = {
                'compareResults': compare_result,
                'generatedAt':    compare_result.get('generated_at', ''),
                'modelUsed':      model,
                'tone':           tone,
            }
            cost_info = {
                'total_usd': compare_total,
                'breakdown': compare_result.get('cost_by_provider', {}),
                'provider':  'compare',
                'model':     ','.join(p.get('model', '') for p in compare_providers_cfg),
            }

        elif use_agent:
            print(f"\n  Agent mode: {provider}/{model}", file=sys.stderr)
            analyzer = AsterionAIAnalyzer(
                provider=provider, model=model, temperature=temperature,
                max_tokens=max_tokens, tone='technical',
                streaming=False,  # agent doesn't support streaming
                cost_tracker=cost_tracker,
            )
            agent_text = analyzer.analyze_with_agent(report)
            result = {
                'agentAnalysis': agent_text,
                'generatedAt':   datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'modelUsed':     f"{provider}/{model}",
                'tone':          'agent',
            }
            cost_info = {
                'total_usd': cost_tracker.total_cost,
                'breakdown': cost_tracker.breakdown,
                'provider':  provider,
                'model':     model,
            }

        else:
            # Standard mode
            analyzer = AsterionAIAnalyzer(
                provider=provider, model=model, temperature=temperature,
                max_tokens=max_tokens, tone=tone,
                streaming=streaming, cost_tracker=cost_tracker,
            )

            if tone == 'technical':
                text = analyzer.analyze_technical(report)
                result = {
                    'technicalRemediation': text,
                    'generatedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    'modelUsed':   model,
                    'tone':        tone,
                }
            elif tone == 'non_technical':
                text = analyzer.analyze_non_technical(report)
                result = {
                    'executiveSummary': text,
                    'generatedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    'modelUsed':   model,
                    'tone':        tone,
                }
            else:
                result = analyzer.analyze_both(report)

            cost_info = {
                'total_usd': cost_tracker.total_cost,
                'breakdown': cost_tracker.breakdown,
                'provider':  provider,
                'model':     model,
            }

        result['cost'] = cost_info
        _persist_and_summarize(cost_tracker, provider, model, scan_id)
        return result

    except AIAuthError:
        raise  # propagate to CLI entry point → exit code 2
    except Exception as e:
        print(f"ERROR: AI analysis initialization failed: {e}", file=sys.stderr)
        return None


# =============================================================================
# CLI entry point
# =============================================================================

def _parse_compare_arg(compare_str: str) -> List[Dict[str, str]]:
    """
    Parse --compare argument into list of {provider, model} dicts.
    Format: "openai/gpt-4o-mini-2024-07-18,anthropic/claude-3-5-haiku-20241022"
    """
    providers = []
    for entry in compare_str.split(','):
        entry = entry.strip()
        if '/' in entry:
            prov, mdl = entry.split('/', 1)
            providers.append({'provider': prov.strip(), 'model': mdl.strip()})
        else:
            print(
                f"  WARNING: Could not parse compare entry '{entry}' "
                f"(expected format: provider/model)",
                file=sys.stderr,
            )
    return providers


def main():
    """Main entry point for C# subprocess calls."""
    parser = argparse.ArgumentParser(
        description="AI Analysis Bridge for Asterion Network Security Auditor"
    )

    parser.add_argument("--input",       required=True,  help="Input JSON report path")
    parser.add_argument("--output",      required=True,  help="Output JSON report path")
    parser.add_argument("--provider",    default="openai", choices=["openai", "anthropic", "ollama"])
    parser.add_argument("--model",       default="gpt-4o-mini-2024-07-18")
    parser.add_argument("--temperature", type=float, default=0.3)
    parser.add_argument("--max-tokens",  type=int,   default=6144)
    parser.add_argument("--tone",        default="technical",
                        choices=["technical", "non_technical", "both"])
    parser.add_argument("--stream",      action="store_true",
                        help="Stream output tokens to stdout in real-time")
    parser.add_argument("--agent",       action="store_true",
                        help="Use agent mode with NVD CVE lookup tools")
    parser.add_argument("--compare",     default=None,
                        help="Compare providers: 'openai/gpt-4o-mini,anthropic/claude-3-5-haiku'")
    parser.add_argument("--budget",      type=float, default=0.0,
                        help="Max AI spend in USD (0 = no limit)")
    parser.add_argument("--scan-id",     type=int,   default=None,
                        help="Scan ID for cost DB record")
    parser.add_argument("--verbose",     action="store_true")

    args = parser.parse_args()

    try:
        if not os.path.exists(args.input):
            print(f"ERROR: Input file not found: {args.input}", file=sys.stderr)
            return 1

        print(f"Loading report: {args.input}", file=sys.stderr)
        with open(args.input, 'r', encoding='utf-8') as f:
            report = json.load(f)

        print(f"Report loaded: {len(report.get('findings', []))} findings", file=sys.stderr)

        if args.agent and args.compare:
            print(
                "  WARNING: --agent and --compare are mutually exclusive. "
                "Using --compare and ignoring --agent.",
                file=sys.stderr,
            )
            args.agent = False

        compare_providers_cfg = _parse_compare_arg(args.compare) if args.compare else None

        ai_analysis = analyze_report(
            report=report,
            provider=args.provider,
            model=args.model,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            tone=args.tone,
            streaming=args.stream,
            budget=args.budget if args.budget > 0 else None,
            scan_id=args.scan_id,
            compare_providers_cfg=compare_providers_cfg,
            use_agent=args.agent,
        )

        if ai_analysis is None:
            print("ERROR: AI analysis returned None", file=sys.stderr)
            return 1

        report["aiAnalysis"] = ai_analysis

        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        cost = ai_analysis.get('cost', {})
        print("\n" + "=" * 70, file=sys.stderr)
        print("✓ AI ANALYSIS COMPLETED SUCCESSFULLY", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print(f"Provider: {args.provider}", file=sys.stderr)
        print(f"Model:    {args.model}", file=sys.stderr)
        print(f"Tone:     {ai_analysis.get('tone', args.tone)}", file=sys.stderr)
        print(f"Cost:     ${cost.get('total_usd', 0.0):.4f}", file=sys.stderr)
        print("=" * 70 + "\n", file=sys.stderr)

        return 0

    except AIAuthError as e:
        # Exit code 2 = authentication failure — C# side shows specific "invalid API key" message
        print(f"\nERROR: AI authentication failed — {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
