#!/usr/bin/env python3
"""
AI Analysis Bridge for Asterion Network Security Auditor
Part of the Argos Security Suite

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import argparse
import json
import os
import sys
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    # Core components
    from langchain_core.prompts import PromptTemplate
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.messages import HumanMessage, SystemMessage
    HAS_LANGCHAIN_CORE = True
except ImportError as e:
    print(f"ERROR: Missing langchain-core: {e}", file=sys.stderr)
    print("Install with: pip install langchain-core>=1.0.0", file=sys.stderr)
    sys.exit(1)

# OpenAI support (optional)
try:
    from langchain_openai import ChatOpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

# Anthropic support (optional)
try:
    from langchain_anthropic import ChatAnthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

# Ollama support (optional)
try:
    from langchain_ollama import ChatOllama
    HAS_OLLAMA = True
except ImportError:
    try:
        from langchain_community.chat_models import ChatOllama
        HAS_OLLAMA = True
    except ImportError:
        HAS_OLLAMA = False


class AsterionAIAnalyzer:
    """
    Uses LCEL (LangChain Expression Language) exclusively.
    """
    
    def __init__(
        self, 
        provider: str = "openai",
        model: str = "gpt-4-turbo-preview",
        temperature: float = 0.3,
        max_tokens: int = 2000,
        tone: str = "technical"
    ):
        """Initialize AI analyzer with selected provider."""
        if not HAS_LANGCHAIN_CORE:
            raise ImportError("langchain-core required. Install: pip install langchain-core>=1.0.0")
        
        self.provider = provider.lower()
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.tone = tone.lower()
        
        # Validate API key
        self._validate_api_key()
        
        # Create LLM instance
        self.llm = self._create_llm()
        
        # Initialize output parser
        self.output_parser = StrOutputParser()
        
        # Load prompt template
        self.prompt_template = self._load_prompt_template()
        
        print(f"✓ AI analyzer initialized: {self.provider}/{self.model}", file=sys.stderr)
    
    def _validate_api_key(self):
        """Validate that required API key is set."""
        if self.provider == "openai":
            if not os.getenv("AI_API_KEY"):
                raise ValueError("AI_API_KEY environment variable not set")
        elif self.provider == "anthropic":
            if not os.getenv("AI_API_KEY"):
                raise ValueError("AI_API_KEY environment variable not set")
    
    def _create_llm(self):
        """Create LangChain LLM instance based on provider."""
        if self.provider == "openai":
            if not HAS_OPENAI:
                raise ImportError("Install: pip install langchain-openai>=1.0.0")

            api_key = os.getenv("AI_API_KEY")

            return ChatOpenAI(
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                streaming=False,
                api_key=api_key
            )
        
        elif self.provider == "anthropic":
            if not HAS_ANTHROPIC:
                raise ImportError("Install: pip install langchain-anthropic>=1.0.0")

            api_key = os.getenv("AI_API_KEY")

            return ChatAnthropic(
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                timeout=60,
                max_retries=2,
                api_key=api_key
            )
        
        elif self.provider == "ollama":
            if not HAS_OLLAMA:
                raise ImportError("Install: pip install langchain-ollama>=0.3.0")
            
            base_url = "http://localhost:11434"
            
            try:
                import requests
                resp = requests.get(f"{base_url}/api/tags", timeout=5)
                if resp.status_code != 200:
                    raise ConnectionError(f"Ollama server not responding at {base_url}")
                
                models = resp.json().get('models', [])
                model_names = [m['name'] for m in models]
                
                if self.model not in model_names:
                    available = ', '.join(model_names) if model_names else 'none'
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
                verbose=False
            )
        
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _load_prompt_template(self) -> str:
        """Load prompt template from file."""
        prompt_filename = f"{self.tone}.txt"
        
        # Search paths
        search_paths = [
            Path("config/prompts") / prompt_filename,
            Path(__file__).parent.parent / "config" / "prompts" / prompt_filename,
            Path.cwd() / "config" / "prompts" / prompt_filename
        ]
        
        for path in search_paths:
            if path.exists():
                with path.open('r', encoding='utf-8') as f:
                    content = f.read()
                    print(f"✓ Loaded prompt from {path}", file=sys.stderr)
                    return content
        
        raise FileNotFoundError(f"Prompt template not found: {prompt_filename}")
    
    def _sanitize_findings(self, findings: List[Dict[str, Any]]) -> str:
        """Sanitize findings before sending to AI."""
        sanitized = []
        
        # Redaction patterns
        redact_patterns = [
            (r'password[=:]\s*\S+', 'password=***REDACTED***'),
            (r'token[=:]\s*\S+', 'token=***REDACTED***'),
            (r'api[_-]?key[=:]\s*\S+', 'api_key=***REDACTED***'),
            (r'secret[=:]\s*\S+', 'secret=***REDACTED***'),
        ]
        
        for finding in findings:
            clean = {
                "id": finding.get("id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "description": finding.get("description"),
                "recommendation": finding.get("recommendation"),
                "affectedComponent": finding.get("affectedComponent")
            }
            
            # Sanitize evidence
            if finding.get("evidence"):
                evidence = finding["evidence"]
                evidence_value = evidence.get("value", "")
                
                # Apply redactions
                for pattern, replacement in redact_patterns:
                    evidence_value = re.sub(pattern, replacement, evidence_value, flags=re.IGNORECASE)
                
                # Truncate long evidence
                max_length = 500
                if len(evidence_value) > max_length:
                    evidence_value = evidence_value[:max_length] + "... [truncated]"
                
                clean["evidence"] = {
                    "type": evidence.get("type"),
                    "value": evidence_value
                }
            
            sanitized.append(clean)
        
        return json.dumps(sanitized, indent=2)
    
    def _format_context(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Format report data for prompt templates."""
        findings = report.get("findings", [])
        summary = report.get("summary", {})
        
        return {
            "tool": report.get("tool", "asterion"),
            "version": report.get("version", "0.1.0"),
            "target": report.get("target", "unknown"),
            "mode": report.get("mode", "safe"),
            "date": report.get("date", datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')),
            "findings_count": len(findings),
            "critical_count": summary.get("critical", 0),
            "high_count": summary.get("high", 0),
            "medium_count": summary.get("medium", 0),
            "low_count": summary.get("low", 0),
            "info_count": summary.get("info", 0),
            "findings_json": self._sanitize_findings(findings)
        }
    
    def generate_analysis(self, report: Dict[str, Any]) -> str:
        """Generate AI analysis using modern LCEL chain."""
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"Generating {self.tone} analysis with {self.provider}...", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        print(f"Model: {self.model}", file=sys.stderr)
        print(f"Temperature: {self.temperature}", file=sys.stderr)
        print(f"Max Tokens: {self.max_tokens}", file=sys.stderr)
        
        if self.provider == "ollama":
            print(f"\n⚠️  WARNING: Ollama may take 2–5 minutes (or even longer if you're not using a GPU) for large reports", file=sys.stderr)
            print(f"   Model size affects generation time", file=sys.stderr)
            print(f"   Timeout: 1800 seconds (30 minutes)\n", file=sys.stderr)
        
        context = self._format_context(report)
        
        prompt = PromptTemplate(
            input_variables=["target", "mode", "date", "findings_count", 
                            "critical_count", "high_count", "medium_count", 
                            "low_count", "info_count", "findings_json"],
            template=self.prompt_template
        )
        
        chain = prompt | self.llm | self.output_parser
        
        try:
            import time
            start_time = time.time()
            
            print(f"ℹ️  Invoking AI model... (this may take a while)", file=sys.stderr)
            result = chain.invoke(context)
            
            elapsed = time.time() - start_time
            print(f"✓ {self.tone.capitalize()} analysis completed in {elapsed:.1f}s", file=sys.stderr)
            print(f"  Generated: {len(result)} characters\n", file=sys.stderr)
            
            return result.strip()
        
        except Exception as e:
            print(f"✗ Failed to generate {self.tone} analysis: {e}", file=sys.stderr)
            
            # Provider-specific troubleshooting
            if self.provider == "ollama":
                if "timed out" in str(e).lower():
                    print(f"\nℹ️  TIMEOUT FIX:", file=sys.stderr)
                    print(f"   Your model may be too slow. Try:", file=sys.stderr)
                    print(f"   1. Use a smaller model: ollama pull llama3.2:3b", file=sys.stderr)
                    print(f"   2. Increase timeout in ai_analyzer.py (line ~175)\n", file=sys.stderr)
            
            raise
    
    def analyze_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate complete AI analysis for Asterion report.
        
        Args:
            report: Complete Asterion report dictionary
            
        Returns:
            AI analysis dictionary
        """
        # Check if findings exist
        findings = report.get("findings", [])
        if not findings:
            print("WARNING: No findings in report", file=sys.stderr)
        
        # Generate analysis
        analysis_content = self.generate_analysis(report)
        
        # Build result based on tone
        result = {
            "generatedAt": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "modelUsed": self.model,
            "tone": self.tone
        }
        
        # Add content to correct field
        if self.tone == "technical":
            result["technicalRemediation"] = analysis_content
        else:  # non_technical
            result["executiveSummary"] = analysis_content
        
        return result


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="AI Analysis Bridge for Asterion Network Security Auditor"
    )
    
    parser.add_argument("--input", required=True, help="Input JSON report path")
    parser.add_argument("--output", required=True, help="Output JSON report path")
    parser.add_argument("--provider", default="openai", choices=["openai", "anthropic", "ollama"])
    parser.add_argument("--model", default="gpt-4-turbo-preview")
    parser.add_argument("--temperature", type=float, default=0.3)
    parser.add_argument("--max-tokens", type=int, default=2000)
    parser.add_argument("--tone", default="technical", choices=["technical", "non_technical", "both"])
    parser.add_argument("--verbose", action="store_true")
    
    args = parser.parse_args()
    
    try:
        # Load input report
        if not os.path.exists(args.input):
            print(f"ERROR: Input file not found: {args.input}", file=sys.stderr)
            return 1
        
        print(f"Loading report: {args.input}", file=sys.stderr)
        with open(args.input, 'r', encoding='utf-8') as f:
            report = json.load(f)
        
        print(f"Report loaded: {len(report.get('findings', []))} findings", file=sys.stderr)
        
        # ============================================================================
        # HANDLE "both" TONE: Generate BOTH analyses
        # ============================================================================
        if args.tone == "both":
            print(f"\nGenerating BOTH technical and non-technical analyses using {args.provider}/{args.model}...", file=sys.stderr)
            
            # Generate technical analysis
            print(f"\n[1/2] Generating technical remediation...", file=sys.stderr)
            technical_analyzer = AsterionAIAnalyzer(
                provider=args.provider,
                model=args.model,
                temperature=args.temperature,
                max_tokens=args.max_tokens,
                tone="technical"
            )
            technical_result = technical_analyzer.analyze_report(report)
            
            # Generate non-technical analysis
            print(f"\n[2/2] Generating executive summary...", file=sys.stderr)
            nontechnical_analyzer = AsterionAIAnalyzer(
                provider=args.provider,
                model=args.model,
                temperature=args.temperature,
                max_tokens=args.max_tokens,
                tone="non_technical"
            )
            nontechnical_result = nontechnical_analyzer.analyze_report(report)
            
            # Merge both analyses
            ai_analysis = {
                "executiveSummary": nontechnical_result.get("executiveSummary"),
                "technicalRemediation": technical_result.get("technicalRemediation"),
                "generatedAt": technical_result.get("generatedAt"),
                "modelUsed": args.model,
                "tone": "both"
            }
            
            report["aiAnalysis"] = ai_analysis
            
        else:
            # ============================================================================
            # SINGLE TONE: Generate one analysis
            # ============================================================================
            print(f"\nInitializing {args.provider} with model {args.model}...", file=sys.stderr)
            analyzer = AsterionAIAnalyzer(
                provider=args.provider,
                model=args.model,
                temperature=args.temperature,
                max_tokens=args.max_tokens,
                tone=args.tone
            )
            
            # Generate AI analysis
            print(f"\nGenerating AI analysis using {args.provider}/{args.model} ({args.tone} tone)...", file=sys.stderr)
            ai_analysis = analyzer.analyze_report(report)
            
            # Add to report
            report["aiAnalysis"] = ai_analysis
        
        # ============================================================================
        # Save output
        # ============================================================================
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Success summary
        print("\n" + "="*70, file=sys.stderr)
        print("✓ AI ANALYSIS COMPLETED SUCCESSFULLY", file=sys.stderr)
        print("="*70, file=sys.stderr)
        print(f"Provider: {args.provider}", file=sys.stderr)
        print(f"Model: {report['aiAnalysis']['modelUsed']}", file=sys.stderr)
        print(f"Tone: {report['aiAnalysis']['tone']}", file=sys.stderr)
        print(f"Generated: {report['aiAnalysis']['generatedAt']}", file=sys.stderr)
        print("="*70 + "\n", file=sys.stderr)
        
        return 0
    
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())