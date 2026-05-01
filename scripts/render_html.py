#!/usr/bin/env python3
"""
HTML Report Renderer for Asterion

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import argparse
import json
import sys
import re
from pathlib import Path
from datetime import datetime

# Main dependencies
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Markdown (required)
try:
    import markdown
except Exception as e:
    print("ERROR: The 'markdown' library is required. Install with: pip install markdown", file=sys.stderr)
    raise

# Sanitization
try:
    import bleach
    _BLEACH_AVAILABLE = True
except Exception:
    _BLEACH_AVAILABLE = False

# -------------------------------
# Template search utilities
# -------------------------------
def find_template(template_path: str) -> Path | None:
    """Finds the Jinja2 template in various common locations."""
    candidates = [
        Path(template_path),
        Path(__file__).parent / template_path,             # scripts/ + rel
        Path(__file__).parent.parent / template_path,      # repo root + rel
        Path.cwd() / template_path,                        # cwd + rel
    ]
    for p in candidates:
        p = p.resolve()
        if p.exists():
            return p
    return None

# -------------------------------
# Auxiliary filters for Jinja2
# -------------------------------
def _format_datetime_iso8601_to_utc_string(value: str) -> str:
    """
    Converts ISO8601 (with Z or tz) to 'YYYY-MM-DD HH:MM:SS UTC'
    """
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        # if it's not valid ISO, return as is
        return value

def severity_color(severity: str) -> str:
    colors = {
        'critical': '#DC2626',  # Red
        'high': '#EA580C',      # Orange
        'medium': '#F59E0B',    # Amber
        'low': '#3B82F6',       # Blue
        'info': '#6B7280'       # Gray
    }
    return colors.get((severity or "").lower(), '#6B7280')

# -------------------------------
# Robust Markdown
# -------------------------------
_BULLET_REGEX = re.compile(r'(?m)^[\u2022•]\s+')  # lines starting with "• "
_LIST_START_REGEX = re.compile(r':\n(- |\* |\d+\. )')  # ":\n- " => ":\n\n- "

def _normalize_markdown_text(text: str) -> str:
    """
    Normalizes 'markdown-like' content:
      - Changes unicode bullets (•) to markdown "- "
      - Inserts blank line between ":" and list start
      - Normalizes Windows line breaks
    """
    if not text:
        return ""
    text = text.replace("\r\n", "\n")
    text = _BULLET_REGEX.sub("- ", text)
    text = _LIST_START_REGEX.sub(r":\n\n\1", text)
    return text

def _markdown_to_html(text: str) -> str:
    """
    Converts markdown to HTML with:
      - extra: tables, etc.
      - nl2br: converts \n to <br> where applicable
      - sane_lists: tolerant lists
      - codehilite: code blocks
    Sanitizes the resulting HTML fragment (not the full document) via bleach,
    protecting against XSS in AI-generated or user-provided markdown content.
    """
    if not text:
        return ""
    text = _normalize_markdown_text(text)
    html = markdown.markdown(
        text,
        extensions=["extra", "nl2br", "sane_lists", "codehilite"]
    )
    return sanitize_html(html)

# -------------------------------
# Sanitization (optional)
# -------------------------------
_ALLOWED_TAGS = [
    # basic text
    "p", "br", "hr", "span", "div", "blockquote",
    # inline
    "strong", "em", "b", "i", "u", "code", "pre", "kbd", "samp",
    # headers (in case AI produces them)
    "h1", "h2", "h3", "h4", "h5", "h6",
    # lists and tables
    "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td",
    # links
    "a",
]
_ALLOWED_ATTRS = {
    "*": ["class"],
    "a": ["href", "title", "target", "rel"],
    "span": ["class"],
    "div": ["class"],
    "code": ["class"],
    "pre": ["class"],
    "td": ["colspan", "rowspan"],
    "th": ["colspan", "rowspan"],
}
_ALLOWED_PROTOCOLS = ["http", "https", "mailto"]

def sanitize_html(html: str) -> str:
    if not _BLEACH_AVAILABLE:
        return html  # if bleach is not available, return as is
    return bleach.clean(
        html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        protocols=_ALLOWED_PROTOCOLS,
        strip=False
    )

# -------------------------------
# Main render
# -------------------------------
def render_html_report(report_json: str, template_path: str, output_path: str, unsafe_no_sanitize: bool = False) -> None:
    # Load JSON
    with open(report_json, "r", encoding="utf-8") as f:
        report = json.load(f)
    
    # Locate template
    template_file = find_template(template_path)
    if not template_file:
        raise FileNotFoundError(f"Template not found: {template_path}")
    
    # Prepare Jinja2 environment
    env = Environment(
        loader=FileSystemLoader(template_file.parent),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    
    # Jinja2 filters
    env.filters["markdown"] = _markdown_to_html
    env.filters["severity_color"] = severity_color
    env.filters["datetime"] = _format_datetime_iso8601_to_utc_string
    
    # Template
    template = env.get_template(template_file.name)
    
    # Render
    # Note: sanitization of user/AI-generated content is applied per-fragment
    # inside the `markdown` Jinja2 filter (see _markdown_to_html). Do NOT
    # run bleach on the full document — it escapes structural tags like
    # <html>, <style>, <script> that are not in the allowed list.
    if not _BLEACH_AVAILABLE and not unsafe_no_sanitize:
        print("WARN: 'bleach' not available; markdown content will not be sanitized. Install with: pip install bleach", file=sys.stderr)
    html = template.render(report=report)

    # Save
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    
    # Logs
    print(f"✓ HTML report rendered: {out}", file=sys.stderr)
    print(f"  Template: {template_file.name}", file=sys.stderr)
    print(f"  Findings: {len(report.get('findings', []))}", file=sys.stderr)
    if report.get("aiAnalysis"):
        print("  AI Analysis: Included", file=sys.stderr)

# -------------------------------
# CLI
# -------------------------------
def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Render Asterion HTML report with Jinja2 (Robust Markdown)",
        epilog="Example: python render_html.py --input report.json --output report.html"
    )
    p.add_argument("--input", required=True, help="Input JSON file path")
    p.add_argument("--template", default="templates/report.html.j2",
                   help="Jinja2 template path (default: templates/report.html.j2)")
    p.add_argument("--output", required=True, help="Output HTML file path")
    p.add_argument(
        "--unsafe-no-sanitize",
        action="store_true",
        help="Do not sanitize final HTML (useful if you 100% trust your source)"
    )
    return p

def main() -> int:
    args = _build_arg_parser().parse_args()
    try:
        render_html_report(
            report_json=args.input,
            template_path=args.template,
            output_path=args.output,
            unsafe_no_sanitize=args.unsafe_no_sanitize
        )
        return 0
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())