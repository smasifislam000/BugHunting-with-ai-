"""
scanner/js_analysis.py
----------------------
JavaScript file analysis:
- Extract endpoints (LinkFinder)
- Extract secrets (SecretFinder-style regex)
- Find API keys, tokens, credentials
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse

from core.logger import get_logger, info, ok, skip
from core.utils import (
    read_lines, write_lines, ensure_dir, safe_request,
    dedupe, run_command_stream
)

log = get_logger("js_analysis")


# ─────────────────────────────────────────
# Secret Detection Patterns
# ─────────────────────────────────────────
SECRET_PATTERNS = {
    "aws_access_key":    re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret":        re.compile(r"aws_secret_access_key[\"'\s:=]+([A-Za-z0-9/+=]{40})", re.I),
    "google_api":        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "firebase":          re.compile(r"firebaseio\.com"),
    "github_token":      re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "github_oauth":      re.compile(r"gho_[A-Za-z0-9]{36}"),
    "slack_token":       re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
    "stripe_key":        re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "stripe_pub":        re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
    "jwt":               re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "private_key":       re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "twilio":            re.compile(r"SK[0-9a-fA-F]{32}"),
    "sendgrid":          re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    "mailgun":           re.compile(r"key-[0-9a-zA-Z]{32}"),
    "generic_secret":    re.compile(r"(?:secret|token|apikey|api_key|password|passwd|pwd)[\"'\s:=]+([A-Za-z0-9_\-\.]{20,})", re.I),
    "s3_bucket":         re.compile(r"[a-z0-9.\-]+\.s3(?:[.-][a-z0-9\-]+)?\.amazonaws\.com"),
    "internal_url":      re.compile(r"https?://(?:localhost|127\.0\.0\.1|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[^\s\"'<>]+"),
}

ENDPOINT_PATTERNS = [
    re.compile(r'["\'](/[a-zA-Z0-9_\-/]{2,}(?:\?[^"\']*)?)["\']'),
    re.compile(r'["\'](https?://[^"\']+)["\']'),
    re.compile(r'url\s*[:=]\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'endpoint\s*[:=]\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'api(?:Url|_url|Url|URL)\s*[:=]\s*["\']([^"\']+)["\']', re.I),
]


# ─────────────────────────────────────────
# Extract JS URLs from URL list
# ─────────────────────────────────────────
def extract_js_urls(urls: List[str], base_url: str = "") -> List[str]:
    """Keep only .js URLs, add same-origin .js references."""
    js_urls = set()
    for u in urls:
        u = u.strip()
        if not u:
            continue
        if ".js" in u.lower().split("?")[0]:
            js_urls.add(u)
    return sorted(js_urls)


# ─────────────────────────────────────────
# Download JS content
# ─────────────────────────────────────────
def fetch_js(js_url: str, timeout: int = 15) -> str:
    """Download JS file content safely."""
    r = safe_request(js_url, timeout=timeout)
    if r and r.status_code == 200:
        return r.text
    return ""


# ─────────────────────────────────────────
# Extract endpoints
# ─────────────────────────────────────────
def extract_endpoints(js_content: str, base_url: str = "") -> List[str]:
    """Extract all endpoint-like URLs from JS content."""
    endpoints: Set[str] = set()
    for pat in ENDPOINT_PATTERNS:
        for m in pat.findall(js_content):
            if not m:
                continue
            m = m.strip()
            if m.startswith(("http://", "https://")):
                endpoints.add(m)
            elif m.startswith("/"):
                if base_url:
                    endpoints.add(urljoin(base_url, m))
                else:
                    endpoints.add(m)
    return sorted(endpoints)


# ─────────────────────────────────────────
# Extract secrets
# ─────────────────────────────────────────
def extract_secrets(js_content: str) -> List[Dict]:
    """Extract secrets from JS content."""
    findings: List[Dict] = []
    for name, pat in SECRET_PATTERNS.items():
        for m in pat.finditer(js_content):
            value = m.group(1) if m.groups() else m.group(0)
            findings.append({
                "type": "secret",
                "kind": name,
                "value": value[:200],
                "match": m.group(0)[:200],
            })
    # Dedupe by (kind, value)
    seen = set()
    out = []
    for f in findings:
        k = (f["kind"], f["value"])
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


# ─────────────────────────────────────────
# Main orchestrator
# ─────────────────────────────────────────
def analyze_js(urls_file: str, output_dir: str,
               max_files: int = 100) -> Dict:
    """
    Analyze all .js files found in URLs file.
    Returns endpoints + secrets.
    """
    ensure_dir(output_dir)

    all_urls = read_lines(urls_file)
    if not all_urls:
        info("No URLs for JS analysis")
        return {"endpoints": [], "secrets": [], "js_files": []}

    js_files = extract_js_urls(all_urls)[:max_files]
    if not js_files:
        info("No .js files found")
        return {"endpoints": [], "secrets": [], "js_files": []}

    info(f"Analyzing {len(js_files)} JS files")

    all_endpoints: Set[str] = set()
    all_secrets: List[Dict] = []

    for i, js_url in enumerate(js_files, 1):
        try:
            content = fetch_js(js_url)
            if not content:
                continue

            base = f"{urlparse(js_url).scheme}://{urlparse(js_url).netloc}"
            endpoints = extract_endpoints(content, base_url=base)
            secrets = extract_secrets(content)

            for e in endpoints:
                all_endpoints.add(e)
            for s in secrets:
                s["source"] = js_url
                all_secrets.append(s)
        except Exception as e:
            log.debug(f"JS fetch failed {js_url}: {e}")

    endpoints_list = sorted(all_endpoints)

    # Write outputs
    endpoints_file = Path(output_dir) / "js_endpoints.txt"
    write_lines(endpoints_file, endpoints_list)

    secrets_file = Path(output_dir) / "js_secrets.json"
    with open(secrets_file, "w", encoding="utf-8") as f:
        json.dump(all_secrets, f, indent=2, ensure_ascii=False)

    ok(f"Endpoints: {len(endpoints_list)} → {endpoints_file}")
    ok(f"Secrets: {len(all_secrets)} → {secrets_file}")

    # Summary
    kinds = {}
    for s in all_secrets:
        kinds[s["kind"]] = kinds.get(s["kind"], 0) + 1
    if kinds:
        info(f"Secret types: {kinds}")

    return {
        "endpoints": endpoints_list,
        "secrets": all_secrets,
        "js_files": js_files,
    }


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="JS analysis")
    parser.add_argument("-l", "--list", required=True, help="URLs file")
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args()

    result = analyze_js(args.list, args.output)
    print(f"\nEndpoints: {len(result['endpoints'])}")
    print(f"Secrets: {len(result['secrets'])}")