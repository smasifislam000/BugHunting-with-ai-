"""
modules/auto_dork.py
--------------------
Google Dork generator for a target domain.

Generates search queries for:
  - Exposed files (pdf, xls, sql, env)
  - Admin panels
  - Login pages
  - API endpoints
  - Sensitive strings
  - Subdomains
  - Database dumps
  - Backup files
"""

import re
import urllib.parse
from typing import List, Dict, Optional
from pathlib import Path

from core.logger import get_logger, info, ok, warn
from core.utils import write_lines, ensure_dir
from modules._common import module_dir, cli_main

log = get_logger("auto_dork")


# ─────────────────────────────────────────
# Dork templates
# ─────────────────────────────────────────
DORK_TEMPLATES = {
    "sensitive_files": [
        "site:{d} ext:env",
        "site:{d} ext:sql",
        "site:{d} ext:bak",
        "site:{d} ext:log",
        "site:{d} ext:conf",
        "site:{d} ext:config",
        "site:{d} ext:yml OR ext:yaml",
        "site:{d} ext:json",
        "site:{d} ext:xml",
        "site:{d} ext:key",
        "site:{d} ext:pem",
    ],
    "documents": [
        "site:{d} filetype:pdf",
        "site:{d} filetype:doc OR filetype:docx",
        "site:{d} filetype:xls OR filetype:xlsx",
        "site:{d} filetype:ppt OR filetype:pptx",
        "site:{d} filetype:csv",
    ],
    "admin_panels": [
        "site:{d} inurl:admin",
        "site:{d} inurl:login",
        "site:{d} inurl:dashboard",
        "site:{d} inurl:panel",
        "site:{d} inurl:control",
        "site:{d} intitle:admin",
        "site:{d} intitle:dashboard",
        "site:{d} intitle:login",
    ],
    "api_endpoints": [
        "site:{d} inurl:api",
        "site:{d} inurl:api/v1",
        "site:{d} inurl:api/v2",
        "site:{d} inurl:graphql",
        "site:{d} inurl:swagger",
        "site:{d} inurl:openapi",
        "site:{d} inurl:rest",
    ],
    "sensitive_strings": [
        'site:{d} "password"',
        'site:{d} "api_key"',
        'site:{d} "apikey"',
        'site:{d} "token"',
        'site:{d} "secret"',
        'site:{d} "private key"',
        'site:{d} "credentials"',
        'site:{d} "aws_access_key_id"',
        'site:{d} "BEGIN RSA PRIVATE KEY"',
    ],
    "directories": [
        "site:{d} intitle:index.of",
        "site:{d} intitle:index of",
        "site:{d} parent directory",
        "site:{d} directory listing",
    ],
    "subdomains": [
        "site:*.{d}",
        "site:{d} -www",
        "site:{d} inurl:dev",
        "site:{d} inurl:staging",
        "site:{d} inurl:test",
        "site:{d} inurl:beta",
        "site:{d} inurl:internal",
    ],
    "vulnerable_strings": [
        'site:{d} inurl:"id="',
        'site:{d} inurl:"file="',
        'site:{d} inurl:"url="',
        'site:{d} inurl:"redirect="',
        'site:{d} inurl:"next="',
        'site:{d} inurl:"callback="',
        'site:{d} inurl:"debug="',
    ],
    "backend_tech": [
        "site:{d} inurl:phpinfo",
        "site:{d} inurl:server-status",
        "site:{d} inurl:actuator",
        "site:{d} inurl:graphiql",
        "site:{d} inurl:console",
        "site:{d} inurl:.git",
        "site:{d} inurl:.svn",
    ],
    "source_code": [
        "site:github.com {d}",
        "site:gitlab.com {d}",
        "site:bitbucket.org {d}",
        "site:pastebin.com {d}",
        "site:trello.com {d}",
    ],
    "cloud_storage": [
        "site:s3.amazonaws.com {brand}",
        "site:blob.core.windows.net {brand}",
        "site:storage.googleapis.com {brand}",
        "site:digitaloceanspaces.com {brand}",
    ],
    "exposed_emails": [
        "site:{d} intext:@gmail.com",
        "site:{d} intext:@yahoo.com",
        "site:{d} intext:@outlook.com",
        "site:{d} intext:contact",
    ],
    "login_leaks": [
        "site:{d} inurl:login.txt",
        "site:{d} inurl:passwords.txt",
        "site:{d} inurl:users.txt",
        "site:{d} inurl:credentials",
    ],
}


# ─────────────────────────────────────────
# Brand extraction
# ─────────────────────────────────────────
def _brand_names(domain: str) -> List[str]:
    """
    Extract brand-like names from a domain.
    Example: example.co.uk → ['example']
    """
    parts = domain.lower().split(".")
    # Remove common TLDs and ccTLD suffixes
    ignore = {"www", "com", "org", "net", "io", "co", "uk", "us", "in",
              "gov", "edu", "app", "dev", "info", "biz", "site"}
    brands = [p for p in parts if p and p not in ignore]
    return brands or [parts[0]] if parts else [domain]


# ─────────────────────────────────────────
# Generator
# ─────────────────────────────────────────
def generate_dorks(domain: str) -> Dict[str, List[str]]:
    """
    Generate dorks grouped by category.
    """
    brands = _brand_names(domain)
    brand = brands[0] if brands else domain

    result: Dict[str, List[str]] = {}
    for category, templates in DORK_TEMPLATES.items():
        queries = []
        for t in templates:
            try:
                q = t.format(d=domain, brand=brand)
                queries.append(q)
            except Exception:
                continue
        result[category] = queries
    return result


def google_url(query: str) -> str:
    return "https://www.google.com/search?q=" + urllib.parse.quote(query)


def bing_url(query: str) -> str:
    return "https://www.bing.com/search?q=" + urllib.parse.quote(query)


def duckduckgo_url(query: str) -> str:
    return "https://duckduckgo.com/?q=" + urllib.parse.quote(query)


# ─────────────────────────────────────────
# Save output
# ─────────────────────────────────────────
def save_dorks(domain: str, dorks: Dict[str, List[str]],
               output_dir: Path) -> Dict[str, str]:
    """
    Save dorks as text files (one per category) + a combined file.
    """
    ensure_dir(output_dir)
    files: Dict[str, str] = {}

    combined_lines: List[str] = [
        f"# Google Dorks for {domain}",
        f"# Generated by Dream Framework",
        "",
    ]

    for category, queries in dorks.items():
        if not queries:
            continue
        # Individual category file
        cat_file = output_dir / f"dorks_{category}.txt"
        write_lines(cat_file, queries)
        files[category] = str(cat_file)

        combined_lines.append(f"\n## {category}\n")
        for q in queries:
            combined_lines.append(q)

    # Combined file
    combined = output_dir / "dorks_all.txt"
    write_lines(combined, combined_lines)
    files["all"] = str(combined)

    # HTML file with clickable links
    html_lines = [
        "<html><head><title>Dorks</title></head><body>",
        f"<h1>Google Dorks for {domain}</h1>",
    ]
    for category, queries in dorks.items():
        if not queries:
            continue
        html_lines.append(f"<h2>{category}</h2><ul>")
        for q in queries:
            g = google_url(q)
            b = bing_url(q)
            d = duckduckgo_url(q)
            html_lines.append(
                f'<li><code>{q}</code> — '
                f'<a href="{g}" target="_blank">Google</a> | '
                f'<a href="{b}" target="_blank">Bing</a> | '
                f'<a href="{d}" target="_blank">DDG</a></li>'
            )
        html_lines.append("</ul>")
    html_lines.append("</body></html>")
    html_file = output_dir / "dorks.html"
    html_file.write_text("\n".join(html_lines), encoding="utf-8")
    files["html"] = str(html_file)

    return files


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "auto_dork", output_root)

    dorks = generate_dorks(domain)
    total = sum(len(v) for v in dorks.values())

    info(f"Generated {total} dorks across {len(dorks)} categories")

    files = save_dorks(domain, dorks, mdir)

    # Save a JSON summary
    import json
    summary = {
        "domain": domain,
        "total_dorks": total,
        "categories": {k: len(v) for k, v in dorks.items()},
        "files": files,
    }
    with open(mdir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    ok(f"Dorks saved to {mdir}")
    info(f"Open {mdir}/dorks.html in browser for clickable list")

    return {"count": total, "findings": [], "dorks": dorks, "files": files}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Auto Google dork generator")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "auto_dork", run, args.output)