"""
intel/github_recon.py
---------------------
GitHub recon for:
- Leaked secrets in target's public repos
- Subdomains mentioned in code
- API endpoints referenced

Requires: api_keys.github_token (optional — works without, rate-limited).
"""

import time
import re
from typing import Dict, List, Optional

from core.logger import get_logger, info, skip, warn
from core.config_loader import get_config
from core.utils import safe_request

log = get_logger("github_recon")
cfg = get_config()

API = "https://api.github.com"

SECRET_PATTERNS = {
    "aws_key":      re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api":   re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "jwt":          re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "private_key":  re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "slack_token":  re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
    "generic":      re.compile(r"(?:secret|token|apikey|api_key|password)[\"'\s:=]+([A-Za-z0-9_\-]{20,})", re.I),
}


def _headers() -> Dict:
    token = cfg.get("api_keys.github_token", "")
    h = {"Accept": "application/vnd.github.v3+json"}
    if token:
        h["Authorization"] = f"token {token}"
    return h


def search_code(query: str, max_results: int = 30) -> List[Dict]:
    """
    Search GitHub code (requires token for high rate limit).
    """
    headers = _headers()
    if "Authorization" not in headers:
        skip("GitHub token missing — code search unavailable")
        return []

    info(f"GitHub code search: {query}")
    params = {"q": query, "per_page": min(max_results, 100)}
    r = safe_request(f"{API}/search/code", params=params, headers=headers, timeout=20)
    if not r or r.status_code != 200:
        if r and r.status_code == 403:
            warn("GitHub rate limit hit")
        return []
    try:
        data = r.json()
    except Exception:
        return []

    items = []
    for it in data.get("items", []):
        items.append({
            "repo": it.get("repository", {}).get("full_name", ""),
            "path": it.get("path", ""),
            "url": it.get("html_url", ""),
        })
    time.sleep(1)
    ok(f"GitHub: {len(items)} code hits")
    return items


def search_repos(query: str, max_results: int = 30) -> List[Dict]:
    """Search repos (works without token, low rate)."""
    headers = _headers()
    info(f"GitHub repo search: {query}")
    params = {"q": query, "per_page": min(max_results, 100)}
    r = safe_request(f"{API}/search/repositories", params=params,
                     headers=headers, timeout=20)
    if not r or r.status_code != 200:
        return []
    try:
        data = r.json()
    except Exception:
        return []
    return [
        {
            "full_name": it.get("full_name"),
            "description": it.get("description", ""),
            "html_url": it.get("html_url", ""),
            "stars": it.get("stargazers_count", 0),
            "updated_at": it.get("updated_at", ""),
        }
        for it in data.get("items", [])
    ]


def org_repos(org: str, max_results: int = 50) -> List[Dict]:
    """List public repos of an org."""
    headers = _headers()
    params = {"per_page": min(max_results, 100)}
    r = safe_request(f"{API}/orgs/{org}/repos", params=params,
                     headers=headers, timeout=20)
    if not r or r.status_code != 200:
        return []
    try:
        data = r.json()
    except Exception:
        return []
    return [
        {
            "name": r_["name"],
            "full_name": r_["full_name"],
            "html_url": r_["html_url"],
            "private": r_["private"],
            "updated_at": r_["updated_at"],
        }
        for r_ in data
    ]


def scan_file_for_secrets(raw_url: str) -> List[Dict]:
    """Download a raw GitHub file and scan for secrets."""
    r = safe_request(raw_url, timeout=15)
    if not r or r.status_code != 200:
        return []
    content = r.text
    hits: List[Dict] = []
    for name, pat in SECRET_PATTERNS.items():
        for m in pat.finditer(content):
            hits.append({
                "kind": name,
                "match": m.group(0)[:200],
                "source": raw_url,
            })
    return hits


def recon_org(org: str, max_repos: int = 20) -> Dict:
    """
    Full recon on an organization: list repos, scan for secrets in top files.
    """
    info(f"GitHub recon: org={org}")
    repos = org_repos(org, max_results=max_repos)
    all_secrets: List[Dict] = []

    for repo in repos[:max_repos]:
        # Search for common secret-holding paths
        for query in [
            f"repo:{repo['full_name']} filename:.env",
            f"repo:{repo['full_name']} filename:config",
            f"repo:{repo['full_name']} filename:credentials",
        ]:
            for hit in search_code(query, max_results=3):
                # Fetch raw content
                raw_url = hit["url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                all_secrets.extend(scan_file_for_secrets(raw_url))

    return {
        "org": org,
        "repos": repos,
        "secrets": all_secrets,
        "secret_count": len(all_secrets),
    }


if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser()
    parser.add_argument("--search")
    parser.add_argument("--org")
    args = parser.parse_args()
    if args.org:
        print(json.dumps(recon_org(args.org), indent=2, default=str))
    elif args.search:
        print(json.dumps(search_code(args.search), indent=2, default=str))