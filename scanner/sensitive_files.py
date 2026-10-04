"""
scanner/sensitive_files.py
--------------------------
Sensitive file / backup file discovery (scanner-level).
Checks: .env, .git/config, backups, config files, phpinfo, server-status.
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse

from pathlib import Path

from core.logger import get_logger, info, ok, skip, warn
from core.utils import safe_request, write_lines, ensure_dir, read_lines
from core.rate_limiter import acquire
from core.config_loader import get_config

log = get_logger("sensitive_files")
cfg = get_config()


PATHS = [
    "/.env", "/.env.local", "/.env.prod", "/.env.dev", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn/entries", "/.DS_Store", "/.htaccess", "/.htpasswd",
    "/config.json", "/config.yml", "/config.yaml", "/config.php",
    "/wp-config.php.bak", "/wp-config.php~",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info",
    "/backup.zip", "/backup.tar.gz", "/backup.tar", "/backup.rar",
    "/db.sql", "/dump.sql", "/backup.sql",
    "/site.tar.gz", "/app.zip", "/www.zip",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/actuator", "/actuator/health", "/actuator/env",
    "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml",
]


def test_path(base_url: str, path: str) -> Optional[Dict]:
    url = base_url.rstrip("/") + path
    try:
        acquire(url)
        r = safe_request(url, timeout=8, allow_redirects=False)
    except Exception:
        return None
    if not r:
        return None
    if r.status_code != 200:
        return None

    text = (r.text or "")[:2000]
    ctype = (r.headers.get("Content-Type") or "").lower()

    if "text/html" in ctype and "<html" in text.lower():
        if path not in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
            return None

    severity = "low"
    type_ = "sensitive_file"

    if ".env" in path or "config" in path or "wp-config" in path:
        severity = "critical"
        type_ = "config_leak"
    elif ".git" in path or ".svn" in path:
        severity = "high"
        type_ = "vcs_exposure"
    elif "backup" in path or ".sql" in path or ".zip" in path or ".tar" in path:
        severity = "high"
        type_ = "backup_exposed"
    elif "phpinfo" in path or "server-status" in path or "actuator" in path:
        severity = "medium"
        type_ = "info_disclosure"

    return {
        "type": type_,
        "url": url,
        "status": r.status_code,
        "length": len(r.content),
        "preview": text[:300],
        "severity": severity,
        "confidence": 70,
    }


def scan_sensitive_files(urls_file: str, output_dir: str) -> Dict:
    ensure_dir(output_dir)
    urls = read_lines(urls_file)
    if not urls:
        info("No URLs to derive hosts from")
        return {"count": 0, "findings": []}

    hosts = sorted({f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in urls})
    info(f"Sensitive files: testing {len(PATHS)} paths across {len(hosts[:20])} hosts")
    findings: List[Dict] = []

    for host in hosts[:20]:
        for path in PATHS:
            try:
                f = test_path(host, path)
                if f:
                    findings.append(f)
                    warn(f"[{f['severity']}] {f['url']}")
            except Exception as e:
                log.debug(f"sensitive probe failed {host}{path}: {e}")

    if findings:
        write_lines(Path(output_dir) / "sensitive_files_findings.txt",
                    [f"[{f['severity']}] {f['type']} -> {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Sensitive files scanner")
    p.add_argument("-l", "--list", required=True)
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()
    result = scan_sensitive_files(args.list, args.output)
    print(f"\nSensitive files findings: {result['count']}")