"""
modules/sensitive_files.py
--------------------------
Sensitive file / backup file discovery.
Checks: .env, .git/config, backups, config files, phpinfo, server-status.
"""

from urllib.parse import urlparse, urljoin
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("sensitive_files")


PATHS = [
    "/.env", "/.env.local", "/.env.prod", "/.env.dev", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn/entries", "/.DS_Store", "/.htaccess", "/.htpasswd",
    "/config.json", "/config.yml", "/config.yaml", "/config.php",
    "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info",
    "/backup.zip", "/backup.tar.gz", "/backup.tar", "/backup.rar",
    "/db.sql", "/dump.sql", "/database.sql", "/backup.sql",
    "/site.tar.gz", "/app.zip", "/www.zip",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/actuator", "/actuator/health", "/actuator/env",
    "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml",
]


def test_path(base_url: str, path: str) -> Optional[Dict]:
    url = base_url.rstrip("/") + path
    r = safe_request(url, timeout=8, allow_redirects=False)
    if not r:
        return None
    if r.status_code != 200:
        return None
    text = (r.text or "")[:2000]
    ctype = (r.headers.get("Content-Type") or "").lower()

    # Reject generic HTML (likely a 200-OK error page)
    if "text/html" in ctype and "<html" in text.lower():
        # Except robots/sitemap
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


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "sensitive_files", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        return {"count": 0, "findings": []}

    # Unique hosts
    hosts = sorted({f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in urls})
    info(f"Testing {len(PATHS)} paths across {len(hosts)} hosts")
    findings: List[Dict] = []

    for host in hosts[:20]:
        for path in PATHS:
            try:
                f = test_path(host, path)
                if f:
                    findings.append(f)
                    save_finding(domain, "sensitive_files", f["type"],
                                 f["severity"], f["url"],
                                 evidence=f["preview"], confidence=f["confidence"],
                                 scan_id=scan_id, output_root=output_root)
                    warn(f"[{f['severity']}] {f['url']}")
            except Exception as e:
                log.debug(f"sensitive probe failed {host}{path}: {e}")

    if findings:
        write_lines(mdir / "sensitive_files_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "sensitive_files", run, args.output)