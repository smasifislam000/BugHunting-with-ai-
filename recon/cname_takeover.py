"""
recon/cname_takeover.py
-----------------------
Subdomain takeover detection via CNAME analysis.
Uses fingerprint list of known SaaS providers.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, warn, skip
from core.utils import safe_request, read_lines, write_lines, ensure_dir

log = get_logger("cname_takeover")


FINGERPRINTS = {
    "github.io":          ["There isn't a GitHub Pages site here", "For root URLs"],
    "herokuapp.com":      ["No such app", "heroku | no such app"],
    "s3.amazonaws.com":   ["NoSuchBucket", "The specified bucket does not exist"],
    "cloudfront.net":     ["Bad request", "ERROR: The request could not be satisfied"],
    "netlify.app":        ["Not Found - Request ID", "page not found"],
    "vercel.app":         ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
    "surge.sh":           ["project not found"],
    "bitbucket.io":       ["Repository not found"],
    "fastly.net":         ["Fastly error: unknown domain"],
    "pantheonsite.io":    ["The gods are wise", "The site you were looking for"],
    "readme.io":          ["Project doesnt exist", "Project not found"],
    "azurewebsites.net":  ["Error 404 - Web app not found"],
    "trafficmanager.net": ["404 Not Found"],
    "ghost.io":           ["Domain error"],
    "helpscoutdocs.com":  ["No settings were found for this company"],
    "statuspage.io":      ["Better Status Page for"],
    "zendesk.com":        ["Help Center Closed"],
    "wordpress.com":      ["Do you want to register"],
    "tumblr.com":         ["There's nothing here"],
    "smugmug.com":        ["Nothing found"],
    "uservoice.com":      ["This UserVoice subdomain is currently available"],
    "teamwork.com":       ["Oops - We didn't find your site"],
}


def load_cnames(recon_dir: str) -> List[Dict]:
    p = Path(recon_dir) / "cname_records.txt"
    lines = read_lines(p)
    out = []
    for ln in lines:
        if "->" in ln:
            h, c = ln.split("->", 1)
            out.append({"host": h.strip(), "cname": c.strip()})
    return out


def check_takeover(host: str, cname: str) -> Optional[Dict]:
    provider = None
    for prov in FINGERPRINTS:
        if prov in cname.lower():
            provider = prov
            break
    if not provider:
        return None

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = safe_request(url, timeout=8, allow_redirects=True)
        except Exception:
            continue
        if not r:
            continue
        text = (r.text or "")[:20000]
        for fp in FINGERPRINTS[provider]:
            if fp.lower() in text.lower():
                return {
                    "type": "subdomain_takeover",
                    "url": url,
                    "host": host,
                    "cname": cname,
                    "provider": provider,
                    "evidence": f"Fingerprint: {fp}",
                    "severity": "critical",
                    "confidence": 90,
                }
    return None


def scan_takeover(recon_dir: str, output_dir: str) -> Dict:
    ensure_dir(output_dir)
    cnames = load_cnames(recon_dir)
    if not cnames:
        info("No CNAME records - nothing to check")
        return {"count": 0, "findings": []}

    info(f"Checking {len(cnames)} CNAMEs for takeover")
    findings: List[Dict] = []

    for rec in cnames:
        try:
            res = check_takeover(rec["host"], rec["cname"])
            if res:
                findings.append(res)
                warn(f"TAKEOVER: {res['host']} -> {res['cname']}")
        except Exception as e:
            log.debug(f"takeover check failed: {e}")

    if findings:
        write_lines(Path(output_dir) / "takeover_findings.txt",
                    [f"[CRITICAL] {f['host']} -> {f['cname']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    import json
    p = argparse.ArgumentParser(description="Subdomain takeover detection")
    p.add_argument("-r", "--recon-dir", required=True)
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()
    result = scan_takeover(args.recon_dir, args.output)
    print(json.dumps({"count": result["count"]}, indent=2))