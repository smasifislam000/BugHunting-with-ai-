"""
modules/cname_takeover.py
-------------------------
Subdomain takeover detection via CNAME analysis.
Uses fingerprint list of known SaaS providers.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, read_lines, write_lines, dedupe
from modules._common import recon_dir, module_dir, save_finding, cli_main

log = get_logger("cname_takeover")


# Known vulnerable fingerprints
FINGERPRINTS = {
    "github.io":         ["There isn't a GitHub Pages site here", "For root URLs"],
    "herokuapp.com":     ["No such app", "heroku | no such app"],
    "s3.amazonaws.com":  ["NoSuchBucket", "The specified bucket does not exist"],
    "cloudfront.net":    ["Bad request", "ERROR: The request could not be satisfied"],
    "netlify.app":       ["Not Found - Request ID", "page not found"],
    "vercel.app":        ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
    "surge.sh":          ["project not found"],
    "bitbucket.io":      ["Repository not found"],
    "fastly.net":        ["Fastly error: unknown domain"],
    "pantheonsite.io":   ["The gods are wise", "The site you were looking for"],
    "readme.io":         ["Project doesnt exist", "Project not found"],
    "azurewebsites.net": ["Error 404 - Web app not found"],
    "trafficmanager.net":["404 Not Found"],
    "ghost.io":          ["Domain error"],
    "helpscoutdocs.com": ["No settings were found for this company"],
    "statuspage.io":     ["Better Status Page for"],
    "zendesk.com":       ["Help Center Closed"],
    "wordpress.com":     ["Do you want to register"],
    "tumblr.com":        ["There's nothing here"],
    "smugmug.com":       ["Nothing found"],
    "uservoice.com":     ["This UserVoice subdomain is currently available"],
    "teamwork.com":      ["Oops - We didn't find your site"],
}


def load_cnames(domain: str, output_root: str = "results") -> List[Dict]:
    """Parse cname_records.txt → list of {host, cname}."""
    p = recon_dir(domain, output_root) / "cname_records.txt"
    lines = read_lines(p)
    out = []
    for ln in lines:
        if "->" in ln:
            h, c = ln.split("->", 1)
            out.append({"host": h.strip(), "cname": c.strip()})
    return out


def check_takeover(host: str, cname: str) -> Optional[Dict]:
    """Probe http(s)://host and look for fingerprints."""
    # Match against known providers
    provider = None
    for prov in FINGERPRINTS:
        if prov in cname.lower():
            provider = prov
            break
    if not provider:
        return None

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        r = safe_request(url, timeout=8, allow_redirects=True)
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


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "cname_takeover", output_root)
    cnames = load_cnames(domain, output_root)
    if not cnames:
        info("No CNAME records — nothing to check")
        return {"count": 0, "findings": []}

    info(f"Checking {len(cnames)} CNAMEs for takeover")
    findings: List[Dict] = []

    for rec in cnames:
        try:
            res = check_takeover(rec["host"], rec["cname"])
            if res:
                findings.append(res)
                save_finding(
                    domain, "cname_takeover", "subdomain_takeover",
                    "critical", res["url"],
                    evidence=res["evidence"], confidence=res["confidence"],
                    scan_id=scan_id, output_root=output_root,
                )
                warn(f"TAKEOVER: {res['host']} → {res['cname']}")
        except Exception as e:
            log.debug(f"takeover check failed: {e}")

    if findings:
        write_lines(mdir / "takeover_findings.txt",
                    [f"[CRITICAL] {f['host']} → {f['cname']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "cname_takeover", run, args.output)