"""
intel/intel_merger.py
---------------------
Central orchestrator for all intelligence sources.
Merges results from Shodan, Censys, VT, SecurityTrails, NVD, ExploitDB, GitHub.

Design principle: every source is OPTIONAL. Missing key = skip.
Framework never crashes because of a missing API.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from core.logger import get_logger, banner, info, ok, warn, skip, err
from core.utils import ensure_dir, save_json, load_json, read_lines
from core.config_loader import get_config

from intel import shodan_api
from intel import censys_api
from intel import virustotal_api
from intel import securitytrails_api
from intel import nvd_api
from intel import exploitdb
from intel import github_recon

log = get_logger("intel_merger")
cfg = get_config()


# ─────────────────────────────────────────
# Source status
# ─────────────────────────────────────────
def source_status() -> Dict[str, bool]:
    """Which intel sources are enabled and have credentials?"""
    return {
        "shodan":          cfg.has_api_key("shodan"),
        "censys":          cfg.has_censys(),
        "virustotal":      cfg.has_api_key("virustotal"),
        "securitytrails":  cfg.has_api_key("securitytrails"),
        "nvd":             True,  # works without key
        "exploitdb":       True,  # local tool
        "github":          cfg.has_api_key("github_token"),
    }


# ─────────────────────────────────────────
# Domain recon (subdomains + IPs + DNS history)
# ─────────────────────────────────────────
def gather_domain_intel(domain: str, output_dir: str = "results",
                        known_ips: Optional[List[str]] = None) -> Dict:
    """
    Collect intel from all sources for a single domain.
    Never crashes on missing key.
    """
    banner(f"INTEL: {domain}")
    out_dir = Path(output_dir) / domain / "intel"
    ensure_dir(out_dir)

    result = {
        "domain": domain,
        "started_at": datetime.utcnow().isoformat(),
        "sources": {},
        "subdomains": set(),
        "ips": set(),
        "cves": [],
        "exploits": [],
        "github_secrets": [],
    }

    # ── VirusTotal subdomains ──
    try:
        info("[VT] subdomains")
        subs = virustotal_api.get_subdomains(domain)
        result["sources"]["virustotal_subdomains"] = len(subs)
        result["subdomains"].update(subs)
    except Exception as e:
        log.debug(f"VT failed: {e}")

    # ── SecurityTrails subdomains + DNS history ──
    try:
        info("[ST] subdomains")
        subs = securitytrails_api.get_subdomains(domain)
        result["sources"]["securitytrails_subdomains"] = len(subs)
        result["subdomains"].update(subs)
    except Exception as e:
        log.debug(f"ST subdomains failed: {e}")

    try:
        info("[ST] DNS history")
        dns_hist = securitytrails_api.get_dns_history(domain, "a")
        result["sources"]["securitytrails_dns_history"] = len(dns_hist)
        for rec in dns_hist:
            for v in (rec.get("values") or []):
                ip = v.get("ip")
                if ip:
                    result["ips"].add(ip)
    except Exception as e:
        log.debug(f"ST DNS history failed: {e}")

    # ── Shodan domain info ──
    try:
        info("[Shodan] domain info")
        dinfo = shodan_api.domain_info(domain)
        if dinfo:
            result["sources"]["shodan_subdomains"] = len(dinfo.get("subdomains", []))
            result["subdomains"].update(dinfo.get("subdomains", []))
    except Exception as e:
        log.debug(f"Shodan failed: {e}")

    # ── Shodan + Censys per known IP ──
    ips_to_check = set(known_ips or []) | result["ips"]
    shodan_ips: List[Dict] = []
    censys_ips: List[Dict] = []
    for ip in list(ips_to_check)[:20]:
        try:
            data = shodan_api.lookup_host(ip)
            if data:
                shodan_ips.append(data)
        except Exception:
            pass
        try:
            data = censys_api.lookup_host(ip)
            if data:
                censys_ips.append(data)
        except Exception:
            pass
    result["sources"]["shodan_ips"] = len(shodan_ips)
    result["sources"]["censys_ips"] = len(censys_ips)

    # ── Finalize ──
    result["subdomains"] = sorted(result["subdomains"])
    result["ips"] = sorted(result["ips"])
    result["shodan_data"] = shodan_ips
    result["censys_data"] = censys_ips

    # Save
    save_json(out_dir / "domain_intel.json", result)

    # Write subdomain list for downstream modules
    if result["subdomains"]:
        from core.utils import write_lines
        write_lines(out_dir / "intel_subdomains.txt", result["subdomains"])

    ok(f"Domain intel: {len(result['subdomains'])} subs, {len(result['ips'])} IPs")

    # Remove sets (not JSON serializable elsewhere)
    result.pop("subdomains", None)
    result.pop("ips", None)
    return result


# ─────────────────────────────────────────
# Tech stack → CVEs + Exploits
# ─────────────────────────────────────────
def enrich_tech_stack(tech_stack_json: str, output_dir: str) -> Dict:
    """
    Given tech_stack.json, find CVEs and public exploits.
    """
    tech_data = load_json(tech_stack_json, {})
    tech_list = tech_data.get("unique_tech", [])

    if not tech_list:
        info("No tech stack to enrich")
        return {"cves": {}, "exploits": {}}

    banner("INTEL: CVE + Exploit Enrichment")
    out_dir = Path(output_dir)
    ensure_dir(out_dir)

    cves = nvd_api.cves_for_tech_stack(tech_list)
    exploits = exploitdb.exploits_for_tech_stack(tech_list)

    result = {
        "tech_list": tech_list,
        "cves": cves,
        "exploits": exploits,
    }
    save_json(out_dir / "tech_intel.json", result)

    # Summary
    total_cves = sum(len(v) for v in cves.values())
    total_exploits = sum(len(v) for v in exploits.values())
    ok(f"CVEs: {total_cves} | Exploits: {total_exploits}")
    return result


# ─────────────────────────────────────────
# GitHub recon for org
# ─────────────────────────────────────────
def gather_github_intel(org: str, output_dir: str) -> Dict:
    """GitHub recon on an org name."""
    if not cfg.has_api_key("github_token"):
        skip("GitHub token missing — skipping GitHub recon")
        return {"secrets": [], "repos": []}

    banner(f"INTEL: GitHub {org}")
    out_dir = Path(output_dir) / org / "intel"
    ensure_dir(out_dir)

    result = github_recon.recon_org(org)
    save_json(out_dir / "github_recon.json", result)
    ok(f"GitHub: {result.get('secret_count', 0)} secrets, {len(result.get('repos', []))} repos")
    return result


# ─────────────────────────────────────────
# Unified entry
# ─────────────────────────────────────────
def run_full_intel(domain: str,
                   output_dir: str = "results",
                   known_ips: Optional[List[str]] = None,
                   tech_stack_json: Optional[str] = None,
                   github_org: Optional[str] = None) -> Dict:
    """
    Full intel pipeline.
    """
    banner(f"FULL INTEL PIPELINE: {domain}")

    status = source_status()
    info("Source status:")
    for src, ok_flag in status.items():
        marker = "✓" if ok_flag else "·"
        info(f"  [{marker}] {src}")

    final = {
        "domain": domain,
        "domain_intel": None,
        "tech_intel": None,
        "github_intel": None,
    }

    try:
        final["domain_intel"] = gather_domain_intel(domain, output_dir, known_ips)
    except Exception as e:
        err(f"Domain intel failed: {e}")

    if tech_stack_json and Path(tech_stack_json).exists():
        try:
            final["tech_intel"] = enrich_tech_stack(tech_stack_json,
                                                    f"{output_dir}/{domain}/intel")
        except Exception as e:
            err(f"Tech intel failed: {e}")

    if github_org:
        try:
            final["github_intel"] = gather_github_intel(github_org, output_dir)
        except Exception as e:
            err(f"GitHub intel failed: {e}")

    return final


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Intel merger")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-o", "--output", default="results")
    parser.add_argument("--tech-stack", default=None,
                        help="Path to tech_stack.json from recon")
    parser.add_argument("--github-org", default=None)
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()

    if args.status:
        print(json.dumps(source_status(), indent=2))
    else:
        result = run_full_intel(
            args.target, args.output,
            tech_stack_json=args.tech_stack,
            github_org=args.github_org,
        )
        print(json.dumps({k: bool(v) for k, v in result.items()}, indent=2))