"""
recon/recon.py
--------------
Main recon orchestrator.
Chains: subdomain enum → live hosts → DNS → tech detect → takeover.
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime

from core.logger import get_logger, banner, ok, info, warn, err, skip
from core.utils import ensure_dir, save_json, timestamp, read_lines, write_lines
from core.config_loader import get_config
from core.database import get_db

from recon.subdomain_enum import enumerate_subdomains
from recon.live_hosts import detect_live_hosts
from recon.dns_resolve import (
    resolve_hosts, get_cnames, generate_permutations, resolve_permutations
)
from recon.tech_detect import extract_tech_stack

log = get_logger("recon")
cfg = get_config()


def full_recon(domain: str, output_root: str = "results",
               deep: bool = False, scan_id: int = None) -> dict:
    """
    Complete recon pipeline.
    Returns dict with all artifacts paths + stats.
    """
    banner(f"RECON: {domain}")

    out_dir = Path(output_root) / domain / "recon"
    ensure_dir(out_dir)

    result = {
        "domain": domain,
        "output_dir": str(out_dir),
        "started_at": datetime.utcnow().isoformat(),
        "artifacts": {},
        "stats": {},
    }

    # ── 1. Subdomain enumeration ──
    info("Phase 1/5: Subdomain enumeration")
    subs = enumerate_subdomains(domain, str(out_dir), deep=deep)
    result["stats"]["subdomains"] = len(subs)
    result["artifacts"]["subdomains"] = str(out_dir / "subdomains.txt")

    if not subs:
        warn("No subdomains found — recon will still try the apex domain")
        subs = [domain]
        write_lines(out_dir / "subdomains.txt", subs)

    # ── 2. DNS permutation (optional) ──
    if deep:
        info("Phase 2/5: DNS permutation")
        perm = generate_permutations(str(out_dir / "subdomains.txt"), str(out_dir))
        if perm:
            resolved_perm = resolve_permutations(str(out_dir / "permutations.txt"), str(out_dir))
            if resolved_perm:
                # Merge with subs
                all_subs = sorted(set(subs) | set(resolved_perm))
                write_lines(out_dir / "subdomains.txt", all_subs)
                result["stats"]["subdomains"] = len(all_subs)
                subs = all_subs
    else:
        skip("Permutation skipped (use --deep to enable)")

    # ── 3. Live host detection ──
    info("Phase 3/5: Live host detection")
    live = detect_live_hosts(str(out_dir / "subdomains.txt"), str(out_dir))
    result["stats"]["live_hosts"] = len(live["urls"])
    result["artifacts"]["live_hosts"] = str(out_dir / "live_hosts.txt")
    result["artifacts"]["live_hosts_json"] = str(out_dir / "live_hosts.json")

    # ── 4. CNAME records ──
    info("Phase 4/5: CNAME records")
    cnames = get_cnames(str(out_dir / "subdomains.txt"), str(out_dir))
    result["stats"]["cname_records"] = len(cnames)
    result["artifacts"]["cname_records"] = str(out_dir / "cname_records.txt")

    # ── 5. Tech stack fingerprinting ──
    info("Phase 5/5: Tech stack fingerprinting")
    tech = extract_tech_stack(str(out_dir / "live_hosts.json"), str(out_dir))
    result["stats"]["unique_tech"] = len(tech.get("unique_tech", []))
    result["stats"]["recommended_modules"] = tech.get("recommended_modules", [])
    result["artifacts"]["tech_stack"] = str(out_dir / "tech_stack.json")

    # ── Save to DB (if scan_id provided) ──
    if scan_id:
        db = get_db()
        host_rows = []
        for m in live.get("meta", []):
            host_rows.append({
                "hostname": m.get("host", ""),
                "ip": m.get("host", ""),  # httpx may not return IP separately
                "status_code": m.get("status_code", 0),
                "title": m.get("title", ""),
                "tech": ",".join(m.get("tech", []) or []),
            })
        db.add_hosts_bulk(scan_id, host_rows)
        ok(f"Saved {len(host_rows)} hosts to DB")

    # ── Final summary ──
    result["finished_at"] = datetime.utcnow().isoformat()
    save_json(out_dir / "recon_summary.json", result)

    banner("RECON COMPLETE")
    print(f"  Subdomains:     {result['stats'].get('subdomains', 0)}")
    print(f"  Live hosts:     {result['stats'].get('live_hosts', 0)}")
    print(f"  CNAME records:  {result['stats'].get('cname_records', 0)}")
    print(f"  Unique tech:    {result['stats'].get('unique_tech', 0)}")
    print(f"  Recommended:    {', '.join(result['stats'].get('recommended_modules', [])) or 'none'}")
    print(f"  Output:         {out_dir}")
    print()

    return result


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Dream Framework - Recon Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 -m recon.recon --target example.com
  python3 -m recon.recon --target example.com --deep
  python3 -m recon.recon --target example.com --output /custom/path
        """
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="results", help="Output root dir")
    parser.add_argument("--deep", action="store_true",
                        help="Enable slow sources (amass, findomain, permutations)")
    parser.add_argument("--no-db", action="store_true",
                        help="Skip database writes")
    args = parser.parse_args()

    db = get_db()
    scan_id = None
    if not args.no_db:
        scan_id = db.start_scan(args.target)
        info(f"Started scan #{scan_id}")

    try:
        result = full_recon(
            args.target, output_root=args.output,
            deep=args.deep, scan_id=scan_id
        )
        if scan_id:
            db.finish_scan(scan_id, status="done")
        print(f"Recon finished: {result['stats']}")
    except KeyboardInterrupt:
        warn("Interrupted by user")
        if scan_id:
            db.finish_scan(scan_id, status="interrupted")
        sys.exit(1)
    except Exception as e:
        err(f"Recon failed: {e}")
        if scan_id:
            db.finish_scan(scan_id, status="error", notes=str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()