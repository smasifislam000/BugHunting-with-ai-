"""
scanner/scanner.py
------------------
Main scanner orchestrator.
Chains all scanners with graceful error handling.
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime

from core.logger import get_logger, banner, ok, info, warn, err, skip
from core.utils import (
    ensure_dir, save_json, read_lines, write_lines, has_tool
)
from core.config_loader import get_config
from core.database import get_db

from scanner.nuclei_runner import run_nuclei, summarize as nuclei_summary
from scanner.xss_scanner import scan_xss
from scanner.sqli_scanner import scan_sqli
from scanner.js_analysis import analyze_js

log = get_logger("scanner")
cfg = get_config()


# ─────────────────────────────────────────
# Collect all URLs from recon output
# ─────────────────────────────────────────
def collect_urls(recon_dir: str) -> list:
    """Gather URLs from recon artifacts."""
    recon = Path(recon_dir)
    urls = set()

    # live hosts
    lh = recon / "live_hosts.txt"
    if lh.exists():
        urls.update(read_lines(lh))

    # js endpoints
    jse = recon / "js_endpoints.txt"
    if jse.exists():
        urls.update(read_lines(jse))

    return sorted(urls)


# ─────────────────────────────────────────
# Build scan targets from recon
# ─────────────────────────────────────────
def build_scan_targets(recon_dir: str, output_dir: str) -> dict:
    """
    Prepare target lists:
    - live_targets.txt (all live hosts)
    - js_targets.txt   (JS files with params)
    - param_targets.txt (URLs with query params)
    """
    ensure_dir(output_dir)

    recon = Path(recon_dir)
    live = read_lines(recon / "live_hosts.txt")

    # URLs with params
    param_urls = [u for u in live if "?" in u and "=" in u]

    # JS files
    js_urls = [u for u in live if ".js" in u.lower().split("?")[0]]

    write_lines(Path(output_dir) / "live_targets.txt", live)
    write_lines(Path(output_dir) / "param_targets.txt", param_urls)
    write_lines(Path(output_dir) / "js_targets.txt", js_urls)

    return {
        "live": live,
        "param": param_urls,
        "js": js_urls,
    }


# ─────────────────────────────────────────
# Full scan pipeline
# ─────────────────────────────────────────
def full_scan(domain: str, recon_dir: str, output_root: str = "results",
              scan_id: int = None,
              modules: list = None) -> dict:
    """
    Complete scan pipeline.
    """
    banner(f"SCANNING: {domain}")

    out_dir = Path(output_root) / domain / "scans"
    ensure_dir(out_dir)

    result = {
        "domain": domain,
        "recon_dir": recon_dir,
        "output_dir": str(out_dir),
        "started_at": datetime.utcnow().isoformat(),
        "modules": {},
        "stats": {},
    }

    # Prepare targets
    info("Preparing scan targets")
    targets = build_scan_targets(recon_dir, str(out_dir))
    info(f"Live: {len(targets['live'])} | Params: {len(targets['param'])} | JS: {len(targets['js'])}")

    if not targets["live"]:
        warn("No live targets — abort")
        return result

    all_modules = modules or [
        "nuclei", "xss", "sqli", "js_analysis",
    ]

    # ── Nuclei ──
    if "nuclei" in all_modules:
        info("Module: Nuclei")
        try:
            findings = run_nuclei(
                str(out_dir / "live_targets.txt"), str(out_dir)
            )
            result["modules"]["nuclei"] = {
                "count": len(findings),
                "summary": nuclei_summary(findings),
            }
            if scan_id:
                db = get_db()
                for f in findings:
                    db.add_finding(
                        scan_id,
                        vuln_type=f.get("template_id", "nuclei")[:80],
                        severity=f.get("severity", "info"),
                        url=f.get("url", ""),
                        host=f.get("host", ""),
                        evidence=f.get("name", "")[:500],
                    )
        except Exception as e:
            log.debug(f"Nuclei module failed: {e}")
            err(f"Nuclei module failed: {e}")

    # ── JS Analysis ──
    if "js_analysis" in all_modules:
        info("Module: JS Analysis")
        try:
            js_result = analyze_js(
                str(out_dir / "live_targets.txt"), str(out_dir)
            )
            result["modules"]["js_analysis"] = {
                "endpoints": len(js_result.get("endpoints", [])),
                "secrets": len(js_result.get("secrets", [])),
            }
            if scan_id:
                db = get_db()
                for s in js_result.get("secrets", []):
                    db.add_finding(
                        scan_id,
                        vuln_type=f"secret_{s.get('kind', 'unknown')}",
                        severity="high",
                        url=s.get("source", ""),
                        evidence=s.get("value", "")[:200],
                    )
        except Exception as e:
            log.debug(f"JS analysis failed: {e}")

    # ── XSS ──
    if "xss" in all_modules and targets["param"]:
        info("Module: XSS")
        try:
            xss_result = scan_xss(
                str(out_dir / "param_targets.txt"), str(out_dir),
                modes=["reflected"]
            )
            result["modules"]["xss"] = {"count": xss_result["count"]}
            if scan_id:
                db = get_db()
                for f in xss_result.get("findings", []):
                    db.add_finding(
                        scan_id,
                        vuln_type="xss",
                        severity="high",
                        url=f.get("url", ""),
                        payload=f.get("payload", ""),
                        evidence=f.get("raw", "")[:500],
                    )
        except Exception as e:
            log.debug(f"XSS module failed: {e}")

    # ── SQLi ──
    if "sqli" in all_modules and targets["param"]:
        info("Module: SQLi")
        try:
            sqli_result = scan_sqli(
                str(out_dir / "param_targets.txt"), str(out_dir)
            )
            result["modules"]["sqli"] = {"count": sqli_result["count"]}
            if scan_id:
                db = get_db()
                for f in sqli_result.get("findings", []):
                    db.add_finding(
                        scan_id,
                        vuln_type="sqli",
                        severity="critical",
                        url=f.get("url", ""),
                        evidence=f.get("raw", "")[:500],
                    )
        except Exception as e:
            log.debug(f"SQLi module failed: {e}")

    result["finished_at"] = datetime.utcnow().isoformat()
    save_json(out_dir / "scan_summary.json", result)

    banner("SCAN COMPLETE")
    for mod, data in result["modules"].items():
        if isinstance(data, dict):
            print(f"  {mod:15s}: {data}")
    print(f"  Output: {out_dir}")
    print()

    return result


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Dream Framework - Scanner Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 -m scanner.scanner --target example.com
  python3 -m scanner.scanner --target example.com --modules nuclei,xss
  python3 -m scanner.scanner --target example.com --output results
        """
    )
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-o", "--output", default="results")
    parser.add_argument("-r", "--recon-dir", default=None,
                        help="Custom recon dir (default: results/<domain>/recon)")
    parser.add_argument("--modules", default=None,
                        help="comma-separated: nuclei,xss,sqli,js_analysis")
    parser.add_argument("--no-db", action="store_true")
    args = parser.parse_args()

    recon_dir = args.recon_dir or f"{args.output}/{args.target}/recon"
    if not Path(recon_dir).exists():
        err(f"Recon dir not found: {recon_dir}")
        err("Run recon first: python3 -m recon.recon --target <domain>")
        sys.exit(1)

    modules = [m.strip() for m in args.modules.split(",")] if args.modules else None

    db = get_db()
    scan_id = None
    if not args.no_db:
        scan_id = db.start_scan(args.target)

    try:
        result = full_scan(
            args.target, recon_dir,
            output_root=args.output,
            scan_id=scan_id,
            modules=modules,
        )
        if scan_id:
            db.finish_scan(scan_id, status="done")
        print(f"Scan finished: {result.get('stats', result.get('modules', {}))}")
    except KeyboardInterrupt:
        warn("Interrupted")
        if scan_id:
            db.finish_scan(scan_id, status="interrupted")
        sys.exit(1)
    except Exception as e:
        err(f"Scan failed: {e}")
        if scan_id:
            db.finish_scan(scan_id, status="error", notes=str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()