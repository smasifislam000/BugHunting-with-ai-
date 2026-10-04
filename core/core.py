"""
core/core.py
------------
MAIN ORCHESTRATOR
Chains: recon → scan → modules → intel → triage → report.
Usage:
  python3 -m core.core --target example.com --full
  python3 -m core.core --target example.com --recon-only
  python3 -m core.core --target example.com --report-only
"""

import sys
import json
import time
import argparse
from pathlib import Path
from datetime import datetime

from core.logger import get_logger, banner, ok, info, warn, err, skip
from core.utils import ensure_dir, save_json
from core.config_loader import get_config
from core.database import get_db

log = get_logger("core")
cfg = get_config()


# ─────────────────────────────────────────
# Ordered module registry
# ─────────────────────────────────────────
MODULE_REGISTRY = [
    # (name, import_path, function_attr, needs_params)
    ("jwt_attack",          "modules.jwt_attack",          "run", False),
    ("oauth_test",          "modules.oauth_test",          "run", False),
    ("graphql_test",        "modules.graphql_test",        "run", False),
    ("cloud_enum",          "modules.cloud_enum",          "run", False),
    ("cloud_metadata",      "modules.cloud_metadata",      "run", True),
    ("open_api",            "modules.open_api",            "run", False),
    ("cname_takeover",      "modules.cname_takeover",      "run", False),
    ("sensitive_files",     "modules.sensitive_files",     "run", False),
    ("ssti",                "modules.ssti",                "run", True),
    ("nosql",               "modules.nosql",               "run", True),
    ("crlf_injection",      "modules.crlf_injection",      "run", True),
    ("ldap_injection",      "modules.ldap_injection",      "run", True),
    ("xxe",                 "modules.xxe",                 "run", False),
    ("deserialization",     "modules.deserialization",     "run", False),
    ("prototype_pollution", "modules.prototype_pollution", "run", False),
    ("postmessage",         "modules.postmessage",         "run", False),
    ("dom_clobbering",      "modules.dom_clobbering",      "run", False),
    ("css_injection",       "modules.css_injection",       "run", True),
    ("dangling_markup",     "modules.dangling_markup",     "run", True),
    ("csp_bypass",          "modules.csp_bypass",          "run", False),
    ("xs_leaks",            "modules.xs_leaks",            "run", False),
    ("host_header",         "modules.host_header",         "run", False),
    ("cache_poison",        "modules.cache_poison",        "run", False),
    ("web_cache_deception", "modules.web_cache_deception", "run", False),
    ("http_desync",         "modules.http_desync",         "run", False),
    ("http2_smuggling",     "modules.http2_smuggling",     "run", False),
    ("race_condition",      "modules.race_condition",      "run", False),
    ("business_logic",      "modules.business_logic",      "run", False),
    ("custom_protocol",     "modules.custom_protocol",     "run", False),
    ("browser_automation",  "modules.browser_automation",  "run", True),
]


def _safe_run_module(name: str, module_path: str, attr: str,
                     domain: str, output_root: str,
                     scan_id: int) -> dict:
    """
    Import + invoke a module; never let one module's failure stop the others.
    """
    try:
        mod = __import__(module_path, fromlist=[attr])
        fn = getattr(mod, attr)
        result = fn(domain=domain, output_root=output_root, scan_id=scan_id)
        return result or {}
    except TypeError:
        # Some modules don't accept scan_id
        try:
            mod = __import__(module_path, fromlist=[attr])
            fn = getattr(mod, attr)
            return fn(domain=domain, output_root=output_root) or {}
        except Exception as e:
            log.debug(f"module {name} fallback failed: {e}")
            return {}
    except Exception as e:
        log.debug(f"module {name} failed: {e}")
        warn(f"module {name}: {e}")
        return {}


def run_recon(domain: str, output_root: str, scan_id: int) -> dict:
    try:
        from recon.recon import full_recon
        return full_recon(domain, output_root=output_root,
                          deep=False, scan_id=scan_id)
    except Exception as e:
        err(f"recon failed: {e}")
        return {}


def run_scanner(domain: str, output_root: str, scan_id: int,
                modules: list = None) -> dict:
    try:
        from scanner.scanner import full_scan
        recon_dir = f"{output_root}/{domain}/recon"
        if not Path(recon_dir).exists():
            warn("recon dir missing — skipping scanner")
            return {}
        return full_scan(domain, recon_dir, output_root=output_root,
                         scan_id=scan_id, modules=modules)
    except Exception as e:
        err(f"scanner failed: {e}")
        return {}


def run_intel(domain: str, output_root: str) -> dict:
    try:
        from intel.intel_merger import run_full_intel
        tech_stack = f"{output_root}/{domain}/recon/tech_stack.json"
        return run_full_intel(domain, output_root,
                              tech_stack_json=tech_stack)
    except Exception as e:
        warn(f"intel failed: {e}")
        return {}


def run_advanced_modules(domain: str, output_root: str,
                         scan_id: int, selected: list = None) -> dict:
    results = {}
    selected_names = set(selected) if selected else None

    banner("ADVANCED MODULES")
    for name, path, attr, _needs_params in MODULE_REGISTRY:
        if selected_names and name not in selected_names:
            continue
        info(f"→ {name}")
        r = _safe_run_module(name, path, attr, domain, output_root, scan_id)
        count = 0
        if isinstance(r, dict):
            count = r.get("count") or len(r.get("findings", []) or [])
        results[name] = {"count": count}
        if count:
            ok(f"{name}: {count} finding(s)")
        else:
            info(f"{name}: 0")

    return results


def run_triage(domain: str, scan_id: int) -> dict:
    """Optional: ask AI to triage pending findings."""
    try:
        from core.ai_engine import is_ai_available, triage_finding
    except Exception:
        return {"skipped": "ai_engine unavailable"}

    if not is_ai_available():
        return {"skipped": "no AI key configured"}

    db = get_db()
    findings = db.get_findings(scan_id, status="pending")
    triaged = 0
    for f in findings[:50]:
        try:
            res = triage_finding(f)
            if not res:
                continue
            verdict = res.get("verdict", "uncertain")
            new_status = {
                "true_positive": "confirmed",
                "false_positive": "false_positive",
            }.get(verdict, "pending")
            if new_status != "pending":
                db.update_finding_status(f["id"], new_status,
                                         confidence=res.get("confidence", 0))
                triaged += 1
        except Exception as e:
            log.debug(f"triage failed: {e}")
    return {"triaged": triaged, "total": len(findings)}


def run_reports(domain: str, output_root: str, scan_id: int,
                use_ai: bool = True) -> list:
    try:
        from reporting.report import generate_reports
        return generate_reports(domain, scan_id, output_root,
                                only_severity=["critical", "high", "medium"],
                                use_ai=use_ai)
    except Exception as e:
        warn(f"report generation failed: {e}")
        return []


# ─────────────────────────────────────────
# Master pipeline
# ─────────────────────────────────────────
def full_pipeline(domain: str, output_root: str = "results",
                  with_intel: bool = True,
                  with_modules: bool = True,
                  with_triage: bool = True,
                  with_reports: bool = True,
                  only_modules: list = None) -> dict:
    """
    End-to-end pipeline.
    """
    banner(f"DREAM FRAMEWORK — FULL PIPELINE: {domain}")

    db = get_db()
    scan_id = db.start_scan(domain)
    info(f"Scan #{scan_id}")

    started = datetime.utcnow()

    # 1) RECON
    try:
        recon = run_recon(domain, output_root, scan_id)
    except Exception as e:
        err(f"recon failed: {e}")
        recon = {}

    # 2) SCANNER (nuclei/xss/sqli/js)
    try:
        scan = run_scanner(domain, output_root, scan_id)
    except Exception as e:
        err(f"scanner failed: {e}")
        scan = {}

    # 3) ADVANCED MODULES
    modules_result = {}
    if with_modules:
        try:
            modules_result = run_advanced_modules(domain, output_root, scan_id,
                                                  selected=only_modules)
        except Exception as e:
            err(f"modules failed: {e}")

    # 4) INTEL
    intel_result = {}
    if with_intel:
        try:
            intel_result = run_intel(domain, output_root)
        except Exception as e:
            warn(f"intel failed: {e}")

    # 5) TRIAGE
    triage_result = {}
    if with_triage:
        try:
            triage_result = run_triage(domain, scan_id)
        except Exception as e:
            warn(f"triage failed: {e}")

    # 6) REPORTS
    reports = []
    if with_reports:
        try:
            reports = run_reports(domain, output_root, scan_id)
        except Exception as e:
            warn(f"report gen failed: {e}")

    # Finish
    db.finish_scan(scan_id, status="done")

    stats = db.stats(scan_id)
    duration = (datetime.utcnow() - started).total_seconds()

    # Save summary
    summary = {
        "domain": domain,
        "scan_id": scan_id,
        "duration_sec": duration,
        "severity_stats": stats,
        "reports_generated": reports,
        "modules": modules_result,
        "triage": triage_result,
    }
    summary_path = Path(output_root) / domain / "pipeline_summary.json"
    ensure_dir(summary_path.parent)
    save_json(summary_path, summary)

    banner("PIPELINE COMPLETE")
    print(f"  Scan ID:        {scan_id}")
    print(f"  Duration:       {duration:.1f}s")
    print(f"  Critical/High:  {stats.get('critical', 0)}/{stats.get('high', 0)}")
    print(f"  Medium/Low:     {stats.get('medium', 0)}/{stats.get('low', 0)}")
    print(f"  Reports:        {len(reports)}")
    print(f"  Summary:        {summary_path}")
    print()

    return summary


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="Dream Framework — Main Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 -m core.core --target example.com --full
  python3 -m core.core --target example.com --recon-only
  python3 -m core.core --target example.com --modules ssti,xxe,sensitive_files
  python3 -m core.core --target example.com --report-only --scan-id 3
        """
    )
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--full", action="store_true",
                      help="recon + scan + modules + intel + triage + reports")
    mode.add_argument("--recon-only", action="store_true")
    mode.add_argument("--scan-only", action="store_true")
    mode.add_argument("--modules-only", action="store_true")
    mode.add_argument("--report-only", action="store_true")

    p.add_argument("--modules", default=None,
                   help="comma-separated list of modules to run")
    p.add_argument("--no-intel", action="store_true")
    p.add_argument("--no-triage", action="store_true")
    p.add_argument("--no-reports", action="store_true")
    p.add_argument("--no-ai", action="store_true",
                   help="skip AI triage/polish")
    p.add_argument("--scan-id", type=int, default=None)

    args = p.parse_args()
    domain = args.target
    out = args.output

    db = get_db()

    try:
        if args.recon_only:
            sid = db.start_scan(domain)
            r = run_recon(domain, out, sid)
            db.finish_scan(sid, "done")
            print(json.dumps(r.get("stats", {}), indent=2))

        elif args.scan_only:
            sid = db.start_scan(domain)
            run_scanner(domain, out, sid)
            db.finish_scan(sid, "done")

        elif args.modules_only:
            sid = db.start_scan(domain)
            sel = [m.strip() for m in (args.modules or "").split(",") if m.strip()] or None
            r = run_advanced_modules(domain, out, sid, selected=sel)
            db.finish_scan(sid, "done")
            print(json.dumps(r, indent=2))

        elif args.report_only:
            sid = args.scan_id
            if sid is None:
                err("--report-only requires --scan-id")
                sys.exit(1)
            files = run_reports(domain, out, sid, use_ai=not args.no_ai)
            print(f"Generated {len(files)} report(s)")

        else:
            # Default: full pipeline
            sel = [m.strip() for m in (args.modules or "").split(",") if m.strip()] or None
            full_pipeline(
                domain, out,
                with_intel=not args.no_intel,
                with_modules=True,
                with_triage=not (args.no_triage or args.no_ai),
                with_reports=not args.no_reports,
                only_modules=sel,
            )

    except KeyboardInterrupt:
        warn("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        err(f"Pipeline failed: {e}")
        log.exception("pipeline error")
        sys.exit(1)


if __name__ == "__main__":
    main()