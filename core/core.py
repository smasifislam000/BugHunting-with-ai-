"""
core/core.py
------------
Dream Framework — MAIN ORCHESTRATOR (FINAL + Fast Engine)

Chains:
  recon → scanner → advanced modules → intel → AI proof → AI triage → reports → verification

AI Modes:
  - auto:        only Critical needs manual approval (default)
  - hybrid:      High + Critical need approval
  - checkpoint:  all Medium+ need approval

Usage:
  python3 -m core.core --target example.com --full
  python3 -m core.core --target example.com --recon-only
  python3 -m core.core --target example.com --modules jwt_attack,ssti
  python3 -m core.core --review
  python3 -m core.core --review-verify
  python3 -m core.core --report-only --scan-id 3
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

# Try fast engine first, fallback to original
try:
    from core.ai_engine_fast import ask_ai, is_ai_available
except ImportError:
    from core.ai_engine import ask_ai, is_ai_available

log = get_logger("core")
cfg = get_config()


# ─────────────────────────────────────────
# AI mode policy
# ─────────────────────────────────────────
AI_MODES = {
    "auto": {
        "info": "auto", "low": "auto",
        "medium": "auto_notify", "high": "auto_notify",
        "critical": "manual_approval",
    },
    "hybrid": {
        "info": "auto", "low": "auto",
        "medium": "auto_notify", "high": "manual_approval",
        "critical": "manual_approval",
    },
    "checkpoint": {
        "info": "auto", "low": "auto_notify",
        "medium": "manual_approval", "high": "manual_approval",
        "critical": "manual_approval",
    },
}


def get_ai_mode() -> str:
    mode = cfg.get("ai_mode.default", "auto")
    if mode not in AI_MODES:
        mode = "auto"
    return mode


def requires_manual_approval(severity: str) -> bool:
    mode = get_ai_mode()
    policy = AI_MODES.get(mode, AI_MODES["auto"])
    action = policy.get((severity or "info").lower(), "auto")
    return action == "manual_approval"


# ─────────────────────────────────────────
# Module registry
# ─────────────────────────────────────────
MODULE_REGISTRY = [
    ("jwt_attack",          "modules.jwt_attack",          "run"),
    ("oauth_test",          "modules.oauth_test",          "run"),
    ("cloud_enum",          "modules.cloud_enum",          "run"),
    ("cloud_metadata",      "modules.cloud_metadata",      "run"),
    ("aws_deep",            "modules.aws_deep",            "run"),
    ("gcp_deep",            "modules.gcp_deep",            "run"),
    ("azure_deep",          "modules.azure_deep",          "run"),
    ("docker_k8s_check",    "modules.docker_k8s_check",    "run"),
    ("graphql_test",        "modules.graphql_test",        "run"),
    ("graphql_deep",        "modules.graphql_deep",        "run"),
    ("open_api",            "modules.open_api",            "run"),
    ("api_versioning",      "modules.api_versioning",      "run"),
    ("cname_takeover",      "modules.cname_takeover",      "run"),
    ("host_header",         "modules.host_header",         "run"),
    ("rdns",                "modules.rdns",                "run"),
    ("ssti",                "modules.ssti",                "run"),
    ("xxe",                 "modules.xxe",                 "run"),
    ("nosql",               "modules.nosql",               "run"),
    ("ldap_injection",      "modules.ldap_injection",      "run"),
    ("crlf_injection",      "modules.crlf_injection",      "run"),
    ("email_header",        "modules.email_header",        "run"),
    ("deserialization",     "modules.deserialization",     "run"),
    ("http2_smuggling",     "modules.http2_smuggling",     "run"),
    ("http_desync",         "modules.http_desync",         "run"),
    ("cache_poison",        "modules.cache_poison",        "run"),
    ("web_cache_deception", "modules.web_cache_deception", "run"),
    ("prototype_pollution", "modules.prototype_pollution", "run"),
    ("postmessage",         "modules.postmessage",         "run"),
    ("dom_clobbering",      "modules.dom_clobbering",      "run"),
    ("css_injection",       "modules.css_injection",       "run"),
    ("dangling_markup",     "modules.dangling_markup",     "run"),
    ("csp_bypass",          "modules.csp_bypass",          "run"),
    ("xs_leaks",            "modules.xs_leaks",            "run"),
    ("sensitive_files",     "modules.sensitive_files",     "run"),
    ("bypass_403",          "modules.bypass_403",          "run"),
    ("diff_analysis",       "modules.diff_analysis",       "run"),
    ("race_condition",      "modules.race_condition",      "run"),
    ("business_logic",      "modules.business_logic",      "run"),
    ("custom_protocol",     "modules.custom_protocol",     "run"),
    ("browser_automation",  "modules.browser_automation",  "run"),
    ("auth_bypass",         "modules.auth_bypass",         "run"),
    ("cdn_misconfig",       "modules.cdn_misconfig",       "run"),
    ("session_analysis",    "modules.session_analysis",    "run"),
    ("websocket_test",      "modules.websocket_test",      "run"),
    ("websocket_smuggling", "modules.websocket_smuggling", "run"),
    ("grpc_test",           "modules.grpc_test",           "run"),
    ("auto_dork",           "modules.auto_dork",           "run"),
    ("nuclei_template_gen", "modules.nuclei_template_gen", "run"),
]


# ─────────────────────────────────────────
# Safe module runner
# ─────────────────────────────────────────
def _safe_run_module(name, module_path, attr, domain, output_root, scan_id):
    try:
        mod = __import__(module_path, fromlist=[attr])
        fn = getattr(mod, attr)
        try:
            result = fn(domain=domain, output_root=output_root, scan_id=scan_id)
        except TypeError:
            result = fn(domain=domain, output_root=output_root)
        return result or {}
    except ImportError as e:
        log.debug("module " + name + " import failed: " + str(e))
        return {"error": "import: " + str(e)}
    except Exception as e:
        log.debug("module " + name + " failed: " + str(e))
        warn("module " + name + ": " + str(e))
        return {"error": str(e)}


# ─────────────────────────────────────────
# Phase runners
# ─────────────────────────────────────────
def run_recon(domain, output_root, scan_id):
    try:
        from recon.recon import full_recon
        return full_recon(domain, output_root=output_root,
                          deep=False, scan_id=scan_id)
    except Exception as e:
        err("recon failed: " + str(e))
        return {}


def run_scanner(domain, output_root, scan_id, modules=None):
    try:
        from scanner.scanner import full_scan
        recon_dir = output_root + "/" + domain + "/recon"
        if not Path(recon_dir).exists():
            warn("recon dir missing - skipping scanner")
            return {}
        return full_scan(domain, recon_dir, output_root=output_root,
                         scan_id=scan_id, modules=modules)
    except Exception as e:
        err("scanner failed: " + str(e))
        return {}


def run_intel(domain, output_root):
    try:
        from intel.intel_merger import run_full_intel
        tech = output_root + "/" + domain + "/recon/tech_stack.json"
        return run_full_intel(domain, output_root, tech_stack_json=tech)
    except Exception as e:
        warn("intel failed: " + str(e))
        return {}


def run_advanced_modules(domain, output_root, scan_id, selected=None):
    results = {}
    selected_names = set(selected) if selected else None

    banner("ADVANCED MODULES")
    for name, path, attr in MODULE_REGISTRY:
        if selected_names and name not in selected_names:
            continue
        info("-> " + name)
        r = _safe_run_module(name, path, attr, domain, output_root, scan_id)
        count = r.get("count", 0) if isinstance(r, dict) else 0
        results[name] = {
            "count": count,
            "error": r.get("error") if isinstance(r, dict) else None,
        }
        if count:
            ok(name + ": " + str(count) + " finding(s)")
        else:
            info(name + ": 0")

    return results


# ─────────────────────────────────────────
# AI Proof phase
# ─────────────────────────────────────────
def run_proof_phase(domain, output_root, scan_id, max_proofs=20):
    result = {}
    try:
        from core.ai_proof import prove_findings
        db = get_db()
        findings = db.get_findings(scan_id)
        if not findings:
            return {"proven": 0, "unconfirmed": 0, "needs_review": 0}

        info("Proving " + str(min(len(findings), max_proofs)) + " findings...")
        result = prove_findings(findings, output_root, max_proofs=max_proofs)
        ok("Proof: " + str(result.get("proven", 0)) + " proven, " +
           str(result.get("unconfirmed", 0)) + " unconfirmed, " +
           str(result.get("needs_review", 0)) + " need review")

        for d in result.get("details", []):
            if d["verdict"] == "PROVEN":
                for f in findings:
                    if (f.get("url") == d["url"]
                            and f.get("vuln_type") == d["vuln_type"]):
                        try:
                            db.update_finding_status(
                                f["id"], "confirmed",
                                confidence=d.get("confidence", 0)
                            )
                        except Exception:
                            pass
    except Exception as e:
        warn("Proof phase failed: " + str(e))
        result = {"error": str(e)}

    return result


# ─────────────────────────────────────────
# AI Triage
# ─────────────────────────────────────────
def run_triage(domain, scan_id, use_feedback=True, use_self_critique=False):
    try:
        from core.ai_engine import is_ai_available as _is_avail
    except Exception:
        try:
            from core.ai_engine_fast import is_ai_available as _is_avail
        except Exception:
            return {"skipped": "ai_engine unavailable"}

    if not _is_avail():
        return {"skipped": "no AI key configured"}

    db = get_db()
    findings = db.get_findings(scan_id, status="pending")
    if not findings:
        return {"triaged": 0, "queued": 0}

    if use_feedback:
        try:
            from core.ai_feedback import get_ai_feedback
            get_ai_feedback()
        except Exception:
            pass

    triaged = 0
    queued = 0

    for f in findings[:100]:
        prompt = (
            "Analyze this finding and return JSON with "
            '{"verdict": "true_positive"|"false_positive"|"uncertain", '
            '"severity": "critical|high|medium|low|info", '
            '"confidence": 0-100, "reasoning": "...", "next_step": "..."}:\n\n'
            + json.dumps(f, ensure_ascii=False)[:2500]
        )

        try:
            res = ask_ai(prompt, json_mode=True, timeout=60,
                         enable_cot=use_self_critique)
        except Exception as e:
            log.debug("ask_ai failed: " + str(e))
            continue

        if not res:
            continue

        verdict = res.get("verdict", "uncertain")
        severity = res.get("severity", f.get("severity", "medium"))
        conf = res.get("confidence", 50)

        if requires_manual_approval(severity):
            try:
                from core.ai_checkpoint import queue_critical
                queue_critical({
                    "vuln_type": f.get("vuln_type"),
                    "severity": severity,
                    "url": f.get("url"),
                    "param": f.get("param"),
                    "payload": f.get("payload"),
                    "evidence": f.get("evidence"),
                    "ai_reasoning": res.get("reasoning"),
                    "ai_next_step": res.get("next_step"),
                    "host": f.get("host", ""),
                }, source="triage")
                queued += 1
            except Exception as e:
                log.debug("checkpoint failed: " + str(e))
            continue

        new_status = {
            "true_positive": "confirmed",
            "false_positive": "false_positive",
        }.get(verdict, "pending")

        if new_status != "pending":
            try:
                db.update_finding_status(f["id"], new_status, confidence=conf)
                triaged += 1
            except Exception as e:
                log.debug("db update failed: " + str(e))

        if use_feedback:
            try:
                from core.ai_feedback import record_accepted, record_rejected
                if verdict == "true_positive":
                    record_accepted("triage", prompt[:500], res)
                elif verdict == "false_positive":
                    record_rejected("triage", prompt[:500], res)
            except Exception:
                pass

    return {
        "triaged": triaged,
        "queued_for_manual": queued,
        "total_pending": len(findings),
    }


# ─────────────────────────────────────────
# Reports + Verification Queue
# ─────────────────────────────────────────
def run_reports(domain, output_root, scan_id, use_ai=True):
    reports = []
    try:
        from reporting.report import generate_reports
        reports = generate_reports(domain, scan_id, output_root,
                                   only_severity=["critical", "high", "medium"],
                                   use_ai=use_ai)
    except Exception as e:
        warn("report generation failed: " + str(e))
        return []

    if not reports:
        return []

    try:
        from core.ai_disclosure import attach_disclosure
        from core.human_verification import queue_for_verification

        queued = 0
        for rp in reports:
            try:
                rp_path = Path(rp)
                md = rp_path.read_text(encoding="utf-8")
                md = attach_disclosure(md, platform="hackerone")
                rp_path.write_text(md, encoding="utf-8")

                stem = rp_path.stem
                parts = stem.split("_")
                vuln_type = parts[1] if len(parts) > 1 else "unknown"
                severity = parts[2] if len(parts) > 2 else "unknown"

                queue_for_verification(str(rp_path), {
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "url": "",
                    "host": domain,
                })
                queued += 1
            except Exception as e:
                log.debug("queue failed for " + str(rp) + ": " + str(e))

        if queued:
            warn(str(queued) + " report(s) queued for manual verification. "
                 "Run: python3 -m core.core --review-verify")
    except Exception as e:
        warn("verification queue failed: " + str(e))

    return reports


# ─────────────────────────────────────────
# Full pipeline
# ─────────────────────────────────────────
def full_pipeline(domain, output_root="results",
                  with_intel=True,
                  with_modules=True,
                  with_proof=True,
                  with_triage=True,
                  with_reports=True,
                  with_feedback=True,
                  with_self_critique=False,
                  only_modules=None):
    banner("DREAM FRAMEWORK - FULL PIPELINE: " + domain)

    db = get_db()
    scan_id = db.start_scan(domain)
    info("Scan #" + str(scan_id) + " | AI mode: " + get_ai_mode())

    started = datetime.utcnow()

    try:
        from core.time_budget import get_budget
        budget = get_budget()
        budget.start("total")
    except Exception:
        budget = None

    recon = run_recon(domain, output_root, scan_id)
    scan = run_scanner(domain, output_root, scan_id)

    modules_result = {}
    if with_modules:
        modules_result = run_advanced_modules(domain, output_root, scan_id,
                                              selected=only_modules)

    intel_result = {}
    if with_intel:
        intel_result = run_intel(domain, output_root)

    proof_result = {}
    if with_proof:
        proof_result = run_proof_phase(domain, output_root, scan_id,
                                       max_proofs=20)

    triage_result = {}
    if with_triage:
        triage_result = run_triage(domain, scan_id,
                                   use_feedback=with_feedback,
                                   use_self_critique=with_self_critique)

    reports = []
    if with_reports:
        reports = run_reports(domain, output_root, scan_id,
                              use_ai=with_triage)

    db.finish_scan(scan_id, status="done")
    stats = db.stats(scan_id)
    duration = (datetime.utcnow() - started).total_seconds()

    summary = {
        "domain": domain,
        "scan_id": scan_id,
        "duration_sec": duration,
        "ai_mode": get_ai_mode(),
        "severity_stats": stats,
        "reports_generated": len(reports),
        "modules": modules_result,
        "proof": proof_result,
        "triage": triage_result,
    }
    summary_path = Path(output_root) / domain / "pipeline_summary.json"
    ensure_dir(summary_path.parent)
    save_json(summary_path, summary)

    banner("PIPELINE COMPLETE")
    print("  Scan ID:        " + str(scan_id))
    print("  Duration:       " + str(round(duration, 1)) + "s")
    print("  Critical:       " + str(stats.get("critical", 0)))
    print("  High:           " + str(stats.get("high", 0)))
    print("  Medium:         " + str(stats.get("medium", 0)))
    print("  Reports:        " + str(len(reports)))
    if proof_result.get("proven"):
        print("  Proven:         " + str(proof_result.get("proven", 0)))
    if triage_result.get("queued_for_manual"):
        print("  Pending:        " + str(triage_result["queued_for_manual"]) +
              " critical (run --review)")
    if reports:
        print("  Verify:         " + str(len(reports)) +
              " report(s) queued (run --review-verify)")
    print("  Summary:        " + str(summary_path))
    print()

    return summary


# ─────────────────────────────────────────
# Review functions
# ─────────────────────────────────────────
def run_review():
    try:
        from core.ai_checkpoint import review_interactive
        review_interactive()
    except Exception as e:
        err("review failed: " + str(e))


def run_verify():
    try:
        from core.human_verification import review_interactive
        review_interactive()
    except Exception as e:
        err("verification failed: " + str(e))


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="Dream Framework - Main Orchestrator (FINAL)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 -m core.core --target example.com --full
  python3 -m core.core --target example.com --recon-only
  python3 -m core.core --target example.com --modules jwt_attack,ssti
  python3 -m core.core --review
  python3 -m core.core --review-verify
  python3 -m core.core --target example.com --full --ai-mode hybrid
        """
    )
    p.add_argument("-t", "--target", help="Target domain")
    p.add_argument("-o", "--output", default="results")

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--full", action="store_true")
    mode.add_argument("--recon-only", action="store_true")
    mode.add_argument("--scan-only", action="store_true")
    mode.add_argument("--modules-only", action="store_true")
    mode.add_argument("--report-only", action="store_true")
    mode.add_argument("--review", action="store_true")
    mode.add_argument("--review-verify", action="store_true",
                      help="Interactive human verification of pending reports")

    p.add_argument("--modules", default=None,
                   help="comma-separated list of modules")
    p.add_argument("--ai-mode", choices=["auto", "hybrid", "checkpoint"],
                   default=None)
    p.add_argument("--no-intel", action="store_true")
    p.add_argument("--no-proof", action="store_true")
    p.add_argument("--no-triage", action="store_true")
    p.add_argument("--no-reports", action="store_true")
    p.add_argument("--no-feedback", action="store_true")
    p.add_argument("--self-critique", action="store_true")
    p.add_argument("--scan-id", type=int, default=None)

    args = p.parse_args()

    if args.review:
        run_review()
        return

    if args.review_verify:
        run_verify()
        return

    if not args.target:
        err("--target is required (except for --review / --review-verify)")
        sys.exit(1)

    if args.ai_mode:
        cfg.data.setdefault("ai_mode", {})["default"] = args.ai_mode

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
            sel = [m.strip() for m in (args.modules or "").split(",")
                   if m.strip()] or None
            r = run_advanced_modules(domain, out, sid, selected=sel)
            db.finish_scan(sid, "done")
            print(json.dumps(r, indent=2))

        elif args.report_only:
            sid = args.scan_id
            if sid is None:
                err("--report-only requires --scan-id")
                sys.exit(1)
            files = run_reports(domain, out, sid, use_ai=not args.no_triage)
            print("Generated " + str(len(files)) + " report(s)")

        else:
            sel = [m.strip() for m in (args.modules or "").split(",")
                   if m.strip()] or None
            full_pipeline(
                domain, out,
                with_intel=not args.no_intel,
                with_modules=True,
                with_proof=not args.no_proof,
                with_triage=not args.no_triage,
                with_reports=not args.no_reports,
                with_feedback=not args.no_feedback,
                with_self_critique=args.self_critique,
                only_modules=sel,
            )

    except KeyboardInterrupt:
        warn("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        err("Pipeline failed: " + str(e))
        log.exception("pipeline error")
        sys.exit(1)


if __name__ == "__main__":
    main()