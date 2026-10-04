"""
modules/_common.py
------------------
Shared helpers used by every module:
- Find recon artifacts
- Load URLs / params
- Save findings to SQLite
- Standard CLI wrapper
"""

from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

from core.logger import get_logger, banner, info, ok, warn
from core.utils import (
    read_lines, write_lines, ensure_dir, save_json, load_json, dedupe
)
from core.config_loader import get_config
from core.database import get_db

log = get_logger("module")
cfg = get_config()


# ─────────────────────────────────────────
# Paths
# ─────────────────────────────────────────
def recon_dir(domain: str, output_root: str = "results") -> Path:
    return Path(output_root) / domain / "recon"


def module_dir(domain: str, module_name: str,
               output_root: str = "results") -> Path:
    p = Path(output_root) / domain / "modules" / module_name
    ensure_dir(p)
    return p


# ─────────────────────────────────────────
# Input helpers
# ─────────────────────────────────────────
def load_live_hosts(domain: str, output_root: str = "results") -> List[str]:
    p = recon_dir(domain, output_root) / "live_hosts.txt"
    return read_lines(p)


def load_urls(domain: str, output_root: str = "results") -> List[str]:
    """Union of live_hosts + js_endpoints + param URLs."""
    base = recon_dir(domain, output_root)
    urls = set()
    for fname in ("live_hosts.txt", "js_endpoints.txt"):
        urls.update(read_lines(base / fname))
    return sorted(urls)


def load_params(domain: str, output_root: str = "results") -> List[str]:
    p = recon_dir(domain, output_root) / "live_hosts.txt"
    return [u for u in read_lines(p) if "?" in u and "=" in u]


def load_tech_stack(domain: str, output_root: str = "results") -> Dict:
    p = recon_dir(domain, output_root) / "tech_stack.json"
    return load_json(p, {})


# ─────────────────────────────────────────
# Finding emitter
# ─────────────────────────────────────────
def save_finding(domain: str, module_name: str, vuln_type: str,
                 severity: str, url: str, param: str = "",
                 payload: str = "", evidence: str = "",
                 confidence: int = 0, scan_id: Optional[int] = None,
                 output_root: str = "results") -> Optional[int]:
    """
    Persist a finding to SQLite AND a JSONL file in the module dir.
    """
    # JSONL log
    mdir = module_dir(domain, module_name, output_root)
    jsonl = mdir / "findings.jsonl"
    record = {
        "ts": datetime.utcnow().isoformat(),
        "module": module_name,
        "type": vuln_type,
        "severity": severity,
        "url": url,
        "param": param,
        "payload": payload[:500],
        "evidence": evidence[:1000],
        "confidence": confidence,
    }
    try:
        import json
        with open(jsonl, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        log.debug(f"findings.jsonl write failed: {e}")

    # DB
    try:
        db = get_db()
        sid = scan_id
        if sid is None:
            sid = db.start_scan(f"{domain}::{module_name}")
        fid = db.add_finding(
            sid,
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            param=param,
            payload=payload,
            evidence=evidence,
            host=_host_of(url),
            confidence=confidence,
        )
        return fid
    except Exception as e:
        log.debug(f"save_finding failed: {e}")
        return None


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc
    except Exception:
        return ""


# ─────────────────────────────────────────
# Standard CLI entrypoint
# ─────────────────────────────────────────
def cli_main(domain: str, module_name: str, fn, output_root: str = "results"):
    """
    Standard wrapper. Called by each module's __main__.
    """
    banner(f"MODULE: {module_name} | {domain}")
    try:
        results = fn(domain=domain, output_root=output_root)
        if isinstance(results, dict):
            count = results.get("count") or len(results.get("findings", []) or [])
            ok(f"{module_name} done — {count} finding(s)")
        else:
            ok(f"{module_name} done")
        return results
    except KeyboardInterrupt:
        warn("Interrupted")
        return None
    except Exception as e:
        log.exception(f"module {module_name} failed: {e}")
        warn(f"{module_name} failed: {e}")
        return None