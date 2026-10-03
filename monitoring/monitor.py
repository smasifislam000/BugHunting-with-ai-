"""
monitoring/monitor.py
---------------------
Continuous monitoring: re-runs recon periodically and diffs.
Notifies on new subdomains / new findings.
"""

import json
import time
from pathlib import Path
from datetime import datetime
from typing import List, Set, Dict, Optional

from core.logger import get_logger, banner, info, ok, warn
from core.utils import ensure_dir, read_lines, write_lines, save_json, load_json
from core.config_loader import get_config
from monitoring.notifier import notify, notify_finding

log = get_logger("monitor")
cfg = get_config()


def diff_sets(old: Set[str], new: Set[str]) -> Set[str]:
    return new - old


def snapshot_path(domain: str, output_root: str = "results") -> Path:
    return Path(output_root) / domain / "monitoring" / "snapshot.json"


def load_snapshot(domain: str, output_root: str = "results") -> Dict:
    return load_json(snapshot_path(domain, output_root), {})


def save_snapshot(domain: str, data: Dict, output_root: str = "results") -> None:
    p = snapshot_path(domain, output_root)
    ensure_dir(p.parent)
    save_json(p, data)


def tick(domain: str, output_root: str = "results") -> Dict:
    """
    One monitoring iteration:
      1. Re-run subdomain enumeration only (fast).
      2. Diff against previous snapshot.
      3. Notify on new subdomains.
    """
    from recon.subdomain_enum import enumerate_subdomains

    info(f"Monitor tick for {domain}")
    out_dir = Path(output_root) / domain / "recon"
    ensure_dir(out_dir)

    current = set(enumerate_subdomains(domain, str(out_dir)))
    prev_snap = load_snapshot(domain, output_root)
    prev = set(prev_snap.get("subdomains", []))

    new_subs = diff_sets(prev, current)

    result = {
        "ts": datetime.utcnow().isoformat(),
        "subdomains": sorted(current),
        "new_since_last": sorted(new_subs),
    }
    save_snapshot(domain, result, output_root)

    if new_subs:
        msg = (
            f"🔍 *New subdomains detected* for `{domain}`\n"
            + "\n".join(f"• `{s}`" for s in sorted(new_subs)[:20])
        )
        notify(msg)
        ok(f"NEW: {len(new_subs)} subdomains")
    else:
        info("No new subdomains")

    return result


def run_forever(domain: str, interval_hours: int = 6,
                output_root: str = "results") -> None:
    """
    Blocking loop. Ctrl+C to stop.
    """
    banner(f"MONITOR: {domain} every {interval_hours}h")
    interval = max(300, interval_hours * 3600)
    while True:
        try:
            tick(domain, output_root)
        except KeyboardInterrupt:
            info("Monitor stopped by user")
            break
        except Exception as e:
            warn(f"tick failed: {e}")
        info(f"Sleeping {interval_hours}h...")
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Continuous monitor")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-i", "--interval", type=int, default=6,
                   help="hours between checks")
    p.add_argument("-o", "--output", default="results")
    p.add_argument("--once", action="store_true", help="Run one tick then exit")
    args = p.parse_args()

    if args.once:
        print(tick(args.target, args.output))
    else:
        run_forever(args.target, args.interval, args.output)
