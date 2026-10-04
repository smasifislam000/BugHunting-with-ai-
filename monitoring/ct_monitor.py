"""
monitoring/ct_monitor.py
------------------------
Certificate Transparency log monitoring.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import List, Set, Dict

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, save_json, load_json, ensure_dir
from monitoring.alerts import alert_new_subdomains

log = get_logger("ct_monitor")


def _state_file(domain):
    return Path("results") / domain / "monitoring" / "ct_state.json"


def _load_state(domain):
    return load_json(_state_file(domain), {"known": [], "last_check": ""})


def _save_state(domain, state):
    p = _state_file(domain)
    ensure_dir(p.parent)
    save_json(p, state)


def fetch_crt_sh(domain, timeout=30):
    url = "https://crt.sh/?q=%25." + domain + "&output=json"
    r = safe_request(url, timeout=timeout)
    if not r or r.status_code != 200:
        warn("crt.sh fetch failed")
        return []
    try:
        data = r.json()
    except Exception:
        return []
    return data if isinstance(data, list) else []


def extract_domains(crt_entries):
    domains = set()
    for entry in crt_entries:
        name_val = entry.get("name_value", "")
        common = entry.get("common_name", "")
        for raw in (name_val, common):
            for line in (raw or "").split("\n"):
                d = line.strip().lower()
                if d and "*" not in d:
                    domains.add(d)
    return domains


def check(domain):
    info("CT check for " + domain)
    entries = fetch_crt_sh(domain)
    if not entries:
        return {"new": [], "total_known": 0}

    current = extract_domains(entries)
    state = _load_state(domain)
    known = set(state.get("known", []))
    new_domains = sorted(current - known)

    state["known"] = sorted(known | current)
    state["last_check"] = datetime.utcnow().isoformat()
    _save_state(domain, state)

    if new_domains:
        ok("CT: " + str(len(new_domains)) + " new domain(s)")
        try:
            alert_new_subdomains(domain, new_domains)
        except Exception as e:
            log.debug("alert failed: " + str(e))
    else:
        info("CT: no new domains")

    return {
        "new": new_domains,
        "total_known": len(current),
        "total_certs": len(entries),
    }


def run_forever(domain, interval_minutes=60):
    info("CT monitor started")
    while True:
        try:
            check(domain)
        except KeyboardInterrupt:
            break
        except Exception as e:
            warn("CT monitor failed: " + str(e))
        try:
            time.sleep(interval_minutes * 60)
        except KeyboardInterrupt:
            break
    info("CT monitor stopped")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="CT log monitor")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-i", "--interval", type=int, default=60)
    p.add_argument("--once", action="store_true")
    args = p.parse_args()

    if args.once or args.interval == 0:
        result = check(args.target)
        print(json.dumps(result, indent=2))
    else:
        run_forever(args.target, args.interval)