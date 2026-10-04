"""
monitoring/alerts.py
--------------------
Alert dispatcher for Discord/Telegram.
Dedupe + rate-limit to avoid spam.
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from core.logger import get_logger, info, ok, warn, skip
from core.config_loader import get_config
from monitoring.notifier import send_discord, send_telegram

log = get_logger("alerts")
cfg = get_config()


# ─────────────────────────────────────────
# Rate limiting / dedupe
# ─────────────────────────────────────────
_STATE_FILE = Path(".cache/alerts_state.json")
_MIN_INTERVAL = 60      # seconds between same-type alerts
_DEDUPE_WINDOW = 3600   # do not send same alert within 1 hour


def _load_state() -> Dict:
    if not _STATE_FILE.exists():
        return {"last_sent": {}, "recent": []}
    try:
        with open(_STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"last_sent": {}, "recent": []}


def _save_state(state: Dict) -> None:
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        log.debug(f"state save failed: {e}")


def _should_send(alert_type: str, dedupe_key: str) -> bool:
    state = _load_state()
    now = time.time()

    # Same-type rate limit
    last = state["last_sent"].get(alert_type, 0)
    if now - last < _MIN_INTERVAL:
        return False

    # Dedupe
    cutoff = now - _DEDUPE_WINDOW
    state["recent"] = [
        r for r in state["recent"] if r.get("ts", 0) > cutoff
    ]
    for r in state["recent"]:
        if r.get("key") == dedupe_key:
            return False

    # Record
    state["last_sent"][alert_type] = now
    state["recent"].append({"ts": now, "key": dedupe_key})
    _save_state(state)
    return True


def _send_all(message: str) -> bool:
    sent = False
    if send_discord(message):
        sent = True
    if send_telegram(message):
        sent = True
    return sent


# ─────────────────────────────────────────
# Public alert functions
# ─────────────────────────────────────────
def alert_new_subdomains(domain: str, subdomains: List[str]) -> bool:
    if not subdomains:
        return False
    key = f"newsubs:{domain}:{len(subdomains)}:{subdomains[0]}"
    if not _should_send("new_subdomains", key):
        return False
    lines = [f"🔍 *New subdomains for* `{domain}`"]
    for s in subdomains[:30]:
        lines.append(f"  • `{s}`")
    if len(subdomains) > 30:
        lines.append(f"  … and {len(subdomains) - 30} more")
    return _send_all("\n".join(lines))


def alert_critical_finding(domain: str, finding: Dict) -> bool:
    key = f"critical:{domain}:{finding.get('url', '')}:{finding.get('vuln_type', '')}"
    if not _should_send("critical_finding", key):
        return False
    msg = (
        f"🔴 *CRITICAL finding* on `{domain}`\n"
        f"*Type:* {finding.get('vuln_type', '?')}\n"
        f"*URL:* `{finding.get('url', '')[:200]}`\n"
        f"*Evidence:* {(finding.get('evidence') or '')[:300]}\n"
        f"⚠️ *Requires manual approval*"
    )
    return _send_all(msg)


def alert_high_finding(domain: str, finding: Dict) -> bool:
    key = f"high:{domain}:{finding.get('url', '')}:{finding.get('vuln_type', '')}"
    if not _should_send("high_finding", key):
        return False
    msg = (
        f"🟠 *High finding* on `{domain}`\n"
        f"*Type:* {finding.get('vuln_type', '?')}\n"
        f"*URL:* `{finding.get('url', '')[:200]}`"
    )
    return _send_all(msg)


def alert_scan_complete(domain: str, summary: Dict) -> bool:
    key = f"done:{domain}:{datetime.utcnow().strftime('%Y-%m-%d-%H')}"
    if not _should_send("scan_complete", key):
        return False
    msg = (
        f"✅ *Scan complete:* `{domain}`\n"
        f"• Critical: {summary.get('critical', 0)}\n"
        f"• High:     {summary.get('high', 0)}\n"
        f"• Medium:   {summary.get('medium', 0)}\n"
        f"• Low:      {summary.get('low', 0)}\n"
        f"• Total:    {summary.get('total', 0)}"
    )
    return _send_all(msg)


def alert_scan_error(domain: str, phase: str, error: str) -> bool:
    key = f"err:{domain}:{phase}:{error[:50]}"
    if not _should_send("scan_error", key):
        return False
    msg = (
        f"⚠️ *Scan error* on `{domain}`\n"
        f"*Phase:* {phase}\n"
        f"*Error:* `{error[:300]}`"
    )
    return _send_all(msg)


def alert_custom(title: str, body: str,
                 dedupe_key: Optional[str] = None) -> bool:
    key = dedupe_key or f"custom:{title[:80]}"
    if not _should_send("custom", key):
        return False
    msg = f"*{title}*\n{body}"
    return _send_all(msg)


def test_alerts() -> None:
    """Send a test alert to all configured channels."""
    sent = _send_all("🧪 *Dream Framework alert test* — if you see this, alerts work.")
    if sent:
        ok("Test alert sent")
    else:
        warn("No alert channel configured (set discord_webhook or telegram in config.json)")


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Alerts")
    p.add_argument("--test", action="store_true")
    p.add_argument("--new-subs", nargs=2, metavar=("DOMAIN", "SUBS_CSV"))
    p.add_argument("--critical", metavar="DOMAIN")
    args = p.parse_args()

    if args.test:
        test_alerts()
    elif args.new_subs:
        subs = [s.strip() for s in args.new_subs[1].split(",") if s.strip()]
        alert_new_subdomains(args.new_subs[0], subs)
    elif args.critical:
        alert_critical_finding(args.critical, {
            "vuln_type": "test_vuln",
            "url": "https://example.com/test",
            "evidence": "This is a test alert.",
        })
    else:
        test_alerts()