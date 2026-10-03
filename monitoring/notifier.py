"""
monitoring/notifier.py
----------------------
Send alerts to Discord / Telegram.
Silently skips if no webhook/token configured.
"""

from typing import Optional, Dict
from core.logger import get_logger, info, skip, warn
from core.config_loader import get_config
from core.utils import safe_request

log = get_logger("notifier")
cfg = get_config()


def send_discord(message: str) -> bool:
    url = cfg.get("monitoring.discord_webhook", "")
    if not url:
        return False
    try:
        r = safe_request(url, method="POST",
                         json={"content": message[:2000]}, timeout=10)
        return bool(r and r.status_code in (200, 204))
    except Exception as e:
        log.debug(f"discord failed: {e}")
        return False


def send_telegram(message: str) -> bool:
    token = cfg.get("monitoring.telegram_bot_token", "")
    chat = cfg.get("monitoring.telegram_chat_id", "")
    if not token or not chat:
        return False
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        r = safe_request(url, method="POST",
                         json={"chat_id": chat, "text": message[:4000],
                               "parse_mode": "Markdown"},
                         timeout=10)
        return bool(r and r.status_code == 200)
    except Exception as e:
        log.debug(f"telegram failed: {e}")
        return False


def notify(message: str) -> bool:
    """Try all channels. Returns True if at least one succeeded."""
    sent = False
    if send_discord(message):
        sent = True
    if send_telegram(message):
        sent = True
    if not sent:
        skip("No notifier configured (discord/telegram)")
    return sent


def notify_finding(finding: Dict, domain: str) -> None:
    sev = finding.get("severity", "?").upper()
    msg = (
        f"[{sev}] *{finding.get('vuln_type')}*\n"
        f"Target: `{domain}`\n"
        f"URL: {finding.get('url', '')[:300]}\n"
        f"Evidence: {(finding.get('evidence') or '')[:300]}"
    )
    notify(msg)
