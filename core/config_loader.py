"""
core/config_loader.py
---------------------
Loads config.json with deep defaults.
Never crashes on missing keys or missing file.
"""

import json
from pathlib import Path
from typing import Any, Dict, List


# ─────────────────────────────────────────
# Default Config (fallback if file missing)
# ─────────────────────────────────────────
DEFAULT_CONFIG: Dict[str, Any] = {
    "system": {
        "version": "1.0.0",
        "workspace": ".",
        "results_dir": "results",
        "logs_dir": "logs",
        "database": "bug_bounty.db",
    },
    "ai_driver": {
        "supported_agents": ["claude-code", "commandcode", "opencode", "cursor"],
        "internal_ai_optional": {
            "enabled": False,
            "provider": "none",
            "providers": {},
        },
    },
    "api_keys": {
        "shodan": "",
        "censys_id": "",
        "censys_secret": "",
        "virustotal": "",
        "securitytrails": "",
        "chaos": "",
        "github_token": "",
        "nvd": "",
    },
    "burp": {
        "enabled": True,
        "mode": "mcp",
        "collaborator": {"enabled": True},
        "match_replace_rules": "burp/match_replace.yaml",
    },
    "scan_settings": {
        "max_concurrent": 20,
        "nuclei_rate_limit": 70,
        "nuclei_severity": ["critical", "high", "medium"],
        "httpx_threads": 50,
        "request_timeout": 10,
        "retry_count": 3,
        "user_agent": "Mozilla/5.0 (compatible; DreamFramework/1.0)",
        "waf_bypass_headers": {},
    },
    "modules": {
        "enabled_by_default": ["recon", "scanner"],
        "optional": [],
    },
    "reporting": {
        "format": "hackerone",
        "auto_generate": True,
        "min_severity": "medium",
        "output_dir": "reports",
    },
    "monitoring": {
        "discord_webhook": "",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
    },
    "safety": {
        "respect_scope": True,
        "rate_limit_per_host": 50,
        "max_requests_per_host": 10000,
    },
}


# ─────────────────────────────────────────
# Deep merge helper
# ─────────────────────────────────────────
def _deep_merge(base: Dict, override: Dict) -> Dict:
    """Recursively merge override into base; override wins."""
    result = dict(base)
    for key, val in (override or {}).items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


# ─────────────────────────────────────────
# Config Class
# ─────────────────────────────────────────
class Config:
    def __init__(self, path: str = "config.json"):
        self.path = Path(path)
        self.data: Dict[str, Any] = {}
        self._load()

    def _load(self):
        if not self.path.exists():
            self.data = dict(DEFAULT_CONFIG)
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            self.data = _deep_merge(DEFAULT_CONFIG, user_cfg)
        except Exception:
            self.data = dict(DEFAULT_CONFIG)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Dot-notation access:
          cfg.get("api_keys.shodan")
          cfg.get("scan_settings.nuclei_rate_limit")
        """
        parts = key.split(".")
        cur: Any = self.data
        for p in parts:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return default
        return cur

    def has_api_key(self, name: str) -> bool:
        """Check if an API key is present and non-empty."""
        val = self.get(f"api_keys.{name}", "")
        return bool(val and str(val).strip())

    def has_censys(self) -> bool:
        return (self.has_api_key("censys_id")
                and self.has_api_key("censys_secret"))

    def enabled_modules(self) -> List[str]:
        return list(self.get("modules.enabled_by_default", []))

    def optional_modules(self) -> List[str]:
        return list(self.get("modules.optional", []))

    def reload(self):
        self._load()

    def __repr__(self):
        return f"<Config path={self.path} keys={len(self.data)}>"


# ─────────────────────────────────────────
# Singleton accessor
# ─────────────────────────────────────────
_config_instance: Config | None = None

def get_config(path: str = "config.json", reload: bool = False) -> Config:
    global _config_instance
    if _config_instance is None or reload:
        _config_instance = Config(path)
    return _config_instance