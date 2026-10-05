"""
core/external_cli.py
--------------------
External AI CLI detection and bridge.

Purpose:
  - Detect which AI CLIs are installed (OpenCode, Claude Code, Aider, Goose)
  - Recommend the best CLI for the user's environment
  - Provide a bridge to drive the framework from an external CLI

Supported CLIs:
  - OpenCode       (75+ providers, free tier available)
  - Claude Code    (Anthropic paid)
  - Aider          (BYOK, 75+ providers)
  - Goose          (BYOK, 75+ providers)
  - Cursor         (Anthropic/OpenAI)

Side-effect free:
  - Only reads system state (which tool is installed)
  - Never executes external CLIs on its own
  - Only provides detection and recommendations
"""

import os
import shutil
import subprocess
from typing import Dict, List, Optional

from core.logger import get_logger, info, ok, warn, skip
from core.config_loader import get_config

log = get_logger("external_cli")
cfg = get_config()


# ─────────────────────────────────────────
# Known AI CLIs
# ─────────────────────────────────────────
KNOWN_CLIS = {
    "opencode": {
        "command": "opencode",
        "install": "curl -fsSL https://opencode.ai/install | bash",
        "free_tier": True,
        "providers": "75+ (OpenRouter, Groq, Google, Anthropic, Ollama)",
        "notes": "Best free option. Supports local models via Ollama.",
    },
    "claude": {
        "command": "claude",
        "install": "npm install -g @anthropic-ai/claude-code",
        "free_tier": False,
        "providers": "Anthropic only",
        "notes": "Requires paid Anthropic subscription.",
    },
    "aider": {
        "command": "aider",
        "install": "pip install aider-chat",
        "free_tier": True,
        "providers": "75+ (BYOK)",
        "notes": "Bring your own key. Works with OpenRouter, DeepSeek, etc.",
    },
    "goose": {
        "command": "goose",
        "install": "pip install goose-ai",
        "free_tier": True,
        "providers": "75+ (BYOK)",
        "notes": "Open source AI agent by Block.",
    },
    "cursor": {
        "command": "cursor",
        "install": "https://cursor.sh",
        "free_tier": False,
        "providers": "Anthropic, OpenAI",
        "notes": "Desktop app; CLI mode limited.",
    },
    "continue": {
        "command": "continue",
        "install": "npm install -g @continuedev/cli",
        "free_tier": True,
        "providers": "BYOK",
        "notes": "Open-source. Works with local models.",
    },
}


# ─────────────────────────────────────────
# Detection
# ─────────────────────────────────────────
def is_installed(cli_name: str) -> bool:
    """
    Check if a CLI is available on PATH.
    """
    meta = KNOWN_CLIS.get(cli_name)
    if not meta:
        return False
    return shutil.which(meta["command"]) is not None


def detect_installed() -> Dict[str, bool]:
    """
    Return dict of all known CLIs and whether they are installed.
    """
    return {name: is_installed(name) for name in KNOWN_CLIS}


def get_installed() -> List[str]:
    """
    Return list of installed CLI names.
    """
    return [name for name, present in detect_installed().items() if present]


def get_versions() -> Dict[str, str]:
    """
    Try to get version of each installed CLI.
    """
    versions = {}
    for name in get_installed():
        meta = KNOWN_CLIS[name]
        try:
            r = subprocess.run(
                [meta["command"], "--version"],
                capture_output=True, text=True, timeout=5
            )
            out = (r.stdout or r.stderr or "").strip().split("\n")[0]
            versions[name] = out[:120] if out else "unknown"
        except Exception:
            versions[name] = "unknown"
    return versions


# ─────────────────────────────────────────
# Recommendation
# ─────────────────────────────────────────
def recommend() -> Optional[Dict]:
    """
    Recommend the best CLI based on:
      1. Preference from config.json
      2. Free tier availability
      3. Local model support
    """
    installed = get_installed()
    if not installed:
        return None

    preferred = cfg.get("external_cli.preferred_cli", "opencode")

    # If preferred is installed, use it
    if preferred in installed:
        return {"cli": preferred, "reason": "Preferred in config.json",
                "meta": KNOWN_CLIS[preferred]}

    # Otherwise, prioritize free + opencode + aider + goose
    priority = ["opencode", "aider", "goose", "continue", "claude", "cursor"]
    for name in priority:
        if name in installed:
            return {"cli": name, "reason": "Best available option",
                    "meta": KNOWN_CLIS[name]}

    # Fallback: any installed
    return {"cli": installed[0], "reason": "Only option available",
            "meta": KNOWN_CLIS[installed[0]]}


# ─────────────────────────────────────────
# Environment report
# ─────────────────────────────────────────
def environment_report() -> Dict:
    """
    Full environment report for external CLI mode.
    """
    installed = get_installed()
    versions = get_versions()
    recommendation = recommend()

    report = {
        "external_cli_enabled": cfg.get("external_cli.enabled", True),
        "preferred_cli": cfg.get("external_cli.preferred_cli", "opencode"),
        "installed": installed,
        "versions": versions,
        "recommendation": recommendation,
        "all_known_clis": list(KNOWN_CLIS.keys()),
        "config_note": "See AGENTS.md for External CLI instructions",
    }
    return report


def print_report() -> None:
    """
    Pretty-print environment report.
    """
    print("=" * 60)
    print("  External CLI Environment")
    print("=" * 60)
    installed = get_installed()
    if not installed:
        print()
        print("  No external AI CLI installed.")
        print()
        print("  Install one:")
        for name, meta in KNOWN_CLIS.items():
            print(f"    {name:10s}  {meta['install']}")
        print()
        print("  Recommended: opencode (free, 75+ providers)")
        return

    versions = get_versions()
    print()
    print("  Installed CLIs:")
    for name in installed:
        v = versions.get(name, "unknown")
        print(f"    {name:10s}  {v}")

    rec = recommend()
    if rec:
        print()
        print("  Recommended:")
        print(f"    {rec['cli']}")
        print(f"    Reason: {rec['reason']}")
        print(f"    Providers: {rec['meta']['providers']}")
        print(f"    Free tier: {'Yes' if rec['meta']['free_tier'] else 'No'}")
        print()
        print("  How to use:")
        print(f"    $ {rec['meta']['command']}")
        print("    Then: Read AGENTS.md. Run core.core on target. Analyze.")


# ─────────────────────────────────────────
# Bridge: generate suggested commands for CLI
# ─────────────────────────────────────────
def suggested_commands(target: str = "example.com") -> List[str]:
    """
    Return commands an external CLI can run for the framework.
    """
    return [
        f"python3 -m core.core --target {target} --recon-only",
        f"python3 -m core.core --target {target} --full",
        f"python3 -m core.core --target {target} --modules jwt_attack,ssti",
        "python3 -m core.core --review",
        "python3 -m core.core --review-verify",
    ]


def print_suggested(target: str = "example.com") -> None:
    print()
    print("Suggested commands for external CLI:")
    print()
    for cmd in suggested_commands(target):
        print("  " + cmd)


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser(description="External AI CLI detection")
    p.add_argument("--detect", action="store_true",
                   help="Detect installed CLIs")
    p.add_argument("--recommend", action="store_true",
                   help="Recommend best CLI")
    p.add_argument("--report", action="store_true",
                   help="Full environment report")
    p.add_argument("--suggest", metavar="DOMAIN", default="example.com",
                   help="Suggest commands for a target")
    p.add_argument("--json", action="store_true",
                   help="Output as JSON")

    args = p.parse_args()

    if args.detect:
        installed = get_installed()
        versions = get_versions()
        if args.json:
            print(json.dumps({"installed": installed, "versions": versions},
                             indent=2))
        else:
            print("Installed CLIs:")
            for name in installed:
                print(f"  - {name} ({versions.get(name, '?')})")
            if not installed:
                print("  (none)")

    elif args.recommend:
        rec = recommend()
        if rec:
            if args.json:
                print(json.dumps(rec, indent=2, default=str))
            else:
                print(f"Recommended: {rec['cli']}")
                print(f"Reason:      {rec['reason']}")
        else:
            print("No CLI installed. Try installing opencode:")
            print("  curl -fsSL https://opencode.ai/install | bash")

    elif args.report:
        if args.json:
            print(json.dumps(environment_report(), indent=2, default=str))
        else:
            print_report()

    elif args.suggest:
        print_suggested(args.suggest)

    else:
        print_report()