"""
burp/collaborator.py
--------------------
Out-of-Band (OOB) detection bridge.
Combines: Burp Collaborator (via MCP) + Interactsh (local fallback).
"""

import json
import time
import uuid
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from core.logger import get_logger, info, ok, warn, skip
from core.utils import (
    has_tool, ensure_dir, save_json, load_json,
    run_command_stream, run_command
)
from core.config_loader import get_config
from burp.burp_mcp_client import (
    mcp_get_collaborator_payload, mcp_poll_collaborator
)

log = get_logger("collaborator")
cfg = get_config()


# ─────────────────────────────────────────
# Interactsh (local fallback)
# ─────────────────────────────────────────
class InteractshSession:
    """
    Manage an interactsh-client session via subprocess.
    Falls back gracefully if interactsh-client is missing.
    """

    def __init__(self, output_dir: str = "results/oob"):
        self.output_dir = Path(output_dir)
        ensure_dir(self.output_dir)
        self.proc: Optional[subprocess.Popen] = None
        self.payload: str = ""
        self.log_file = self.output_dir / "interactsh.log"
        self.available = has_tool("interactsh-client")

    def start(self) -> bool:
        if not self.available:
            skip("interactsh-client not installed")
            return False
        if self.proc is not None:
            return True

        info("Starting interactsh-client session")
        try:
            self.proc = subprocess.Popen(
                ["interactsh-client", "-json", "-o", str(self.output_dir / "interactions.json")],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except Exception as e:
            warn(f"Failed to start interactsh: {e}")
            self.proc = None
            return False

        # Wait for payload generation
        for _ in range(30):
            time.sleep(0.5)
            if self.proc.poll() is not None:
                warn("interactsh-client exited early")
                self.proc = None
                return False
            payload = self._read_payload_from_output()
            if payload:
                self.payload = payload
                ok(f"Interactsh payload: {payload}")
                return True
        warn("Timed out waiting for interactsh payload")
        return False

    def _read_payload_from_output(self) -> str:
        """Best-effort read a payload url from log output."""
        try:
            if self.log_file.exists():
                text = self.log_file.read_text(errors="ignore")
                for token in text.split():
                    if ".oast." in token or ".interactsh." in token:
                        return token.strip()
        except Exception:
            pass
        # Try interactions.json too
        try:
            data = load_json(self.output_dir / "interactions.json", [])
            if isinstance(data, list) and data:
                return ""
        except Exception:
            pass
        return ""

    def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None

    def read_interactions(self) -> List[Dict]:
        """Read interactions from the output file."""
        data = load_json(self.output_dir / "interactions.json", [])
        if isinstance(data, list):
            return data
        return []


# ─────────────────────────────────────────
# High-level OOB helpers
# ─────────────────────────────────────────
def get_oob_payload() -> Dict:
    """
    Get an OOB payload from Burp Collaborator (MCP) OR Interactsh.
    """
    # Prefer Burp Collaborator via MCP
    if cfg.get("burp.collaborator.enabled", True) and cfg.get("burp.enabled", True):
        result = mcp_get_collaborator_payload()
        if result.get("ok"):
            return result

    # Fallback to Interactsh
    sess = InteractshSession()
    if sess.start():
        return {
            "ok": True,
            "source": "interactsh",
            "payload": sess.payload,
            "session": sess,
        }
    return {"ok": False, "error": "no OOB provider available"}


def poll_oob(provider_session=None) -> List[Dict]:
    """
    Poll for OOB interactions.
    """
    interactions: List[Dict] = []

    if cfg.get("burp.collaborator.enabled", True) and cfg.get("burp.enabled", True):
        result = mcp_poll_collaborator()
        if result.get("ok"):
            data = result.get("interactions") or result.get("data")
            if isinstance(data, list):
                interactions.extend(data)

    if provider_session and isinstance(provider_session, InteractshSession):
        interactions.extend(provider_session.read_interactions())

    return interactions


def inject_oob_into_params(urls_file: str, output_file: str,
                           param_names: Optional[List[str]] = None) -> int:
    """
    Inject an OOB payload into all parameters of URLs.
    Returns count of URLs processed.
    """
    from core.utils import read_lines, write_lines, inject_param, get_params

    urls = read_lines(urls_file)
    if not urls:
        return 0

    oob = get_oob_payload()
    if not oob.get("ok"):
        warn("No OOB payload available")
        return 0
    payload = oob.get("payload") or ""
    if not payload:
        return 0

    out_lines: List[str] = []
    for url in urls:
        params = get_params(url)
        for p in params:
            if param_names and p not in param_names:
                continue
            out_lines.append(inject_param(url, p, payload))

    write_lines(output_file, out_lines)
    ok(f"Injected OOB into {len(out_lines)} param variants → {output_file}")
    return len(out_lines)


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="OOB / Collaborator helper")
    parser.add_argument("--get-payload", action="store_true")
    parser.add_argument("--poll", action="store_true")
    parser.add_argument("--inject", help="URLs file to inject OOB into")
    parser.add_argument("--out", default="results/oob/injected.txt")
    args = parser.parse_args()

    if args.get_payload:
        print(json.dumps(get_oob_payload(), indent=2, default=str))
    elif args.poll:
        print(json.dumps(poll_oob(), indent=2, default=str))
    elif args.inject:
        n = inject_oob_into_params(args.inject, args.out)
        print(f"Injected: {n}")
    else:
        parser.print_help()