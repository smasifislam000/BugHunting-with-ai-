"""
burp/burp_mcp_client.py
-----------------------
MCP client bridge for Burp Suite Pro.

The AI CLI (Claude Code / CommandCode / Cursor) connects to Burp Pro via MCP.
This module provides Python helpers the AI can invoke via tool calls,
or that scripts can use to send structured requests to Burp Pro.

MCP Configuration for Claude Code / CommandCode:
Add to your MCP config (e.g., ~/.config/claude/mcp.json):
{
  "mcpServers": {
    "burp": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-burp"],
      "env": {
        "BURP_MCP_HOST": "127.0.0.1",
        "BURP_MCP_PORT": "9876"
      }
    }
  }
}

This client provides fallback direct HTTP control too.
"""

import json
import time
import socket
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn, skip
from core.utils import safe_request, has_tool, ensure_dir, save_json
from core.config_loader import get_config

log = get_logger("burp_mcp")
cfg = get_config()


# ─────────────────────────────────────────
# Burp MCP Server Discovery
# ─────────────────────────────────────────
def discover_mcp_server(host: str = "127.0.0.1",
                        port: int = 9876,
                        timeout: float = 1.5) -> bool:
    """
    Check if Burp MCP server is listening.
    Returns True if port is open.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def check_burp_mcp_status() -> Dict:
    """
    Diagnose Burp MCP availability.
    """
    host = cfg.get("burp.mcp_host", "127.0.0.1")
    port = cfg.get("burp.mcp_port", 9876)
    enabled = cfg.get("burp.enabled", True)

    status = {
        "enabled": enabled,
        "host": host,
        "port": port,
        "reachable": False,
        "mode": cfg.get("burp.mode", "mcp"),
    }

    if not enabled:
        status["note"] = "Burp integration disabled in config.json"
        return status

    status["reachable"] = discover_mcp_server(host, port)
    if not status["reachable"]:
        status["note"] = (
            f"Burp MCP server not reachable on {host}:{port}. "
            f"Ensure Burp Suite Pro is running with the MCP plugin loaded."
        )
    return status


# ─────────────────────────────────────────
# MCP Tool Wrappers
# (AI agent calls these; they return structured dicts)
# ─────────────────────────────────────────
def mcp_scan_url(url: str,
                 scan_config: Optional[str] = None,
                 scope_only: bool = True) -> Dict:
    """
    Request Burp Pro to actively scan a URL.
    In MCP mode, the AI agent should invoke the 'burp_scan_url' tool
    exposed by the MCP server. This Python helper is a fallback for
    direct REST API (if you also enabled Burp REST API).
    """
    if not url:
        return {"ok": False, "error": "empty url"}

    mode = cfg.get("burp.mode", "mcp")

    if mode == "rest":
        return _rest_scan_url(url, scan_config, scope_only)

    # MCP mode: this is a placeholder the AI replaces with a real tool call
    return {
        "ok": True,
        "mode": "mcp",
        "action": "delegate_to_ai",
        "instruction": (
            f"AI agent: call the MCP tool 'burp_scan_url' with "
            f"url={url!r} scan_config={scan_config!r} scope_only={scope_only}"
        ),
        "url": url,
    }


def mcp_send_request(raw_request: str,
                     host: str = "127.0.0.1",
                     port: int = 8080) -> Dict:
    """
    Send a raw HTTP request through Burp's proxy (127.0.0.1:8080).
    Useful for manual replay / tunneling through Burp.
    """
    try:
        # Parse raw request minimally
        lines = raw_request.replace("\r\n", "\n").split("\n")
        if not lines:
            return {"ok": False, "error": "empty request"}
        request_line = lines[0]
        parts = request_line.split()
        if len(parts) < 3:
            return {"ok": False, "error": "invalid request line"}
        method, path, _ = parts[0], parts[1], parts[2]

        headers = {}
        body_start = 0
        for i, ln in enumerate(lines[1:], 1):
            if not ln.strip():
                body_start = i + 1
                break
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip()] = v.strip()

        body = "\n".join(lines[body_start:]) if body_start else ""

        # Send via Burp proxy
        proxies = {
            "http": f"http://{host}:{port}",
            "https": f"http://{host}:{port}",
        }
        scheme = "https" if "HTTPS" in raw_request[:100].upper() else "http"
        full_url = f"{scheme}://{headers.get('Host', '')}{path}"

        r = safe_request(full_url, method=method, headers=headers,
                         data=body, timeout=20)
        if r is None:
            return {"ok": False, "error": "request failed via Burp proxy"}

        return {
            "ok": True,
            "status": r.status_code,
            "length": len(r.content),
            "headers": dict(r.headers),
            "body": r.text[:5000],
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def mcp_get_collaborator_payload() -> Dict:
    """
    Get a Burp Collaborator payload for OOB testing.
    In MCP mode, AI should call 'burp_collaborator_generate'.
    """
    mode = cfg.get("burp.mode", "mcp")
    if mode == "rest":
        return _rest_get_collaborator()
    return {
        "ok": True,
        "mode": "mcp",
        "instruction": "AI agent: call MCP tool 'burp_collaborator_generate'",
    }


def mcp_poll_collaborator(payload_id: Optional[str] = None) -> Dict:
    """
    Poll Burp Collaborator for interactions.
    In MCP mode, AI should call 'burp_collaborator_poll'.
    """
    mode = cfg.get("burp.mode", "mcp")
    if mode == "rest":
        return _rest_poll_collaborator(payload_id)
    return {
        "ok": True,
        "mode": "mcp",
        "instruction": "AI agent: call MCP tool 'burp_collaborator_poll'",
    }


# ─────────────────────────────────────────
# REST API fallback (if enabled in config)
# ─────────────────────────────────────────
def _rest_base() -> str:
    return cfg.get("burp.rest_api.url", "http://127.0.0.1:1337")


def _rest_headers() -> Dict:
    key = cfg.get("burp.rest_api.api_key", "")
    return {"Authorization": f"Bearer {key}"} if key else {}


def _rest_scan_url(url: str, scan_config: Optional[str],
                   scope_only: bool) -> Dict:
    """
    Direct Burp REST API call (Burp Pro only).
    """
    if not cfg.get("burp.rest_api.enabled", False):
        return {"ok": False, "error": "REST API disabled in config.json"}

    key = cfg.get("burp.rest_api.api_key", "")
    if not key:
        return {"ok": False, "error": "Burp REST API key missing"}

    payload = {
        "urls": [url],
        "scan_configurations": [scan_config] if scan_config else [],
    }
    try:
        import requests
        r = requests.post(
            f"{_rest_base()}/v0.1/scan",
            headers={**_rest_headers(), "Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=15,
        )
        if r.status_code == 201:
            location = r.headers.get("Location", "")
            return {
                "ok": True,
                "mode": "rest",
                "scan_id": location.split("/")[-1] if location else "",
                "url": url,
            }
        return {"ok": False, "error": f"HTTP {r.status_code}", "body": r.text[:500]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _rest_get_collaborator() -> Dict:
    try:
        import requests
        r = requests.post(
            f"{_rest_base()}/v0.1/collaborator/generate",
            headers=_rest_headers(),
            timeout=15,
        )
        if r.status_code in (200, 201):
            return {"ok": True, "mode": "rest", "data": r.json()}
        return {"ok": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _rest_poll_collaborator(payload_id: Optional[str]) -> Dict:
    try:
        import requests
        url = f"{_rest_base()}/v0.1/collaborator/interactions"
        if payload_id:
            url += f"/{payload_id}"
        r = requests.get(url, headers=_rest_headers(), timeout=15)
        if r.status_code == 200:
            return {"ok": True, "mode": "rest", "interactions": r.json()}
        return {"ok": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ─────────────────────────────────────────
# High-level helpers for scripts / AI
# ─────────────────────────────────────────
def bulk_scan(urls: List[str], output_dir: str = "results/burp",
              scan_config: Optional[str] = None) -> Dict:
    """
    Scan a list of URLs through Burp Pro.
    In MCP mode, this returns a delegation plan for the AI.
    """
    ensure_dir(output_dir)

    results = {
        "mode": cfg.get("burp.mode", "mcp"),
        "total": len(urls),
        "delegated": [],
        "errors": [],
    }

    status = check_burp_mcp_status()
    if not status["reachable"] and cfg.get("burp.mode") == "mcp":
        warn(f"Burp MCP unreachable: {status.get('note', '')}")

    for url in urls:
        try:
            res = mcp_scan_url(url, scan_config=scan_config)
            results["delegated"].append({"url": url, "result": res})
        except Exception as e:
            results["errors"].append({"url": url, "error": str(e)})

    save_json(Path(output_dir) / "burp_delegation.json", results)
    ok(f"Burp delegation plan saved: {len(results['delegated'])} URLs")
    return results


# ─────────────────────────────────────────
# CLI diagnostic
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Burp MCP client")
    parser.add_argument("--status", action="store_true",
                        help="Check Burp MCP server reachability")
    parser.add_argument("--scan", help="URL to scan via Burp")
    args = parser.parse_args()

    if args.status:
        st = check_burp_mcp_status()
        print(json.dumps(st, indent=2))
    elif args.scan:
        res = mcp_scan_url(args.scan)
        print(json.dumps(res, indent=2))
    else:
        parser.print_help()