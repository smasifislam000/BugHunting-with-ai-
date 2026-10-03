"""
reporting/poc_generator.py
--------------------------
Generate PoC commands (curl, python, HTTP raw) for findings.
"""

from typing import Dict, Optional


def curl_poc(url: str, method: str = "GET", headers: Optional[Dict] = None,
             data: str = "", payload_note: str = "") -> str:
    lines = [f"curl -i -sk -X {method}"]
    for k, v in (headers or {}).items():
        lines.append(f'  -H "{k}: {v}"')
    if data:
        lines.append(f"  --data '{data}'")
    lines.append(f'  "{url}"')
    cmd = " \\\n".join(lines)
    if payload_note:
        cmd = f"# PoC: {payload_note}\n{cmd}"
    return cmd


def raw_http_poc(url: str, method: str = "GET",
                 headers: Optional[Dict] = None,
                 body: str = "") -> str:
    from urllib.parse import urlparse
    p = urlparse(url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    host = p.netloc
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    lines.append("Connection: close")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("")
    if body:
        lines.append(body)
    return "\r\n".join(lines)


def python_poc(url: str, method: str = "GET",
               headers: Optional[Dict] = None,
               data: str = "") -> str:
    code = f"""import requests

url = {url!r}
headers = {headers!r}
data = {data!r}

r = requests.request({method!r}, url, headers=headers, data=data, verify=False)
print(r.status_code)
print(r.text[:2000])
"""
    return code


def poc_for_finding(finding: Dict) -> Dict:
    """Return {curl, raw_http, python} PoC strings."""
    url = finding.get("url", "")
    method = finding.get("method", "GET")
    payload = finding.get("payload", "")
    param = finding.get("param", "")

    headers = {}
    if payload and method == "POST":
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    note = f"inject '{payload[:80]}' into param '{param}'" if param else ""

    return {
        "curl":      curl_poc(url, method, headers, data=(payload if method == "POST" else ""), payload_note=note),
        "raw_http":  raw_http_poc(url, method, headers, body=(payload if method == "POST" else "")),
        "python":    python_poc(url, method, headers, data=(payload if method == "POST" else "")),
    }


if __name__ == "__main__":
    import json
    sample = {"url": "https://example.com/?q=1", "method": "GET",
              "param": "q", "payload": "<script>alert(1)</script>"}
    print(json.dumps(poc_for_finding(sample), indent=2))
