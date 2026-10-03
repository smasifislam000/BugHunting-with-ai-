"""
modules/graphql_test.py
-----------------------
GraphQL discovery + introspection + basic abuse:
- Introspection enabled?
- GraphQL endpoint discovery
- Suggest batching attacks
- Detect GET-based GraphQL (CSRF-like)
"""

import json
import re
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines, dedupe
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("graphql_test")


GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/v1/graphql", "/v2/graphql",
    "/api/graphql", "/query", "/gql", "/api/gql",
]

INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types { name kind }
      }
    }
    """
}


def discover_graphql(urls: List[str]) -> List[str]:
    """Find likely GraphQL endpoints."""
    found = set()
    for u in urls:
        path = urlparse(u).path.lower()
        if "graphql" in path or path.endswith("/gql") or path == "/query":
            found.add(u)
    # Probe common paths on each unique host
    hosts = set()
    for u in urls[:50]:
        p = urlparse(u)
        hosts.add(f"{p.scheme}://{p.netloc}")
    for host in list(hosts)[:20]:
        for path in GRAPHQL_PATHS:
            found.add(host + path)
    return sorted(found)


def test_introspection(endpoint: str) -> Optional[Dict]:
    """Send introspection query."""
    r = safe_request(endpoint, method="POST",
                     headers={"Content-Type": "application/json"},
                     json=INTROSPECTION_QUERY, timeout=15)
    if not r:
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except Exception:
        return None
    if "data" in data and "__schema" in (data.get("data") or {}):
        schema = data["data"]["__schema"]
        types = schema.get("types", [])
        return {
            "type": "graphql_introspection_enabled",
            "url": endpoint,
            "evidence": f"Introspection enabled. {len(types)} types exposed.",
            "severity": "medium",
            "confidence": 95,
            "types": [t.get("name") for t in types[:30]],
        }
    return None


def test_get_introspection(endpoint: str) -> Optional[Dict]:
    """Try introspection via GET (CSRF-able)."""
    q = "query={__schema{types{name}}}"
    url = f"{endpoint}?{q}"
    r = safe_request(url, timeout=15)
    if r and r.status_code == 200 and "__schema" in (r.text or ""):
        return {
            "type": "graphql_get_introspection",
            "url": url,
            "evidence": "Introspection works via GET — potential CSRF",
            "severity": "medium",
            "confidence": 80,
        }
    return None


def test_field_suggestion(endpoint: str) -> Optional[Dict]:
    """Trigger field suggestions in error messages (info disclosure)."""
    bad = {"query": "query { nonexistent_field_xyz }"}
    r = safe_request(endpoint, method="POST",
                     headers={"Content-Type": "application/json"},
                     json=bad, timeout=15)
    if not r:
        return None
    text = r.text or ""
    if "Did you mean" in text or "suggestions" in text.lower():
        return {
            "type": "graphql_field_suggestion",
            "url": endpoint,
            "evidence": "Field suggestions leak schema names",
            "severity": "low",
            "confidence": 75,
        }
    return None


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "graphql_test", output_root)
    urls = load_urls(domain, output_root)

    endpoints = discover_graphql(urls)
    if not endpoints:
        info("No GraphQL endpoints detected")
        return {"count": 0, "findings": []}

    info(f"Probing {len(endpoints)} candidate GraphQL endpoints")
    findings: List[Dict] = []
    working: List[str] = []

    for ep in endpoints[:80]:
        try:
            r = test_introspection(ep)
            if r:
                findings.append(r)
                working.append(ep)
                continue
            r = test_get_introspection(ep)
            if r:
                findings.append(r)
                working.append(ep)
                continue
            r = test_field_suggestion(ep)
            if r:
                findings.append(r)
                working.append(ep)
        except Exception as e:
            log.debug(f"graphql test failed {ep}: {e}")

    # Save
    write_lines(mdir / "working_graphql.txt", working)
    for f in findings:
        save_finding(domain, "graphql_test", f["type"], f["severity"],
                     f["url"], evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "graphql_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "graphql_test", run, args.output)