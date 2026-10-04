"""
modules/graphql_deep.py
-----------------------
GraphQL deep query exploitation.

Beyond introspection:
  - Nested query depth attacks
  - Batching attacks (rate limit bypass)
  - Field suggestions from errors
  - Mutation discovery
  - Query aliasing for brute-force
"""

import json
import re
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("graphql_deep")


# ─────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────
GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/gql", "/api/gql", "/graphiql",
]


def _endpoint_candidates(urls: List[str]) -> List[str]:
    found: Set[str] = set()
    for u in urls:
        low = u.lower()
        if "graphql" in low or "/gql" in low or low.endswith("/query"):
            found.add(u)
    # Also build from unique hosts
    hosts: Set[str] = set()
    for u in urls[:100]:
        try:
            p = urlparse(u)
            hosts.add(f"{p.scheme}://{p.netloc}")
        except Exception:
            continue
    for h in list(hosts)[:20]:
        for path in GRAPHQL_PATHS:
            found.add(h + path)
    return sorted(found)


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────
def _post_graphql(url: str, query: str,
                  variables: Optional[Dict] = None,
                  headers: Optional[Dict] = None) -> Optional[object]:
    acquire(url)
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    return safe_request(url, method="POST", headers=h,
                        data=json.dumps(payload), timeout=12)


# ─────────────────────────────────────────
# Tests
# ─────────────────────────────────────────
def test_introspection(url: str) -> Optional[Dict]:
    """
    Check if full introspection is enabled.
    """
    query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields { name }
        }
      }
    }
    """
    r = _post_graphql(url, query)
    if not r or r.status_code != 200:
        return None
    try:
        data = r.json()
    except Exception:
        return None
    schema = (data.get("data") or {}).get("__schema")
    if not schema:
        return None
    types = schema.get("types", [])
    mutations = schema.get("mutationType")
    subscriptions = schema.get("subscriptionType")
    return {
        "type": "graphql_introspection_full",
        "url": url,
        "evidence": (
            f"{len(types)} types, "
            f"mutations: {'yes' if mutations else 'no'}, "
            f"subscriptions: {'yes' if subscriptions else 'no'}"
        ),
        "severity": "medium",
        "confidence": 95,
        "types_count": len(types),
        "has_mutations": bool(mutations),
        "has_subscriptions": bool(subscriptions),
        "type_names": [t.get("name") for t in types[:50]],
    }


def test_field_suggestions(url: str) -> Optional[Dict]:
    """
    Trigger field suggestions via invalid queries.
    Leaks field names even when introspection is disabled.
    """
    probes = [
        'query { usr }',
        'query { user { id } }',
        'query { admin }',
    ]
    leaked: Set[str] = set()
    for q in probes:
        r = _post_graphql(url, q)
        if not r:
            continue
        text = r.text or ""
        # Common formats: "Did you mean \"user\"?"
        for m in re.finditer(r'[Dd]id you mean\s+["\']?(\w+)', text):
            leaked.add(m.group(1))
        for m in re.finditer(r'["\']suggestion["\']\s*:\s*["\'](\w+)', text):
            leaked.add(m.group(1))
    if leaked:
        return {
            "type": "graphql_field_suggestion_leak",
            "url": url,
            "evidence": f"Leaked fields: {sorted(leaked)[:20]}",
            "severity": "low",
            "confidence": 75,
        }
    return None


def test_deep_nested_query(url: str, depth: int = 15) -> Optional[Dict]:
    """
    Try a deeply-nested query to trigger DoS / depth limit issues.
    """
    # Build nested field: user { friends { friends { ... } } }
    nested = "user"
    for _ in range(depth):
        nested = f"user {{ friends {{ {nested} }} }}"
    # simpler: nest id field
    q = "query { " + ("{ " * depth) + "__typename " + ("} " * depth) + " }"
    r = _post_graphql(url, q)
    if not r:
        return None
    # If it takes >5s or returns 500 → potential DoS
    elapsed = r.elapsed.total_seconds() if hasattr(r, "elapsed") else 0
    if elapsed > 5 or r.status_code in (500, 502, 504):
        return {
            "type": "graphql_deep_query_dos_suspect",
            "url": url,
            "evidence": f"Depth={depth}, response: {r.status_code} in {elapsed:.2f}s",
            "severity": "medium",
            "confidence": 40,
        }
    return None


def test_batching_attack(url: str) -> Optional[Dict]:
    """
    Try sending multiple queries in one request (aliasing) to bypass rate limits.
    """
    # Build aliased query
    parts = []
    for i in range(50):
        parts.append(f'q{i}: __typename')
    q = "query { " + " ".join(parts) + " }"
    r = _post_graphql(url, q)
    if r and r.status_code == 200:
        try:
            data = r.json().get("data") or {}
            if len(data) >= 40:
                return {
                    "type": "graphql_batch_alias_possible",
                    "url": url,
                    "evidence": f"Aliased {len(data)} queries in single request",
                    "severity": "low",
                    "confidence": 60,
                }
        except Exception:
            pass
    return None


def test_batch_array(url: str) -> Optional[Dict]:
    """
    Try JSON array of queries (GraphQL batching).
    """
    payload = [
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ]
    acquire(url)
    r = safe_request(url, method="POST",
                     headers={"Content-Type": "application/json"},
                     data=json.dumps(payload), timeout=12)
    if r and r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list) and len(data) >= 3:
                return {
                    "type": "graphql_batch_array_supported",
                    "url": url,
                    "evidence": "Server accepts JSON array of queries (batch)",
                    "severity": "low",
                    "confidence": 70,
                }
        except Exception:
            pass
    return None


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "graphql_deep", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        info("No URLs to test")
        return {"count": 0, "findings": []}

    endpoints = _endpoint_candidates(urls)
    info(f"Probing {len(endpoints[:30])} GraphQL candidates")

    findings: List[Dict] = []
    working: List[str] = []

    for ep in endpoints[:30]:
        try:
            intro = test_introspection(ep)
            if intro:
                findings.append(intro)
                working.append(ep)

            field = test_field_suggestions(ep)
            if field:
                findings.append(field)

            deep = test_deep_nested_query(ep)
            if deep:
                findings.append(deep)

            batch = test_batch_array(ep)
            if batch:
                findings.append(batch)

            alias = test_batching_attack(ep)
            if alias:
                findings.append(alias)

        except Exception as e:
            log.debug(f"graphql test failed {ep}: {e}")

    # Save
    if working:
        write_lines(mdir / "working_graphql_endpoints.txt", working)

    for f in findings:
        save_finding(domain, "graphql_deep", f["type"], f["severity"],
                     f["url"], evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "graphql_deep_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="GraphQL deep scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "graphql_deep", run, args.output)