"""
modules/graphql_introspection.py
--------------------------------
GraphQL introspection + basic exploitation.

Checks:
  - Full introspection enabled
  - Schema leak
  - Field suggestions from errors
  - GET-based introspection (CSRF surface)
"""

import json
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, urljoin

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("graphql_introspection")


INTROSPECTION_QUERY = {
    "query": """
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
}


def _post_graphql(url: str, query: str) -> Optional[object]:
    acquire(url)
    return safe_request(url, method="POST",
                        headers={"Content-Type": "application/json"},
                        data=json.dumps({"query": query}),
                        timeout=12)


def test_introspection(url: str) -> Optional[Dict]:
    r = _post_graphql(url, INTROSPECTION_QUERY["query"])
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
    return {
        "type": "graphql_introspection_enabled",
        "url": url,
        "evidence": (
            f"Full schema exposed: {len(types)} types, "
            f"mutations={'yes' if mutations else 'no'}"
        ),
        "severity": "medium",
        "confidence": 95,
        "types_count": len(types),
        "type_names": [t.get("name") for t in types[:50]],
    }


def test_get_introspection(url: str) -> Optional[Dict]:
    q = "query={__schema{types{name}}}"
    sep = "&" if "?" in url else "?"
    test_url = f"{url}{sep}{q}"
    acquire(test_url)
    r = safe_request(test_url, timeout=10)
    if r and r.status_code == 200 and "__schema" in (r.text or ""):
        return {
            "type": "graphql_get_introspection",
            "url": test_url,
            "evidence": "Introspection works via GET - potential CSRF",
            "severity": "medium",
            "confidence": 80,
        }
    return None


def test_field_suggestion(url: str) -> Optional[Dict]:
    probes = [
        "query { usr }",
        "query { admin }",
        "query { user { id } }",
    ]
    leaked = set()
    for q in probes:
        r = _post_graphql(url, q)
        if not r:
            continue
        text = r.text or ""
        for m in re.finditer(r'[Dd]id you mean\s+["\']?(\w+)', text):
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


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "graphql_introspection", output_root)
    urls = load_urls(domain, output_root)

    # Find graphql candidates
    candidates = set()
    for u in urls:
        low = u.lower()
        if "graphql" in low or "/gql" in low or low.endswith("/query"):
            candidates.add(u)
    # Add common paths
    hosts = set()
    for u in urls[:50]:
        try:
            p = urlparse(u)
            hosts.add(f"{p.scheme}://{p.netloc}")
        except Exception:
            continue
    for h in list(hosts)[:10]:
        for path in ("/graphql", "/api/graphql", "/v1/graphql", "/gql"):
            candidates.add(h + path)

    if not candidates:
        info("No GraphQL endpoints found")
        return {"count": 0, "findings": []}

    info(f"Testing {len(candidates)} GraphQL candidates")
    findings: List[Dict] = []

    for ep in list(candidates)[:30]:
        for tester in (test_introspection, test_get_introspection,
                       test_field_suggestion):
            try:
                r = tester(ep)
                if r:
                    findings.append(r)
            except Exception as e:
                log.debug(f"graphql test failed: {e}")

    for f in findings:
        save_finding(domain, "graphql_introspection", f["type"], f["severity"],
                     f["url"], evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "graphql_findings.txt",
                    [f"[{f['severity']}] {f['type']} -> {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="GraphQL introspection scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "graphql_introspection", run, args.output)