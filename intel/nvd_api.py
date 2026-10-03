"""
intel/nvd_api.py
----------------
CVE lookups via NVD API (works without key, rate-limited).
With key: 50 req / 30s. Without: 5 req / 30s.
"""

import time
from typing import Dict, List, Optional

from core.logger import get_logger, info, skip, warn
from core.config_loader import get_config
from core.utils import safe_request, load_json, save_json, ensure_dir

log = get_logger("nvd")
cfg = get_config()

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(keyword: str, max_results: int = 20) -> List[Dict]:
    """
    Search NVD by keyword (e.g., 'wordpress 5.8', 'apache 2.4.49').
    """
    key = cfg.get("api_keys.nvd", "")
    headers = {"apiKey": key} if key else {}

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max_results, 100),
    }
    info(f"NVD search: {keyword}")
    r = safe_request(BASE, params=params, headers=headers, timeout=30)
    if not r or r.status_code != 200:
        if r:
            log.debug(f"NVD HTTP {r.status_code}")
        return []

    try:
        data = r.json()
    except Exception:
        return []

    cves: List[Dict] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id", "")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        metrics = cve.get("metrics", {})
        score, severity = _extract_cvss(metrics)
        cves.append({
            "id": cid,
            "description": desc[:500],
            "cvss_score": score,
            "severity": severity,
            "published": cve.get("published", ""),
            "references": [ref.get("url") for ref in cve.get("references", [])][:5],
        })

    if not key:
        time.sleep(6)  # respect rate limit
    ok(f"NVD: {len(cves)} CVEs for '{keyword}'")
    return cves


def search_by_cpe(cpe: str) -> List[Dict]:
    """Search by CPE string (e.g., 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')."""
    key = cfg.get("api_keys.nvd", "")
    headers = {"apiKey": key} if key else {}
    params = {"cpeName": cpe, "resultsPerPage": 50}
    r = safe_request(BASE, params=params, headers=headers, timeout=30)
    if not r or r.status_code != 200:
        return []
    try:
        return r.json().get("vulnerabilities", [])
    except Exception:
        return []


def _extract_cvss(metrics: Dict) -> tuple:
    """Extract CVSS score + severity from metrics."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key, [])
        if arr:
            m = arr[0]
            data = m.get("cvssData", {})
            return data.get("baseScore", 0.0), data.get("baseSeverity", "UNKNOWN")
    return 0.0, "UNKNOWN"


def cves_for_tech_stack(tech_list: List[str], cache_file: str = ".cache/nvd_cache.json",
                        max_per_tech: int = 10) -> Dict[str, List[Dict]]:
    """
    Look up CVEs for each tech in the list.
    Caches results to avoid re-fetching.
    """
    ensure_dir(".cache")
    cache = load_json(cache_file, {})

    result: Dict[str, List[Dict]] = {}
    for tech in tech_list:
        key = tech.lower().strip()
        if not key:
            continue
        if key in cache:
            result[tech] = cache[key]
            continue
        cves = search_cves(tech, max_results=max_per_tech)
        result[tech] = cves
        cache[key] = cves

    save_json(cache_file, cache)
    return result


if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser()
    parser.add_argument("--keyword", required=True)
    args = parser.parse_args()
    print(json.dumps(search_cves(args.keyword), indent=2, default=str))