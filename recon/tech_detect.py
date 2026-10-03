"""
recon/tech_detect.py
--------------------
Fingerprint web technologies from httpx JSON metadata.
Categorizes tech stacks for downstream module selection.
"""

import json
from pathlib import Path
from typing import List, Dict, Set
from collections import Counter

from core.logger import get_logger, info, ok
from core.utils import load_json, save_json, ensure_dir

log = get_logger("tech_detect")


# ─────────────────────────────────────────
# Tech → Recommended Modules
# ─────────────────────────────────────────
TECH_MODULES = {
    # JavaScript frameworks → DOM XSS, prototype pollution
    "react":       ["browser_automation", "prototype_pollution"],
    "vue":         ["browser_automation", "prototype_pollution"],
    "angular":     ["browser_automation", "prototype_pollution"],
    "next.js":     ["js_analysis", "open_api"],
    "nuxt":        ["js_analysis", "open_api"],

    # Backend → injection
    "php":         ["ssti", "deserialization"],
    "laravel":     ["ssti", "deserialization", "open_api"],
    "django":      ["ssti", "open_api"],
    "flask":       ["ssti"],
    "express":     ["prototype_pollution", "nosql"],
    "node.js":     ["prototype_pollution"],
    "rails":       ["deserialization"],

    # API styles
    "graphql":     ["graphql_test"],
    "swagger":     ["open_api"],
    "openapi":     ["open_api"],

    # Auth
    "jwt":         ["jwt_attack"],
    "oauth":       ["oauth_test"],

    # Databases
    "mongodb":     ["nosql"],

    # Cloud
    "cloudflare":  ["cache_poison", "web_cache_deception"],
    "aws":         ["cloud_enum", "cloud_metadata"],
    "gcp":         ["cloud_enum", "cloud_metadata"],
    "azure":       ["cloud_enum", "cloud_metadata"],

    # Web server
    "nginx":       ["http2_smuggling", "host_header"],
    "apache":      ["http2_smuggling"],
    "iis":         ["http2_smuggling"],

    # CMS
    "wordpress":   ["open_api", "cname_takeover"],
    "drupal":      ["cname_takeover"],
    "joomla":      ["cname_takeover"],
}


def extract_tech_stack(live_hosts_json: str, output_dir: str) -> Dict:
    """
    Read httpx JSON, aggregate all detected tech.
    Writes tech_stack.json with categorized info.
    """
    ensure_dir(output_dir)
    meta = load_json(live_hosts_json, [])

    if not meta:
        info("No live hosts metadata found")
        return {}

    tech_counter: Counter = Counter()
    per_host: List[Dict] = []

    for host in meta:
        techs = host.get("tech", []) or []
        for t in techs:
            tech_counter[t] += 1
        per_host.append({
            "url": host.get("url"),
            "host": host.get("host"),
            "tech": techs,
            "server": host.get("webserver", ""),
            "status": host.get("status_code", 0),
            "cdn": host.get("cdn_name", ""),
        })

    # Aggregate
    tech_list = [t for t, _ in tech_counter.most_common()]
    recommended: Set[str] = set()

    for tech in tech_list:
        key = tech.lower()
        for marker, mods in TECH_MODULES.items():
            if marker in key:
                recommended.update(mods)

    result = {
        "unique_tech": tech_list,
        "tech_counts": dict(tech_counter),
        "per_host": per_host,
        "recommended_modules": sorted(recommended),
    }

    out_file = Path(output_dir) / "tech_stack.json"
    save_json(out_file, result)
    ok(f"Detected {len(tech_list)} unique technologies")
    info(f"Recommended modules: {', '.join(sorted(recommended)) or 'none'}")
    return result


def get_recommended_modules(tech_stack_json: str) -> List[str]:
    data = load_json(tech_stack_json, {})
    return data.get("recommended_modules", [])


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Tech stack detection")
    parser.add_argument("-i", "--input", required=True, help="live_hosts.json")
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args()

    result = extract_tech_stack(args.input, args.output)
    print(f"\nUnique tech: {len(result.get('unique_tech', []))}")
    print(f"Recommended: {result.get('recommended_modules', [])}")