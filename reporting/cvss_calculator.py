"""
reporting/cvss_calculator.py
----------------------------
CVSS v3.1 base score calculator.
Also maps severity strings to default vectors.
"""

from typing import Dict, Optional


# ─────────────────────────────────────────
# Default vectors per vulnerability class
# ─────────────────────────────────────────
DEFAULT_VECTORS = {
    "xss":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",     # 6.1
    "xss_stored":       "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",     # 9.0
    "sqli":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     # 9.8
    "sqli_blind":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     # 7.5
    "ssrf":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",     # 9.1
    "ssrf_cloud":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",     # 10.0→clamped 9.9
    "idor":             "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",     # 6.5
    "idor_write":       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",     # 8.1
    "open_redirect":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",     # 6.1
    "subdomain_takeover":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",    # 9.0
    "rce":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",     # 10.0
    "xxe":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",     # 8.6
    "ssti":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",     # 10.0
    "crlf":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",     # 6.1
    "jwt_alg_none":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",     # 9.1
    "jwt_weak_secret":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     # 9.8
    "jwt_kid_injection":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",     # 9.1
    "oauth_open_redirect":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",   # 9.3
    "oauth_missing_state":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",   # 5.3
    "oauth_missing_pkce":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",    # 5.3
    "graphql_introspection":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", # 5.3
    "s3_bucket_public": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     # 7.5
    "gcp_bucket_public":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     # 7.5
    "azure_blob_public":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     # 7.5
    "openapi_spec_exposed":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "config_leak":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     # 9.8
    "vcs_exposure":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     # 7.5
    "backup_exposed":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     # 7.5
    "info_disclosure":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",     # 5.3
    "cache_poisoning":  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N",     # 5.0
    "web_cache_deception":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",   # 6.5
    "http_cl_te_smuggling":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",  # 8.5
    "http_te_cl_smuggling":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",  # 8.5
    "race_condition_suspect":"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",# 5.9
    "weak_csp":         "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",     # 4.2
    "postmessage_vuln": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",     # 6.1
    "css_injection":    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",     # 3.1
    "dom_xss":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",     # 6.1
    "prototype_pollution_client":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",  # 5.0
    "prototype_pollution_server":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",  # 5.0
    "dangling_markup":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",     # 6.1
    "xs_leaks_headers":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",      # 3.1
    "deserialization_cookie":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",# 8.1
    "deserialization_header":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",# 8.1
    "deserialization_body":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", # 8.1
    "ldap_injection":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",     # 9.1
    "nosql_injection":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     # 9.8
    "nosql_injection_json":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
}


# ─────────────────────────────────────────
# CVSS v3.1 base score
# ─────────────────────────────────────────
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def parse_vector(vector: str) -> Dict[str, str]:
    parts = {}
    for seg in vector.split("/"):
        if ":" in seg:
            k, v = seg.split(":", 1)
            parts[k] = v
    return parts


def base_score(vector: str) -> float:
    """
    Compute CVSS v3.1 base score from vector string.
    """
    try:
        p = parse_vector(vector)
        scope_changed = p.get("S", "U") == "C"
        av = _AV[p["AV"]]
        ac = _AC[p["AC"]]
        pr = (_PR_C if scope_changed else _PR_U)[p["PR"]]
        ui = _UI[p["UI"]]
        c = _CIA[p["C"]]
        i = _CIA[p["I"]]
        a = _CIA[p["A"]]

        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
        if scope_changed:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        else:
            impact = 6.42 * isc_base

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0
        if scope_changed:
            return min(10.0, round(1.08 * (impact + exploitability), 1))
        return min(10.0, round(impact + exploitability, 1))
    except Exception:
        return 0.0


def severity_from_score(score: float) -> str:
    if score == 0:      return "info"
    if score < 4.0:     return "low"
    if score < 7.0:     return "medium"
    if score < 9.0:     return "high"
    return "critical"


def vector_for(vuln_type: str) -> str:
    """Get default vector for a vuln type."""
    key = (vuln_type or "").lower().strip()
    return DEFAULT_VECTORS.get(key, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")


def cvss_for(vuln_type: str) -> Dict:
    """Return {vector, score, severity} for a vuln type."""
    vector = vector_for(vuln_type)
    score = base_score(vector)
    return {
        "vector": vector,
        "score": score,
        "severity": severity_from_score(score),
    }


if __name__ == "__main__":
    import argparse, json
    p = argparse.ArgumentParser()
    p.add_argument("--vector")
    p.add_argument("--type", dest="vuln_type")
    args = p.parse_args()
    if args.vector:
        print(json.dumps({
            "vector": args.vector,
            "score": base_score(args.vector),
            "severity": severity_from_score(base_score(args.vector)),
        }, indent=2))
    elif args.vuln_type:
        print(json.dumps(cvss_for(args.vuln_type), indent=2))
