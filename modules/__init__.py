"""
Dream Framework - Advanced Modules
==================================
Each module is standalone:
  python3 -m modules.<name> --target <domain>

All modules:
  - Read recon artifacts from results/<domain>/recon/
  - Write output to results/<domain>/modules/<name>/
  - Insert findings into SQLite (bug_bounty.db)
  - Skip gracefully if tools/API keys are missing
"""

__all__ = [
    # Auth
    "jwt_attack",
    "oauth_test",
    "auth_bypass",
    "session_analysis",
    # Cloud
    "cloud_enum",
    "cloud_metadata",
    "docker_k8s_check",
    # API
    "graphql_test",
    "open_api",
    "api_versioning",
    # Infrastructure
    "cname_takeover",
    "host_header",
    "cdn_misconfig",
    # Modern web
    "websocket_test",
    "grpc_test",
    "postmessage",
    "dom_clobbering",
    "prototype_pollution",
    "browser_automation",
    # Injection
    "ssti",
    "xxe",
    "nosql",
    "ldap_injection",
    "deserialization",
    "crlf_injection",
    "email_header",
    # Protocol
    "http2_smuggling",
    "http_desync",
    "websocket_smuggling",
    # Client-side
    "csp_bypass",
    "css_injection",
    "xs_leaks",
    "dangling_markup",
    # Cache
    "cache_poison",
    "web_cache_deception",
    # Race/logic
    "race_condition",
    "business_logic",
]