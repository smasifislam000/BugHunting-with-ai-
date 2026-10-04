"""
modules/azure_deep.py
---------------------
Azure-specific exploitation helpers.

Checks:
  - Azure Blob Storage (multiple containers)
  - Azure Function App exposure
  - Azure AD / OAuth tenant discovery
  - Azure App Service default hostnames
  - Azure metadata via SSRF
"""

import json
import re
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("azure_deep")


# ─────────────────────────────────────────
# Brand extraction
# ─────────────────────────────────────────
def _brand_names(domain: str) -> Set[str]:
    base = domain.split(".")[0].lower()
    names = {base, base.replace("-", ""), base.replace("_", "")}
    for pre in ["", "dev", "staging", "prod", "test", "backup",
                "media", "static", "assets", "cdn", "storage"]:
        for suf in ["", "dev", "staging", "prod", "backup", "media",
                    "static", "assets", "cdn", "files"]:
            names.add(f"{pre}{base}{suf}")
    return {n for n in names if n}


# ─────────────────────────────────────────
# Common blob containers
# ─────────────────────────────────────────
BLOB_CONTAINERS = [
    "", "public", "www", "static", "assets", "media", "images",
    "files", "uploads", "backup", "backups", "data", "documents",
    "logs", "config", "downloads", "private", "temp",
]


# ─────────────────────────────────────────
# Blob storage check
# ─────────────────────────────────────────
def check_blob_storage(account: str) -> List[Dict]:
    findings: List[Dict] = []
    for container in BLOB_CONTAINERS[:12]:
        url = f"https://{account}.blob.core.windows.net/"
        if container:
            url += f"{container}?restype=container&comp=list"
        else:
            url += "?comp=list"
        acquire(url)
        r = safe_request(url, timeout=8)
        if not r:
            continue
        text = r.text or ""
        if r.status_code == 200 and "<EnumerationResults" in text:
            findings.append({
                "type": "azure_blob_public",
                "url": url,
                "evidence": f"Blob container '{container or '(root)'}' public on {account}",
                "severity": "high",
                "confidence": 90,
            })
            break
        if r.status_code == 403 and "AuthenticationFailed" in text:
            findings.append({
                "type": "azure_blob_exists",
                "url": url,
                "evidence": f"Azure storage account '{account}' exists (403)",
                "severity": "info",
                "confidence": 75,
            })
            break
    return findings


# ─────────────────────────────────────────
# Function App / App Service checks
# ─────────────────────────────────────────
def check_function_app(name: str) -> Optional[Dict]:
    urls = [
        f"https://{name}.azurewebsites.net",
        f"https://{name}.azurewebsites.net/api",
    ]
    for url in urls:
        acquire(url)
        r = safe_request(url, timeout=8, allow_redirects=False)
        if not r:
            continue
        text = (r.text or "").lower()
        if r.status_code in (200, 401, 403):
            if "azure" in text or "function" in text or "app service" in text:
                return {
                    "type": "azure_function_app",
                    "url": url,
                    "evidence": f"Azure Function/App Service reachable: {r.status_code}",
                    "severity": "info",
                    "confidence": 60,
                }
    return None


# ─────────────────────────────────────────
# Azure AD tenant discovery
# ─────────────────────────────────────────
def check_azure_ad(domain: str) -> Optional[Dict]:
    """
    Try to discover Azure AD tenant ID for the domain.
    """
    url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
    acquire(url)
    r = safe_request(url, timeout=8)
    if not r or r.status_code != 200:
        return None
    try:
        data = r.json()
    except Exception:
        return None
    if "issuer" in data:
        issuer = data["issuer"]
        m = re.search(r"/([0-9a-f-]{36})/", issuer)
        tenant_id = m.group(1) if m else ""
        return {
            "type": "azure_ad_tenant_discovered",
            "url": url,
            "evidence": f"Azure AD tenant: {tenant_id or issuer}",
            "severity": "info",
            "confidence": 85,
            "tenant_id": tenant_id,
        }
    return None


# ─────────────────────────────────────────
# Azure metadata via SSRF
# ─────────────────────────────────────────
def check_azure_metadata_via_ssrf(url: str) -> Optional[Dict]:
    if "=" not in url:
        return None
    metadata = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    parsed = urlparse(url)
    if not any(p in parsed.query.lower() for p in
               ["url=", "uri=", "target=", "dest="]):
        return None
    test_url = re.sub(r"=(https?://[^&]+)", f"={metadata}", url, count=1)
    acquire(test_url)
    r = safe_request(test_url,
                     headers={"Metadata": "true"},
                     timeout=10)
    if r and ("vmId" in (r.text or "") or "subscriptionId" in (r.text or "")
              or "resourceGroupName" in (r.text or "")):
        return {
            "type": "azure_metadata_ssrf_confirmed",
            "url": test_url,
            "evidence": "Azure metadata service leaked",
            "severity": "critical",
            "confidence": 90,
        }
    return None


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "azure_deep", output_root)
    urls = load_urls(domain, output_root)

    findings: List[Dict] = []
    brands = _brand_names(domain)

    # Blob storage
    info(f"Testing {len(brands)} Azure storage account candidates")
    for b in list(brands)[:30]:
        for f in check_blob_storage(b):
            findings.append(f)

    # Function Apps
    info("Testing Azure Function Apps")
    for b in list(brands)[:15]:
        f = check_function_app(b)
        if f:
            findings.append(f)

    # Azure AD tenant
    info("Discovering Azure AD tenant")
    ad = check_azure_ad(domain)
    if ad:
        findings.append(ad)

    # Azure metadata via SSRF
    for url in urls[:20]:
        try:
            f = check_azure_metadata_via_ssrf(url)
            if f:
                findings.append(f)
        except Exception as e:
            log.debug(f"azure metadata test failed: {e}")

    # Save
    for f in findings:
        save_finding(domain, "azure_deep", f["type"], f["severity"],
                     f["url"], evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "azure_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Azure deep scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "azure_deep", run, args.output)