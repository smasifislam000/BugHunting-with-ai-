"""
modules/cloud_enum.py
---------------------
Cloud bucket enumeration for the target's domain name.
Supports: AWS S3, GCP Storage, Azure Blob.
Uses the domain's brand name to guess bucket names.
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines, dedupe
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("cloud_enum")


# Common suffixes / prefixes for buckets
PREFIXES = ["", "dev-", "staging-", "prod-", "test-", "backup-", "media-",
            "static-", "assets-", "cdn-", "uploads-", "data-", "public-"]
SUFFIXES = ["", "-dev", "-staging", "-prod", "-backup", "-media",
            "-static", "-assets", "-cdn", "-uploads", "-data", "-public",
            "-files", "-images", "-logs", "-archive"]


def brand_names(domain: str) -> List[str]:
    """Extract brand-like names from domain."""
    base = domain.split(".")[0]
    names = {base}
    # hyphenated / without hyphens
    names.add(base.replace("-", ""))
    names.add(base.replace("_", ""))
    return [n for n in names if n]


def probe_s3(bucket: str) -> Optional[Dict]:
    """Check AWS S3 bucket."""
    url = f"https://{bucket}.s3.amazonaws.com"
    r = safe_request(url, timeout=8)
    if not r:
        return None
    if r.status_code in (200, 403):
        # 200 = public list, 403 = exists but locked
        listing = "ListBucketResult" in (r.text or "")
        return {
            "provider": "aws",
            "bucket": bucket,
            "url": url,
            "public": listing,
            "status": r.status_code,
            "severity": "high" if listing else "low",
            "type": "s3_bucket_public" if listing else "s3_bucket_exists",
        }
    return None


def probe_gcp(bucket: str) -> Optional[Dict]:
    """Check GCP Storage bucket."""
    url = f"https://storage.googleapis.com/{bucket}"
    r = safe_request(url, timeout=8)
    if not r:
        return None
    if r.status_code == 200 and "<ListBucketResult" in (r.text or ""):
        return {
            "provider": "gcp",
            "bucket": bucket,
            "url": url,
            "public": True,
            "severity": "high",
            "type": "gcp_bucket_public",
        }
    if r.status_code in (401, 403):
        return {
            "provider": "gcp",
            "bucket": bucket,
            "url": url,
            "public": False,
            "severity": "low",
            "type": "gcp_bucket_exists",
        }
    return None


def probe_azure(bucket: str) -> Optional[Dict]:
    """Check Azure Blob (best-effort)."""
    url = f"https://{bucket}.blob.core.windows.net/?comp=list"
    r = safe_request(url, timeout=8)
    if not r:
        return None
    if r.status_code == 200 and "<EnumerationResults" in (r.text or ""):
        return {
            "provider": "azure",
            "bucket": bucket,
            "url": url,
            "public": True,
            "severity": "high",
            "type": "azure_blob_public",
        }
    return None


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "cloud_enum", output_root)
    brands = brand_names(domain)

    candidates = set()
    for b in brands:
        for pre in PREFIXES:
            for suf in SUFFIXES:
                candidates.add(f"{pre}{b}{suf}".lower())

    candidates = sorted(candidates)
    info(f"Testing {len(candidates)} bucket name candidates")

    findings: List[Dict] = []
    for cand in candidates:
        for prober in (probe_s3, probe_gcp, probe_azure):
            try:
                res = prober(cand)
                if res:
                    findings.append(res)
                    save_finding(
                        domain, "cloud_enum", res["type"], res["severity"],
                        res["url"], evidence=f"{res['provider']} bucket={res['bucket']} public={res.get('public')}",
                        confidence=90 if res.get("public") else 50,
                        scan_id=scan_id, output_root=output_root,
                    )
            except Exception as e:
                log.debug(f"probe failed {cand}: {e}")

    if findings:
        write_lines(mdir / "buckets.txt",
                    [f"{f['provider']} | {f['bucket']} | {f['url']}" for f in findings])
        publics = [f for f in findings if f.get("public")]
        if publics:
            warn(f"FOUND {len(publics)} PUBLIC BUCKETS")

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "cloud_enum", run, args.output)