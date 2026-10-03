"""
modules/race_condition.py
-------------------------
Race condition detection via concurrent request bursts.
Techniques: coupon reuse, double-spend, limit bypass.
Uses ptmultirequest-style parallel HTTP/1.1 pipelining.
"""

import time
import threading
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines, load_json
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("race_condition")


RACE_HINTS = ["coupon", "redeem", "promo", "gift", "voucher",
              "transfer", "withdraw", "claim", "purchase", "checkout",
              "vote", "like", "follow", "subscribe"]


def parallel_burst(url: str, method: str, body: str, headers: dict,
                   count: int = 20) -> List[int]:
    """Send N requests as simultaneously as possible."""
    results: List[int] = [0] * count
    barrier = threading.Barrier(count)

    def worker(i: int):
        try:
            barrier.wait(timeout=5)
        except Exception:
            pass
        r = safe_request(url, method=method, data=body, headers=headers, timeout=15)
        results[i] = r.status_code if r else 0

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return results


def find_race_candidates(urls: List[str]) -> List[Dict]:
    out = []
    for u in urls:
        low = u.lower()
        for hint in RACE_HINTS:
            if hint in low:
                out.append({"url": u, "hint": hint})
                break
    return out


def test_race(candidate: Dict) -> Optional[Dict]:
    url = candidate["url"]
    p = urlparse(url)

    # Try POST first (state-changing)
    for method, body in [("POST", ""), ("GET", "")]:
        try:
            codes = parallel_burst(url, method, body,
                                   {"Content-Type": "application/x-www-form-urlencoded"},
                                   count=20)
        except Exception as e:
            log.debug(f"race burst failed: {e}")
            continue

        # If more than 3 requests returned 2xx, potential race
        success = sum(1 for c in codes if 200 <= c < 300)
        if success >= 3:
            return {
                "type": "race_condition_suspect",
                "url": url,
                "evidence": f"{success}/20 parallel requests succeeded ({candidate['hint']})",
                "severity": "high",
                "confidence": 40,
            }
    return None


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "race_condition", output_root)
    urls = load_urls(domain, output_root)
    candidates = find_race_candidates(urls)
    if not candidates:
        info("No race condition candidates found")
        return {"count": 0, "findings": []}

    info(f"Testing {len(candidates[:20])} race candidates")
    findings: List[Dict] = []

    for cand in candidates[:20]:
        try:
            res = test_race(cand)
            if res:
                findings.append(res)
                save_finding(domain, "race_condition", res["type"], res["severity"],
                             res["url"], evidence=res["evidence"],
                             confidence=res["confidence"],
                             scan_id=scan_id, output_root=output_root)
                warn(f"RACE: {res['url']} — {res['evidence']}")
        except Exception as e:
            log.debug(f"race test failed {cand['url']}: {e}")

    if findings:
        write_lines(mdir / "race_findings.txt",
                    [f"[{f['severity']}] {f['url']} — {f['evidence']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "race_condition", run, args.output)