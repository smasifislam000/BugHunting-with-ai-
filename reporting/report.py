"""
reporting/report.py
-------------------
HackerOne / Bugcrowd report generator.
Pulls findings from SQLite, generates Markdown reports.
Optionally asks AI to polish the description.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

from core.logger import get_logger, banner, info, ok, warn, skip
from core.utils import ensure_dir, save_json, safe_filename
from core.config_loader import get_config
from core.database import get_db
from reporting.cvss_calculator import cvss_for
from reporting.poc_generator import poc_for_finding

log = get_logger("report")
cfg = get_config()


# ─────────────────────────────────────────
# HackerOne template
# ─────────────────────────────────────────
H1_TEMPLATE = """# {title}

**Severity:** {severity} (CVSS {score})
**Vector:** `{vector}`
**Target:** {host}
**Vulnerability Type:** {vuln_type}

## Summary

{summary}

## Steps To Reproduce

{steps}

## Proof of Concept

### cURL

```bash
{curl_poc}