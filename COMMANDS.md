# 📘 COMMANDS.md — Complete Command Reference

> **This file lists EVERY command you can run in this framework.**
> Each command has a title, what it does, and example output.

---

## 📖 Table of Contents

1. [First-Time Setup](#-1-first-time-setup)
2. [Daily Usage](#-2-daily-usage)
3. [Reconnaissance Commands](#-3-reconnaissance-commands)
4. [Scanner Commands](#-4-scanner-commands)
5. [Advanced Module Commands](#-5-advanced-module-commands)
6. [AI Engine Commands](#-6-ai-engine-commands)
7. [Intelligence Commands](#-7-intelligence-commands)
8. [Burp Suite Commands](#-8-burp-suite-commands)
9. [Report Generation Commands](#-9-report-generation-commands)
10. [Monitoring Commands](#-10-monitoring-commands)
11. [External CLI Commands](#-11-external-cli-commands)
12. [Utility Commands](#-12-utility-commands)
13. [Troubleshooting Commands](#-13-troubleshooting-commands)

---

## 🚀 1. First-Time Setup

### 1.1 — Clone Repository

```bash
git clone https://github.com/smasifislam000/BugHunting-with-ai-.git
cd BugHunting-with-ai-
```

**What it does:** Downloads the entire framework to your device.

### 1.2 — Run Setup Script

```bash
chmod +x setup.sh
bash setup.sh
```

**What it does:** Installs all Go/Python tools (subfinder, nuclei, ffuf, etc.)
**Time:** ~15 minutes

### 1.3 — Install Python Dependencies

```bash
pip3 install -r requirements.txt --break-system-packages
```

**What it does:** Installs Python packages (requests, shodan, etc.)

### 1.4 — Install aiohttp (for parallel AI)

```bash
pip3 install aiohttp --break-system-packages
```

**What it does:** Enables parallel AI calls (5-10x faster).

### 1.5 — Install Playwright (optional, for video evidence)

```bash
pip3 install playwright --break-system-packages
python3 -m playwright install chromium
```

**What it does:** Enables browser automation for DOM XSS + video PoC.

### 1.6 — Verify Installation

```bash
bash scripts/diagnose.sh
```

**What it does:** Checks all tools. Shows ✅ for present, ❌ for missing.

### 1.7 — Configure API Keys

```bash
nano config.json
```

**What it does:** Opens config editor. Add your AI provider key here.

### 1.8 — Verify AI Status

```bash
python3 -m core.ai_engine_fast --status
```

**Expected output:**
```
Active: commandcode | model: command-r-plus
Total providers: 1
  - commandcode (command-r-plus)
```

---

## 📅 2. Daily Usage

### 2.1 — Full Automated Scan (Main Command)

```bash
python3 -m core.core --target example.com --full
```

**What it does:** Runs the complete pipeline:
1. Recon → 2. Scanner → 3. Advanced modules → 4. Intel
5. AI Proof → 6. AI Triage → 7. Reports → 8. Verification Queue

**Time:** 30 min to 3 hours (depends on target size)
**Output:** `results/example.com/`

### 2.2 — Quick Recon Only (Fast Test)

```bash
python3 -m core.core --target example.com --recon-only
```

**What it does:** Only runs reconnaissance (subdomains + live hosts + tech).
**Time:** 2-5 minutes
**Best for:** First test, quick overview.

### 2.3 — Scan Only

```bash
python3 -m core.core --target example.com --scan-only
```

**What it does:** Only runs scanners (nuclei, xss, sqli, js analysis).
**Requires:** Recon must be done first.
**Time:** 20-60 minutes

### 2.4 — Modules Only

```bash
python3 -m core.core --target example.com --modules-only
```

**What it does:** Only runs all advanced modules (48 modules).
**Requires:** Recon must be done first.

### 2.5 — Specific Modules

```bash
python3 -m core.core --target example.com --modules jwt_attack,ssti,xxe
```

**What it does:** Runs only the specified modules.
**Available modules:** See Section 5.

### 2.6 — Review Critical Findings

```bash
python3 -m core.core --review
```

**What it does:** Interactive review of pending Critical findings.
**When:** After a scan, before submitting anything.

**Interactive options:**
- `[a]pprove` — Mark as True Positive, generate report
- `[r]eject` — Mark as False Positive, discard
- `[s]kip` — Review later
- `[o]pen` — Show full preview
- `[q]uit` — Exit

### 2.7 — Verify Pending Reports

```bash
python3 -m core.core --review-verify
```

**What it does:** Interactive verification of generated reports.
**When:** After reports are generated, before submission to HackerOne.

**Interactive options:** Same as `--review`.

### 2.8 — Change AI Mode

```bash
python3 -m core.core --target example.com --full --ai-mode hybrid
```

**Available modes:**
- `auto` — Only Critical needs approval (default)
- `hybrid` — High + Critical need approval
- `checkpoint` — Medium + High + Critical need approval

### 2.9 — Skip AI Triage

```bash
python3 -m core.core --target example.com --full --no-triage
```

**What it does:** Runs the pipeline without AI triage (saves tokens).

### 2.10 — Skip Reports Generation

```bash
python3 -m core.core --target example.com --full --no-reports
```

**What it does:** Runs the pipeline without generating reports (just findings).

---

## 🔍 3. Reconnaissance Commands

### 3.1 — Full Recon

```bash
python3 -m recon.recon --target example.com
```

**What it does:**
- Subdomain enumeration (7 sources)
- Live host detection
- DNS resolution
- Tech stack fingerprinting

**Output folder:** `results/example.com/recon/`

### 3.2 — Deep Recon

```bash
python3 -m recon.recon --target example.com --deep
```

**What it does:** Adds slower sources (amass, permutations).
**Time:** 30+ minutes

### 3.3 — Subdomain Enumeration Only

```bash
python3 -m recon.subdomain_enum --domain example.com --output results/example.com/recon
```

**What it does:** Runs subfinder, amass, chaos, etc.

### 3.4 — Live Host Detection

```bash
python3 -m recon.live_hosts --input results/example.com/recon/subdomains.txt --output results/example.com/recon
```

**What it does:** Uses httpx to find which subdomains are alive.

### 3.5 — Tech Stack Detection

```bash
python3 -m recon.tech_detect --input results/example.com/recon/live_hosts.json --output results/example.com/recon
```

**What it does:** Identifies technologies (React, WordPress, etc.)

### 3.6 — ASN Discovery

```bash
python3 -m recon.asn_discovery --ips results/example.com/recon/ips.txt --output results/example.com/recon
```

**What it does:** Finds ASN + IP ranges for the target.

### 3.7 — Subdomain Takeover Check

```bash
python3 -m recon.cname_takeover --recon-dir results/example.com/recon --output results/example.com/recon
```

**What it does:** Checks if any subdomain is vulnerable to takeover.

### 3.8 — Parameter Discovery

```bash
python3 -m recon.parameter_discovery --list results/example.com/recon/live_hosts.txt --output results/example.com/recon
```

**What it does:** Finds hidden parameters via arjun.

---

## 🎯 4. Scanner Commands

### 4.1 — Full Scan Pipeline

```bash
python3 -m scanner.scanner --target example.com
```

**What it does:** Runs nuclei + XSS + SQLi + JS analysis.
**Requires:** Recon done first.
**Output folder:** `results/example.com/scans/`

### 4.2 — Nuclei Only

```bash
python3 -m scanner.nuclei_runner --list results/example.com/recon/live_hosts.txt --output results/example.com/scans
```

**What it does:** Runs nuclei with critical/high/medium severity.

**With specific severity:**
```bash
python3 -m scanner.nuclei_runner --list results/example.com/recon/live_hosts.txt --output results/example.com/scans --severity critical,high
```

**With specific tags:**
```bash
python3 -m scanner.nuclei_runner --list results/example.com/recon/live_hosts.txt --output results/example.com/scans --tags cve,rce
```

### 4.3 — XSS Scan

```bash
python3 -m scanner.xss_scanner --list results/example.com/recon/live_hosts.txt --output results/example.com/scans --modes reflected
```

**Modes:**
```bash
--modes reflected           # Reflected XSS only (fast)
--modes reflected,stored    # Reflected + Stored
--modes reflected,stored,dom  # All types
--modes blind               # Blind XSS (OOB)
```

### 4.4 — SQLi Scan

```bash
python3 -m scanner.sqli_scanner --list results/example.com/recon/live_hosts.txt --output results/example.com/scans
```

**With custom level/risk:**
```bash
python3 -m scanner.sqli_scanner --list results/example.com/recon/live_hosts.txt --output results/example.com/scans --level 3 --risk 2
```

**Levels:** 1-5 (higher = deeper but slower)
**Risk:** 1-3 (higher = more aggressive but risky)

### 4.5 — SSRF Scan

```bash
python3 -m scanner.ssrf_scanner --list results/example.com/recon/live_hosts.txt --output results/example.com/scans
```

**What it does:** Tests for SSRF via OOB + response analysis.

### 4.6 — CORS Scan

```bash
python3 -m scanner.cors_scanner --list results/example.com/recon/live_hosts.txt --output results/example.com/scans
```

**What it does:** Detects CORS misconfigurations.

### 4.7 — Open Redirect Scan

```bash
python3 -m scanner.redirect_scanner --list results/example.com/recon/live_hosts.txt --output results/example.com/scans
```

**What it does:** Finds open redirect vulnerabilities.

### 4.8 — Sensitive Files Scan

```bash
python3 -m scanner.sensitive_files --list results/example.com/recon/live_hosts.txt --output results/example.com/scans
```

**What it does:** Checks for .env, .git, backups, config files.

### 4.9 — JS Analysis

```bash
python3 -m scanner.js_analysis --list results/example.com/recon/live_hosts.txt --output results/example.com/scans
```

**What it does:** Extracts endpoints + secrets from JavaScript.

### 4.10 — Content Discovery

```bash
python3 -m scanner.content_discovery --target https://example.com --output results/example.com/scans
```

**What it does:** Brute-forces directories/files via ffuf.

---

## 🧩 5. Advanced Module Commands

### 5.1 — Available Modules (48 Total)

**Run any module:**
```bash
python3 -m modules.<module_name> --target example.com --output results
```

### 5.2 — Auth Modules

```bash
python3 -m modules.jwt_attack --target example.com
python3 -m modules.oauth_test --target example.com
python3 -m modules.auth_bypass --target example.com
python3 -m modules.session_analysis --target example.com
```

### 5.3 — Cloud Modules

```bash
python3 -m modules.cloud_enum --target example.com
python3 -m modules.cloud_metadata --target example.com
python3 -m modules.aws_deep --target example.com
python3 -m modules.gcp_deep --target example.com
python3 -m modules.azure_deep --target example.com
python3 -m modules.docker_k8s_check --target example.com
```

### 5.4 — API Modules

```bash
python3 -m modules.graphql_test --target example.com
python3 -m modules.graphql_deep --target example.com
python3 -m modules.graphql_introspection --target example.com
python3 -m modules.open_api --target example.com
python3 -m modules.api_versioning --target example.com
```

### 5.5 — Injection Modules

```bash
python3 -m modules.ssti --target example.com
python3 -m modules.xxe --target example.com
python3 -m modules.nosql --target example.com
python3 -m modules.ldap_injection --target example.com
python3 -m modules.crlf_injection --target example.com
python3 -m modules.email_header --target example.com
python3 -m modules.deserialization --target example.com
```

### 5.6 — Protocol Modules

```bash
python3 -m modules.http2_smuggling --target example.com
python3 -m modules.http_desync --target example.com
python3 -m modules.cache_poison --target example.com
python3 -m modules.web_cache_deception --target example.com
```

### 5.7 — Client-Side Modules

```bash
python3 -m modules.prototype_pollution --target example.com
python3 -m modules.postmessage --target example.com
python3 -m modules.dom_clobbering --target example.com
python3 -m modules.css_injection --target example.com
python3 -m modules.dangling_markup --target example.com
python3 -m modules.csp_bypass --target example.com
python3 -m modules.xs_leaks --target example.com
```

### 5.8 — Infrastructure Modules

```bash
python3 -m modules.cname_takeover --target example.com
python3 -m modules.host_header --target example.com
python3 -m modules.rdns --target example.com
python3 -m modules.cdn_misconfig --target example.com
```

### 5.9 — WebSocket Modules

```bash
python3 -m modules.websocket_test --target example.com
python3 -m modules.websocket_smuggling --target example.com
python3 -m modules.grpc_test --target example.com
```

### 5.10 — Other Modules

```bash
python3 -m modules.sensitive_files --target example.com
python3 -m modules.bypass_403 --target example.com
python3 -m modules.diff_analysis --target example.com
python3 -m modules.race_condition --target example.com
python3 -m modules.business_logic --target example.com
python3 -m modules.custom_protocol --target example.com
python3 -m modules.browser_automation --target example.com
python3 -m modules.auto_dork --target example.com
python3 -m modules.nuclei_template_gen --target example.com
```

---

## 🤖 6. AI Engine Commands

### 6.1 — Check AI Status

```bash
python3 -m core.ai_engine_fast --status
```

**Expected output:**
```
Active: commandcode | model: command-r-plus
Total providers: 1
  - commandcode (command-r-plus)
```

### 6.2 — Test AI Prompt

```bash
python3 -m core.ai_engine_fast --prompt "Classify XSS as critical or high"
```

### 6.3 — Check Cache Stats

```bash
python3 -m core.ai_cache_layer --stats
```

**Expected output:**
```json
{
  "entries": 42,
  "total_hits": 156,
  "tokens_saved_est": 156000,
  "cost_saved_est_usd": 0.0234,
  "size_mb": 0.45
}
```

### 6.4 — Clear Cache

```bash
python3 -m core.ai_cache_layer --clear
```

### 6.5 — Cleanup Expired Cache

```bash
python3 -m core.ai_cache_layer --cleanup
```

### 6.6 — Test Cache

```bash
python3 -m core.ai_cache_layer --test
```

**What it does:** Runs 2 calls, 2nd should hit cache.

### 6.7 — Test Parallel AI

```bash
python3 -m core.ai_parallel --test 5 --workers 5
```

**What it does:** Sends 5 prompts in parallel.
**Expected:** `5/5 succeeded in 2.34s`

### 6.8 — Prove Findings from DB

```bash
python3 -m core.ai_proof --bulk-from-db
```

**What it does:** Auto-proves confirmed findings from SQLite.

### 6.9 — Prove Single Finding

```bash
python3 -m core.ai_proof --url "https://example.com/?q=test" --vuln xss --param q
```

### 6.10 — Triage a Finding

```bash
python3 -c "from core.ai_engine_fast import triage_finding; print(triage_finding({'url': 'https://example.com/?id=1', 'vuln_type': 'idor'}))"
```

### 6.11 — Check AI Hallucination

```bash
python3 -m core.ai_hallucination --text "Example finding with CVE-2021-44228"
```

### 6.12 — Detect External CLIs

```bash
python3 -m core.external_cli --detect
```

### 6.13 — Recommend CLI

```bash
python3 -m core.external_cli --recommend
```

### 6.14 — Full CLI Report

```bash
python3 -m core.external_cli --report
```

---

## 🧠 7. Intelligence Commands

### 7.1 — All Intel Sources

```bash
python3 -m intel.intel_merger --target example.com --output results
```

**What it does:** Runs Shodan + Censys + VirusTotal + SecurityTrails + NVD + GitHub + Chaos.

### 7.2 — NVD CVE Lookup

```bash
python3 -m intel.nvd_api --keyword "apache 2.4.49"
```

**Expected output:**
```json
[
  {"id": "CVE-2021-41773", "severity": "CRITICAL", ...}
]
```

### 7.3 — Shodan Lookup

```bash
python3 -m intel.shodan_api --ip 1.1.1.1
```

### 7.4 — Censys Lookup

```bash
python3 -m intel.censys_api --ip 1.1.1.1
```

### 7.5 — VirusTotal Subdomains

```bash
python3 -m intel.virustotal_api --domain example.com
```

### 7.6 — SecurityTrails

```bash
python3 -m intel.securitytrails_api --domain example.com
```

### 7.7 — ExploitDB Search

```bash
python3 -m intel.exploitdb "apache 2.4.49"
```

### 7.8 — GitHub Recon

```bash
python3 -m intel.github_recon --org example-org
```

### 7.9 — Intel Cache Stats

```bash
python3 -m intel.cache_manager --stats
```

---

## 🔫 8. Burp Suite Commands

### 8.1 — Check Burp MCP Status

```bash
python3 -m burp.burp_mcp_client --status
```

**Expected output:**
```json
{
  "enabled": true,
  "host": "127.0.0.1",
  "port": 9876,
  "reachable": true,
  "mode": "mcp"
}
```

### 8.2 — Scan URL via Burp

```bash
python3 -m burp.burp_mcp_client --scan "https://example.com/api/user?id=1"
```

### 8.3 — Get Collaborator Payload

```bash
python3 -m burp.collaborator --get-payload
```

**Expected output:**
```json
{"ok": true, "source": "interactsh", "payload": "abc123.oast.fun"}
```

### 8.4 — Poll Collaborator

```bash
python3 -m burp.collaborator --poll
```

### 8.5 — Auto Fallback Diagnostics

```bash
python3 -m core.auto_fallback --diagnose
```

---

## 📝 9. Report Generation Commands

### 9.1 — Generate All Reports

```bash
python3 -m reporting.report --target example.com --scan-id 1
```

**What it does:** Generates HackerOne reports for all findings.

**With severity filter:**
```bash
python3 -m reporting.report --target example.com --scan-id 1 --severity critical,high
```

**Without AI polish:**
```bash
python3 -m reporting.report --target example.com --scan-id 1 --no-ai
```

### 9.2 — List Reports

```bash
ls results/example.com/reports/
```

### 9.3 — View a Report

```bash
cat results/example.com/reports/001_xss_high.md
```

### 9.4 — Review Critical Findings

```bash
python3 -m core.ai_checkpoint --list
```

### 9.5 — Approve Critical

```bash
python3 -m core.ai_checkpoint --approve crit_1234567890_0
```

### 9.6 — Verify Reports

```bash
python3 -m core.human_verification --list
```

### 9.7 — Check Verification Status

```bash
python3 -m core.human_verification --verified
```

---

## 📊 10. Monitoring Commands

### 10.1 — One-Time CT Check

```bash
python3 -m monitoring.ct_monitor --target example.com --once
```

**What it does:** Checks Certificate Transparency logs for new subdomains.

### 10.2 — Continuous CT Monitoring

```bash
python3 -m monitoring.ct_monitor --target example.com --interval 60
```

**Interval:** Minutes between checks (60 = every hour).

### 10.3 — Subdomain Monitoring

```bash
python3 -m monitoring.monitor --target example.com --interval 6
```

**Interval:** Hours between checks.

### 10.4 — Test Notifications

```bash
python3 -m monitoring.alerts --test
```

### 10.5 — Monitor Once

```bash
python3 -m monitoring.monitor --target example.com --once
```

---

## 🖥️ 11. External CLI Commands

### 11.1 — Install OpenCode (Free)

```bash
curl -fsSL https://opencode.ai/install | bash
```

### 11.2 — Add OpenCode to PATH

```bash
export PATH="$HOME/.opencode/bin:$PATH"
echo 'export PATH="$HOME/.opencode/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### 11.3 — Login to OpenCode

```bash
opencode auth login
```

Select **"Free"** provider.

### 11.4 — Start OpenCode in Framework

```bash
cd ~/BugHunting-with-ai-
opencode
```

Then in OpenCode:
```
Read AGENTS.md. Then run: python3 -m core.core --target example.com --recon-only. Analyze results and suggest next steps.
```

### 11.5 — Install Claude Code (Paid)

```bash
npm install -g @anthropic-ai/claude-code
```

### 11.6 — Install Aider (Free BYOK)

```bash
pip install aider-chat
```

### 11.7 — Install Goose (Free BYOK)

```bash
pip install goose-ai
```

### 11.8 — Detect All CLIs

```bash
python3 -m core.external_cli --detect
```

### 11.9 — Suggest Commands for Target

```bash
python3 -m core.external_cli --suggest example.com
```

---

## 🛠️ 12. Utility Commands

### 12.1 — Diagnose System

```bash
bash scripts/diagnose.sh
```

**What it does:** Full health check (tools, API keys, config).

### 12.2 — Create Snapshot

```bash
bash scripts/snapshot.sh create before_scan
```

**What it does:** Backs up config + database + results.

### 12.3 — List Snapshots

```bash
bash scripts/snapshot.sh list
```

### 12.4 — Restore Snapshot

```bash
bash scripts/snapshot.sh restore before_scan
```

### 12.5 — Update SecLists

```bash
bash scripts/update_seclists.sh
```

**What it does:** Downloads latest wordlists.

### 12.6 — Check Tool Status

```bash
python3 -m core.tool_checker --list
```

### 12.7 — List Missing Tools

```bash
python3 -m core.tool_checker --missing
```

### 12.8 — View Database

```bash
sqlite3 bug_bounty.db "SELECT * FROM findings WHERE severity='critical'"
```

### 12.9 — Count Findings

```bash
sqlite3 bug_bounty.db "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
```

### 12.10 — View Recent Scans

```bash
sqlite3 bug_bounty.db "SELECT * FROM scans ORDER BY id DESC LIMIT 10"
```

### 12.11 — Check Time Budget

```bash
python3 -m core.time_budget --test
```

### 12.12 — Platform Info

```bash
python3 -m core.platform_detect
```

---

## 🚨 13. Troubleshooting Commands

### 13.1 — Fix PATH (Go tools)

```bash
export PATH="$PATH:$HOME/go/bin"
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### 13.2 — Update Nuclei Templates

```bash
nuclei -update-templates
```

### 13.3 — Test Python Import

```bash
python3 -c "from core.core import full_pipeline; print('OK')"
```

### 13.4 — Test All Modules Import

```bash
python3 -c "
from core.ai_engine_fast import ask_ai
from core.ai_cache_layer import get_cache
from core.ai_parallel import parallel_ai_calls
from core.external_cli import detect_installed
print('All fast modules OK')
"
```

### 13.5 — Check Python Version

```bash
python3 --version
```

**Should be:** 3.10 or higher.

### 13.6 — Check Disk Space

```bash
df -h .
```

### 13.7 — Clear Python Cache

```bash
find . -type d -name __pycache__ -exec rm -rf {} +
```

### 13.8 — Kill Stuck Scans

```bash
pkill -f "python3 -m core"
```

### 13.9 — View Recent Errors

```bash
tail -50 logs/errors.log
```

### 13.10 — Reset Database (⚠️ Danger!)

```bash
rm bug_bounty.db
```

**Warning:** This deletes all findings. Backup first.

### 13.11 — Verify GitHub Sync

```bash
git status
git log --oneline -5
```

### 13.12 — Pull Latest Changes

```bash
git pull --no-edit
```

### 13.13 — Force Reset to Remote

```bash
git fetch --all
git reset --hard origin/main
```

**Warning:** This discards local changes.

---

## 🎯 Common Workflows

### Workflow 1: Quick Recon of New Target

```bash
# 1. Recon only
python3 -m core.core --target newtarget.com --recon-only

# 2. View results
cat results/newtarget.com/recon/subdomains.txt
cat results/newtarget.com/recon/live_hosts.txt
cat results/newtarget.com/recon/tech_stack.json
```

### Workflow 2: Full Scan of Bug Bounty Target

```bash
# 1. Full pipeline
python3 -m core.core --target target.com --full

# 2. Review critical findings
python3 -m core.core --review

# 3. Verify reports
python3 -m core.core --review-verify

# 4. Submit approved reports to HackerOne
cat results/target.com/reports/001_*.md
```

### Workflow 3: Just Find Subdomains

```bash
python3 -m recon.subdomain_enum --domain example.com --output results/example.com/recon
```

### Workflow 4: Monitor for New Subdomains

```bash
# Run in background
nohup python3 -m monitoring.ct_monitor --target example.com --interval 60 &
```

### Workflow 5: Test Specific Vulnerability

```bash
# Only run JWT + SSTI + XXE modules
python3 -m core.core --target example.com --modules jwt_attack,ssti,xxe
```

### Workflow 6: Check AI Costs

```bash
python3 -m core.ai_cache_layer --stats
```

---

## 📊 Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error (check logs) |
| 130 | Interrupted (Ctrl+C) |

---

## 🔑 Global Flags (Available in Most Commands)

| Flag | Description |
|---|---|
| `-t, --target` | Target domain or URL |
| `-o, --output` | Output directory (default: `results`) |
| `--no-db` | Skip database writes |
| `--dry-run` | Show what would happen (no execution) |
| `-h, --help` | Show help |

---

## 📞 Getting Help

For any command, add `--help`:

```bash
python3 -m core.core --help
python3 -m modules.jwt_attack --help
python3 -m recon.recon --help
```

---

## 📌 Quick Reference Card

```bash
# ━━━ SETUP (once) ━━━
bash setup.sh
pip3 install -r requirements.txt --break-system-packages
pip3 install aiohttp --break-system-packages

# ━━━ DAILY ━━━
python3 -m core.core --target <domain> --full         # Full scan
python3 -m core.core --target <domain> --recon-only   # Quick recon
python3 -m core.core --review                         # Review critical
python3 -m core.core --review-verify                  # Verify reports

# ━━━ UTILITY ━━━
bash scripts/diagnose.sh                              # Health check
python3 -m core.tool_checker --missing                # Missing tools
python3 -m core.ai_engine_fast --status               # AI status
python3 -m core.ai_cache_layer --stats                # Cache stats

# ━━━ EXTERNAL CLI ━━━
opencode                                              # Start OpenCode
python3 -m core.external_cli --detect                 # Detect CLIs

# ━━━ FIXES ━━━
export PATH="$PATH:$HOME/go/bin"                      # Fix PATH
nuclei -update-templates                              # Update templates
pkill -f "python3 -m core"                            # Kill stuck scans
```

---

**That's the complete command reference.**

**Last updated:** 2026-10-05 | **Version:** 2.0.0