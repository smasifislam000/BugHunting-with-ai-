# 🎯 Dream Framework

**AI-powered Bug Bounty Hunting Framework** — built for serious hunters.

![Status](https://img.shields.io/badge/status-production--ready-brightgreen)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Modules](https://img.shields.io/badge/modules-48-orange)
![Files](https://img.shields.io/badge/files-140-lightgrey)

---

## 📖 Table of Contents

- [What is This?](#-what-is-this)
- [Key Features](#-key-features)
- [Quick Start](#-quick-start)
- [Installation (Step-by-Step)](#-installation-step-by-step)
- [Configuration](#-configuration)
- [Common Commands](#-common-commands)
- [Directory Structure](#-directory-structure)
- [AI Modes](#-ai-modes)
- [External CLI Mode](#-external-cli-mode)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)
- [Legal Notice](#-legal-notice)

---

## 🎯 What is This?

Dream Framework is a **modular, AI-powered bug bounty hunting framework**.
It chains reconnaissance, scanning, exploitation, and reporting into a
single automated pipeline while keeping **human-in-the-loop** for
critical decisions.

**Who is this for?**
- Bug bounty hunters (beginner to advanced)
- Security researchers
- Penetration testers
- Anyone doing authorized security testing

**Key Stats:**
- 📁 140 Python files
- 🧩 48 vulnerability modules
- 🤖 4 AI providers supported
- ⚡ Parallel AI calls (5-10x faster)
- 💾 Semantic cache (60-80% token savings)

---

## ✨ Key Features

### 🔍 Reconnaissance
- Multi-source subdomain enumeration (7 sources: subfinder, amass, chaos, github, assetfinder, crt.sh, findomain)
- DNS permutation and resolution
- ASN discovery via whois
- Tech stack fingerprinting
- Subdomain takeover detection

### 🎯 Scanning
- **Nuclei** — all templates, filtered by severity
- **XSS** — Dalfox + Kxss (reflected, stored, DOM, blind)
- **SQLi** — SQLmap with smart filtering
- **SSRF** — OOB + response analysis
- **CORS** — misconfiguration detection
- **Open Redirect** — Location header analysis
- **Sensitive Files** — .env, .git, backups, config
- **JS Analysis** — LinkFinder + SecretFinder
- **API Fuzzing** — Kiterunner-style
- **Content Discovery** — ffuf + dirsearch

### 🧩 Advanced Modules (48 total)

| Category | Modules |
|---|---|
| **Auth** | jwt_attack, oauth_test, auth_bypass, session_analysis |
| **Cloud** | cloud_enum, cloud_metadata, aws_deep, gcp_deep, azure_deep, docker_k8s_check |
| **API** | graphql_test, graphql_deep, graphql_introspection, open_api, api_versioning |
| **Infra** | cname_takeover, host_header, rdns, cdn_misconfig |
| **Injection** | ssti, xxe, nosql, ldap_injection, crlf_injection, email_header, deserialization |
| **Protocol** | http2_smuggling, http_desync, cache_poison, web_cache_deception |
| **Client** | prototype_pollution, postmessage, dom_clobbering, css_injection, dangling_markup, csp_bypass, xs_leaks |
| **WebSocket** | websocket_test, websocket_smuggling, grpc_test |
| **Other** | sensitive_files, bypass_403, diff_analysis, race_condition, business_logic, custom_protocol, browser_automation |
| **Generators** | auto_dork, nuclei_template_gen |

### 🤖 AI Integration
- **Multi-provider** — CommandCode, DeepSeek, OpenAI, Anthropic
- **Semantic caching** — 60-80% token savings
- **Parallel calls** — 5-10x speedup
- **Chain-of-Thought** — better accuracy
- **Few-Shot examples** — context-aware prompts
- **Hallucination detection** — verify AI output
- **RAG** — retrieval-augmented generation
- **Feedback loop** — learns from your decisions
- **Uncertainty quantification** — confidence scoring

### 📝 Reporting
- **HackerOne** format
- **Bugcrowd** format
- **CVSS 3.1** scoring
- **PoC generator** — curl + Python
- **Triager-friendly** markdown
- **Video evidence** (Playwright)
- **Auto AI-disclosure** — compliant with platforms

### 🛡️ Safety
- Per-host rate limiting
- IP rotation (proxy support)
- **Critical checkpoint** — human approval
- **Human verification** before submit

### 🖥️ External CLI Support
- **OpenCode** (free, 75+ providers)
- **Claude Code**
- **Aider** (BYOK)
- **Goose** (BYOK)
- **Cursor**

---

## 🚀 Quick Start

**If you're in a hurry:**

```bash
git clone https://github.com/YOUR_USERNAME/BugHunting-with-ai-.git
cd BugHunting-with-ai-
bash setup.sh
pip3 install -r requirements.txt --break-system-packages
pip3 install aiohttp --break-system-packages
# Edit config.json with your API key
python3 -m core.core --target example.com --recon-only
```

**That's it!** First scan is running.

---

## 🛠️ Installation (Step-by-Step)

### Step 1: Choose Your Environment

| OS | Recommended | Notes |
|---|---|---|
| Kali Linux | ✅ Best | All tools preinstalled |
| Ubuntu 22.04 | ✅ Good | Some tools manual |
| Termux (Android) | ⚠️ Limited | For testing only |
| WSL2 | ✅ Good | Windows users |
| macOS | ⚠️ Limited | Many tools missing |

### Step 2: Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/BugHunting-with-ai-.git
cd BugHunting-with-ai-
```

### Step 3: Run Setup Script

```bash
chmod +x setup.sh
bash setup.sh
```

This installs:
- Subfinder, httpx, nuclei, katana, dnsx, naabu
- Interactsh-client, ffuf, dalfox, gau, waybackurls
- Anew, qsreplace, assetfinder, gf, puredns
- Arjun, uro, dirsearch
- Nuclei templates

**Time:** ~15 minutes

### Step 4: Install Python Dependencies

```bash
pip3 install -r requirements.txt --break-system-packages
pip3 install aiohttp --break-system-packages
```

**Optional (for advanced features):**

```bash
pip3 install playwright --break-system-packages
python3 -m playwright install chromium
```

### Step 5: Configure API Keys

Edit `config.json`:

```bash
nano config.json
```

**Required:** At least one AI provider key:
- CommandCode: `https://commandcode.ai`
- DeepSeek: `https://platform.deepseek.com`
- OpenAI: `https://platform.openai.com`
- Anthropic: `https://console.anthropic.com`

**Optional:** Intel API keys (free tiers available):
- Shodan: `https://account.shodan.io`
- Censys: `https://search.censys.io`
- VirusTotal: `https://www.virustotal.com`
- SecurityTrails: `https://securitytrails.com`
- Chaos: `https://chaos.projectdiscovery.io`
- GitHub Token: `https://github.com/settings/tokens`
- NVD: `https://nvd.nist.gov/developers/request-an-api-key`

### Step 6: Verify Installation

```bash
bash scripts/diagnose.sh
```

Expected output: All tools show ✅

### Step 7: First Test Scan

```bash
python3 -m core.core --target example.com --recon-only
```

This scans `example.com` (IANA-managed, safe for testing).

---

## ⚙️ Configuration

All settings are in `config.json`. Here's a quick reference:

### System Settings

```json
{
  "system": {
    "version": "2.0.0",
    "results_dir": "results",
    "logs_dir": "logs",
    "database": "bug_bounty.db"
  }
}
```

### AI Provider Setup

```json
{
  "ai_driver": {
    "internal_ai_optional": {
      "enabled": true,
      "provider": "commandcode",
      "providers": {
        "commandcode": {
          "api_key": "sk-your-key",
          "model": "command-r-plus"
        },
        "deepseek": {
          "api_key": "sk-your-key",
          "model": "deepseek-chat"
        }
      }
    }
  }
}
```

### Scan Settings

```json
{
  "scan_settings": {
    "max_concurrent": 20,
    "nuclei_rate_limit": 70,
    "nuclei_severity": ["critical", "high", "medium"],
    "httpx_threads": 50,
    "request_timeout": 10
  }
}
```

### AI Performance

```json
{
  "ai_performance": {
    "use_fast_engine": true,
    "enable_cache": true,
    "enable_parallel": true,
    "max_parallel_calls": 5,
    "enable_cot": true,
    "enable_few_shot": true,
    "token_budget_per_scan": 100000
  }
}
```

### Safety

```json
{
  "safety": {
    "respect_scope": true,
    "rate_limit_per_host": 30,
    "max_requests_per_host": 10000
  }
}
```

---

## 📋 Common Commands

### Full Pipeline

```bash
# Complete automated scan
python3 -m core.core --target target.com --full
```

### Recon Only (Fast)

```bash
# Subdomains + live hosts only
python3 -m core.core --target target.com --recon-only
```

### Specific Modules

```bash
# Only JWT + SSTI + XXE
python3 -m core.core --target target.com --modules jwt_attack,ssti,xxe
```

### Review Critical Findings

```bash
# Interactive approval of Critical findings
python3 -m core.core --review
```

### Verify Pending Reports

```bash
# Interactive verification of generated reports
python3 -m core.core --review-verify
```

### Single Module Test

```bash
python3 -m modules.jwt_attack --target target.com
python3 -m modules.ssti --target target.com
python3 -m modules.graphql_test --target target.com
```

### AI Status

```bash
# Check which AI provider is active
python3 -m core.ai_engine_fast --status

# Check cache stats
python3 -m core.ai_cache_layer --stats

# Check external CLI detection
python3 -m core.external_cli --detect
```

### Continuous Monitoring

```bash
# Monitor for new subdomains every 6 hours
python3 -m monitoring.monitor --target target.com --interval 6
```

---

## 📁 Directory Structure

```
BugHunting-with-ai-/
├── config.json                    # Settings (edit this!)
├── requirements.txt               # Python dependencies
├── setup.sh                       # Installer
├── AGENTS.md                      # AI agent instructions
├── README.md                      # This file
│
├── core/                          # Core framework
│   ├── core.py                    # Main orchestrator
│   ├── ai_engine.py               # Original AI engine
│   ├── ai_engine_fast.py          # Superfast engine
│   ├── ai_cache_layer.py          # Semantic cache
│   ├── ai_parallel.py             # Parallel calls
│   ├── external_cli.py            # External CLI bridge
│   ├── ai_proof.py                # Auto-proof findings
│   ├── ai_router.py               # Smart model routing
│   ├── ai_rag.py                  # Knowledge base
│   ├── ai_hallucination.py        # Fact checker
│   ├── ai_checkpoint.py           # Critical queue
│   ├── human_verification.py      # Manual approval
│   ├── ai_disclosure.py           # AI usage disclosure
│   ├── ai_feedback.py             # Learning loop
│   ├── poc_enhancer.py            # Triager-friendly PoC
│   ├── database.py                # SQLite
│   ├── logger.py                  # Logging
│   ├── config_loader.py           # Config reader
│   ├── utils.py                   # Helpers
│   └── ...                        # More utilities
│
├── recon/                         # Reconnaissance
│   ├── recon.py                   # Orchestrator
│   ├── subdomain_enum.py          # Subdomain enum
│   ├── live_hosts.py              # httpx
│   ├── dns_resolve.py             # DNS
│   ├── tech_detect.py             # Tech fingerprint
│   ├── asn_discovery.py           # ASN
│   ├── cname_takeover.py          # Takeover detection
│   └── parameter_discovery.py     # Hidden params
│
├── scanner/                       # Vulnerability scanners
│   ├── scanner.py                 # Orchestrator
│   ├── nuclei_runner.py           # Nuclei
│   ├── xss_scanner.py             # XSS
│   ├── sqli_scanner.py            # SQLi
│   ├── ssrf_scanner.py            # SSRF
│   ├── cors_scanner.py            # CORS
│   ├── redirect_scanner.py        # Open redirect
│   ├── sensitive_files.py         # Sensitive files
│   ├── js_analysis.py             # JS analysis
│   ├── api_fuzzing.py             # API fuzzing
│   └── content_discovery.py       # Content discovery
│
├── modules/                       # 48 advanced modules
│   ├── jwt_attack.py
│   ├── oauth_test.py
│   ├── graphql_test.py
│   ├── ssti.py
│   ├── xxe.py
│   ├── ... (45 more)
│
├── intel/                         # Intelligence APIs
│   ├── shodan_api.py
│   ├── censys_api.py
│   ├── virustotal_api.py
│   ├── securitytrails_api.py
│   ├── nvd_api.py
│   ├── exploitdb.py
│   ├── github_recon.py
│   └── intel_merger.py
│
├── burp/                          # Burp Suite Pro
│   ├── burp_mcp_client.py         # MCP client
│   ├── burp_extension.py          # Jython extension
│   ├── collaborator.py            # OOB detection
│   └── match_replace.yaml         # WAF bypass
│
├── reporting/                     # Reports
│   ├── report.py                  # Generator
│   ├── cvss_calculator.py         # CVSS
│   └── poc_generator.py           # PoC
│
├── monitoring/                    # Continuous monitoring
│   ├── monitor.py                 # Subdomain monitor
│   ├── ct_monitor.py              # Cert transparency
│   ├── alerts.py                  # Alerts
│   └── notifier.py                # Discord/Telegram
│
├── payloads/                      # Attack payloads
│   ├── xss.txt
│   ├── sqli.txt
│   ├── ssrf.txt
│   ├── ssti.txt
│   ├── xxe.txt
│   └── ... (7 more)
│
├── wordlists/                     # Wordlists
│   ├── common.txt
│   ├── api_endpoints.txt
│   ├── parameters.txt
│   └── ... (3 more)
│
├── scripts/                       # Utility scripts
│   ├── diagnose.sh                # Health check
│   ├── snapshot.sh                # Backup
│   └── update_seclists.sh         # Wordlists
│
├── results/                       # Scan outputs
│   └── <domain>/
│       ├── recon/                 # Subdomains, live hosts
│       ├── scans/                 # Nuclei, XSS, SQLi
│       ├── modules/               # Per-module output
│       ├── proofs/                # Evidence bundles
│       └── reports/               # Final reports
│
└── logs/                          # Log files
    ├── core_YYYYMMDD.log
    ├── scanner_YYYYMMDD.log
    └── errors.log
```

---

## 🤖 AI Modes

Three modes control when AI stops for manual approval:

### Auto Mode (Default)

```json
{ "ai_mode": { "default": "auto" } }
```

| Severity | Action |
|---|---|
| Info | auto (silent) |
| Low | auto (silent) |
| Medium | auto + notify |
| High | auto + notify |
| **Critical** | **Manual approval required** |

**Best for:** Beginners, fast scans, low-risk targets.

### Hybrid Mode

```json
{ "ai_mode": { "default": "hybrid" } }
```

| Severity | Action |
|---|---|
| Info | auto |
| Low | auto |
| Medium | auto + notify |
| **High** | **Manual approval** |
| **Critical** | **Manual approval** |

**Best for:** Experienced hunters, high-value targets.

### Checkpoint Mode

```json
{ "ai_mode": { "default": "checkpoint" } }
```

| Severity | Action |
|---|---|
| Info | auto |
| **Low** | **Manual approval** |
| **Medium** | **Manual approval** |
| **High** | **Manual approval** |
| **Critical** | **Manual approval** |

**Best for:** Learning, careful analysis, high-stakes programs.

---

## 🖥️ External CLI Mode

Drive the framework from an AI CLI (OpenCode, Claude Code, Aider, Goose).

### Why Use External CLI?

| Feature | Internal AI | External CLI |
|---|---|---|
| Speed | Fast | Depends on CLI |
| Cost | API-based | Free tiers available |
| Autonomy | Limited | Full |
| Token usage | Low | High |
| Best for | Batch scans | Complex chains |

### Install OpenCode (Free)

```bash
curl -fsSL https://opencode.ai/install | bash
export PATH="$HOME/.opencode/bin:$PATH"
echo 'export PATH="$HOME/.opencode/bin:$PATH"' >> ~/.bashrc
opencode auth login   # select "Free"
```

### Use OpenCode

```bash
cd ~/BugHunting-with-ai-
opencode
```

Then type:

```
Read AGENTS.md first. Then run: python3 -m core.core --target example.com --recon-only. Analyze results.
```

### Detect Installed CLIs

```bash
python3 -m core.external_cli --detect
python3 -m core.external_cli --recommend
python3 -m core.external_cli --report
```

---

## 🔧 Troubleshooting

### Problem: "command not found: nuclei"

**Solution:**

```bash
export PATH="$PATH:$HOME/go/bin"
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Problem: "pip3: externally-managed-environment"

**Solution:**

```bash
pip3 install <package> --break-system-packages
```

### Problem: Nuclei templates missing

**Solution:**

```bash
nuclei -update-templates
```

### Problem: "database is locked"

**Solution:**

```bash
# Close all other scans
pkill -f "python3 -m core"

# Then retry
python3 -m core.core --target example.com --full
```

### Problem: IP blocked during scan

**Solution:**

Edit `config.json`:

```json
{
  "safety": {
    "rate_limit_per_host": 10,
    "max_requests_per_host": 1000
  }
}
```

### Problem: AI returns invalid JSON

**Solution:**

The fast engine (ai_engine_fast.py) handles this automatically with:
- JSON extraction from text
- Retry with exponential backoff
- Multi-provider fallback

If still failing, check `config.json` for correct API key.

### Problem: Python version mismatch

**Solution:**

```bash
python3 --version    # Should be 3.10+
```

If older, install a newer Python.

### Problem: Too many false positives

**Solution:**

1. Enable Chain-of-Thought: `ai_performance.enable_cot: true`
2. Use self-critique: `--self-critique` flag
3. Enable cache (reduces variation): `ai_performance.enable_cache: true`

### Problem: Burp MCP not reachable

**Solution:**

1. Start Burp Suite Pro
2. Install MCP plugin
3. Check `config.json`:
```json
{
  "burp": {
    "mcp_host": "127.0.0.1",
    "mcp_port": 9876
  }
}
```

### Problem: Scan takes too long

**Solution:**

Use time budget:

```bash
# Already configured in config.json
# Adjust in ai_performance.token_budget_per_scan
```

Or run recon-only first:

```bash
python3 -m core.core --target example.com --recon-only
```

---

## ❓ FAQ

### Q: Do I need all API keys?

**A:** No. Required: at least one AI provider (CommandCode/DeepSeek/OpenAI/Anthropic). Everything else is optional — the framework skips modules that need missing keys.

### Q: How much does it cost?

**A:** Depends on your AI provider:
- CommandCode: ~$0.001 per scan (variable)
- DeepSeek: ~$0.0001 per scan (very cheap)
- OpenAI GPT-4: ~$0.05 per scan
- Anthropic Claude: ~$0.10 per scan

With cache enabled: 60-80% cheaper.

### Q: How long does a scan take?

**A:** Depends on target size:
- Small site (10 hosts): ~10 minutes
- Medium site (100 hosts): ~1 hour
- Large site (1000+ hosts): 3+ hours

Use `--recon-only` for fast initial run.

### Q: Can I use this on any target?

**A:** **Only authorized targets:**
- Bug bounty programs (in-scope)
- Your own assets
- Systems with explicit permission

**Never use on unauthorized targets.** It's illegal.

### Q: How do I add a new module?

**A:** See `AGENTS.md` — it has details on framework architecture.

### Q: Can I run multiple scans in parallel?

**A:** Yes, but be careful:
```bash
python3 -m core.core --target site1.com --full &
python3 -m core.core --target site2.com --full &
wait
```

The framework has rate limiting per host to avoid issues.

### Q: Does it work on Windows?

**A:** Via WSL2 (recommended) or Git Bash. Native Windows has limited tool support.

### Q: How do I update?

**A:**
```bash
cd ~/BugHunting-with-ai-
git pull
pip3 install -r requirements.txt --break-system-packages
```

### Q: What if a scan fails halfway?

**A:** The framework handles this:
- Each module is isolated
- Failures logged to `logs/`
- Partial results saved to database

Check `logs/errors.log` for details.

### Q: Can I use my own wordlists?

**A:** Yes. Put them in `wordlists/` and update module config, or pass `--wordlist /path/to/list`.

### Q: Does AI scan for me?

**A:** AI handles ~70% (recon, triage, reports). You handle ~30% (business logic, chaining, final verification). It's a **force multiplier**, not a replacement.

### Q: Is this legal?

**A:** Only on authorized targets. See [Legal Notice](#-legal-notice).

### Q: Where do I get help?

1. Check `logs/errors.log`
2. Run `bash scripts/diagnose.sh`
3. Check `AGENTS.md`
4. Open an issue on GitHub

---

## ⚖️ Legal Notice

**This tool is for authorized security testing only.**

✅ **Allowed:**
- Bug bounty programs (respecting scope)
- Your own assets
- Systems with explicit written permission

❌ **Not allowed:**
- Unauthorized testing (illegal in most countries)
- Attacking production systems without permission
- Using on government/military targets
- Any use that violates program rules

**You are responsible for your actions.** The authors of this framework
assume no liability for misuse.

**Always:**
- Read the program's scope
- Respect rate limits
- Test responsibly
- Report ethically

---

## 📝 License

MIT License — see [LICENSE](LICENSE) file.

---

## 🙏 Credits

Built with:
- [ProjectDiscovery](https://projectdiscovery.io) — subfinder, httpx, nuclei, katana, dnsx, naabu
- [TomNomNom](https://github.com/tomnomnom) — waybackurls, anew, qsreplace, assetfinder
- [Hahwul](https://github.com/hahwul) — dalfox
- [ffuf](https://github.com/ffuf/ffuf) — fuzzing
- [SQLMap](https://sqlmap.org) — SQL injection
- [OWASP](https://owasp.org) — references
- And all other open-source maintainers

---

## 📞 Support

- 🐛 **Bugs:** [Open an issue](https://github.com/YOUR_USERNAME/BugHunting-with-ai-/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/YOUR_USERNAME/BugHunting-with-ai-/discussions)
- 📖 **Docs:** See `AGENTS.md`

---

## 🌟 Star History

If this framework helps you find bounties, please ⭐ the repo!

---

## 🚀 Final Words

**Remember:** Code is a force multiplier, not a replacement for skill.

- AI finds ~70% of bugs
- You find ~30% (business logic, chaining, creativity)

**Happy hunting!** 🎯

---

*Last updated: 2026-10-05 | Version 2.0.0*