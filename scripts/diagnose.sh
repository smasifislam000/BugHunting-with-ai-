#!/bin/bash
# ============================================================
# Dream Framework - Diagnostic Script
# ============================================================
# Usage:
#   chmod +x scripts/diagnose.sh
#   ./scripts/diagnose.sh
# ============================================================

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }
head() { echo -e "\n${BLUE}═══════════ $1 ═══════════${NC}"; }

REPORT="diagnose_report.txt"
> "$REPORT"

# ─────────────────────────────────────────────
head "1. System Information"
# ─────────────────────────────────────────────
OS=$(uname -s)
KERNEL=$(uname -r)
ARCH=$(uname -m)
PY=$(python3 --version 2>/dev/null || echo "NOT FOUND")
GO=$(go version 2>/dev/null || echo "NOT FOUND")
GIT=$(git --version 2>/dev/null || echo "NOT FOUND")

echo "OS:      $OS" | tee -a "$REPORT"
echo "Kernel:  $KERNEL" | tee -a "$REPORT"
echo "Arch:    $ARCH" | tee -a "$REPORT"
echo "Python:  $PY" | tee -a "$REPORT"
echo "Go:      $GO" | tee -a "$REPORT"
echo "Git:     $GIT" | tee -a "$REPORT"

# ─────────────────────────────────────────────
head "2. Python Libraries"
# ─────────────────────────────────────────────
PY_LIBS=("requests" "urllib3" "aiohttp" "sqlite3" "yaml" "json")
for lib in "${PY_LIBS[@]}"; do
  if python3 -c "import $lib" 2>/dev/null; then
    ok "python: $lib"
    echo "python: $lib OK" >> "$REPORT"
  else
    fail "python: $lib MISSING"
    echo "python: $lib MISSING" >> "$REPORT"
  fi
done

# Optional libs
OPT_LIBS=("shodan" "censys" "vt" "playwright" "h2")
for lib in "${OPT_LIBS[@]}"; do
  if python3 -c "import $lib" 2>/dev/null; then
    ok "python-opt: $lib"
  else
    warn "python-opt: $lib (optional, missing)"
  fi
done

# ─────────────────────────────────────────────
head "3. Go-Based Tools"
# ─────────────────────────────────────────────
GO_TOOLS=(
  subfinder httpx nuclei katana dnsx naabu
  interactsh-client ffuf dalfox gau waybackurls
  anew qsreplace assetfinder gf puredns dnsgen subzy kxss
)
MISSING=0
for tool in "${GO_TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool: $(command -v $tool)"
    echo "$tool OK" >> "$REPORT"
  else
    fail "$tool: MISSING"
    echo "$tool MISSING" >> "$REPORT"
    MISSING=$((MISSING+1))
  fi
done
info "Total missing Go tools: $MISSING"

# ─────────────────────────────────────────────
head "4. Python-Based Tools"
# ─────────────────────────────────────────────
PY_TOOLS=(arjun uro dirsearch paramspider sqlmap)
for tool in "${PY_TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool"
  else
    warn "$tool: MISSING"
  fi
done

# ─────────────────────────────────────────────
head "5. Nuclei Templates"
# ─────────────────────────────────────────────
if command -v nuclei >/dev/null 2>&1; then
  TPL_DIR="$HOME/nuclei-templates"
  if [ -d "$TPL_DIR" ]; then
    COUNT=$(find "$TPL_DIR" -name "*.yaml" 2>/dev/null | wc -l)
    ok "Nuclei templates: $COUNT files"
  else
    fail "Nuclei templates directory not found"
    warn "Run: nuclei -update-templates"
  fi
else
  fail "nuclei not installed"
fi

# ─────────────────────────────────────────────
head "6. Config File"
# ─────────────────────────────────────────────
if [ -f "config.json" ]; then
  ok "config.json found"
  python3 - <<'PYEOF'
import json
try:
    with open("config.json") as f:
        cfg = json.load(f)
    keys = cfg.get("api_keys", {})
    present = [k for k, v in keys.items() if v]
    missing = [k for k, v in keys.items() if not v]
    print(f"  API keys present: {', '.join(present) or 'none'}")
    print(f"  API keys empty:   {', '.join(missing) or 'none'}")
except Exception as e:
    print(f"  config.json error: {e}")
PYEOF
else
  fail "config.json not found"
fi

# ─────────────────────────────────────────────
head "7. Database"
# ─────────────────────────────────────────────
if [ -f "bug_bounty.db" ]; then
  SIZE=$(du -h bug_bounty.db | cut -f1)
  ok "bug_bounty.db ($SIZE)"
else
  info "bug_bounty.db not created yet (will be on first run)"
fi

# ─────────────────────────────────────────────
head "8. Network Connectivity"
# ─────────────────────────────────────────────
for url in "https://api.github.com" "https://api.deepseek.com" "https://hackerone.com"; do
  if curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" | grep -qE "200|30[0-9]|40[0-9]"; then
    ok "reachable: $url"
  else
    warn "unreachable: $url"
  fi
done

# ─────────────────────────────────────────────
head "9. Burp Suite Detection"
# ─────────────────────────────────────────────
if pgrep -fi burp >/dev/null 2>&1; then
  ok "Burp Suite is running"
else
  warn "Burp Suite not running (needed for MCP integration)"
fi

# Check MCP port
if command -v nc >/dev/null 2>&1; then
  if nc -z 127.0.0.1 9876 2>/dev/null; then
    ok "Burp MCP server listening on 9876"
  else
    info "Burp MCP server not detected on 9876 (may be on other port)"
  fi
fi

# ─────────────────────────────────────────────
head "10. Disk Space"
# ─────────────────────────────────────────────
df -h . | tail -n 1

# ─────────────────────────────────────────────
head "11. Summary"
# ─────────────────────────────────────────────
echo ""
if [ "$MISSING" -eq 0 ]; then
  ok "All required Go tools present"
else
  warn "$MISSING Go tools missing — install via setup.sh"
fi

echo ""
info "Full report saved to: $REPORT"
echo ""
echo -e "${BLUE}═══════════════════════════════════════${NC}"