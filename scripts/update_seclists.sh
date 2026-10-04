#!/bin/bash
# ============================================================
# Dream Framework - SecLists Auto-Update
# ============================================================
# Usage:
#   chmod +x scripts/update_seclists.sh
#   ./scripts/update_seclists.sh
# ============================================================

GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

SECLISTS_DIR="$HOME/SecLists"
WORDLISTS_LOCAL="wordlists"

# ─────────────────────────────────────────────
info "SecLists updater starting"
# ─────────────────────────────────────────────

# Check git
if ! command -v git >/dev/null 2>&1; then
  fail "git not installed"
  exit 1
fi

# Clone or pull
if [ ! -d "$SECLISTS_DIR" ]; then
  info "Cloning SecLists (this may take a few minutes)..."
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR" 2>&1 | tail -3
  if [ $? -eq 0 ]; then
    ok "SecLists cloned"
  else
    fail "SecLists clone failed"
    exit 1
  fi
else
  info "Updating SecLists..."
  (cd "$SECLISTS_DIR" && git pull --depth 1 2>&1 | tail -3)
  if [ $? -eq 0 ]; then
    ok "SecLists updated"
  else
    warn "SecLists update failed — using existing"
  fi
fi

# ─────────────────────────────────────────────
info "Building optimized wordlists for the framework..."
# ─────────────────────────────────────────────
mkdir -p "$WORDLISTS_LOCAL"

# Key wordlists to copy/link
declare -A MAP=(
  ["common.txt"]="Discovery/Web-Content/common.txt"
  ["raft-small-directories.txt"]="Discovery/Web-Content/raft-small-directories.txt"
  ["raft-medium-directories.txt"]="Discovery/Web-Content/raft-medium-directories.txt"
  ["quickhits.txt"]="Discovery/Web-Content/quickhits.txt"
  ["api-endpoints.txt"]="Discovery/Web-Content/api/api-endpoints.txt"
  ["graphql.txt"]="Discovery/Web-Content/graphql.txt"
  ["swagger.txt"]="Discovery/Web-Content/swagger.txt"
  ["backup-files.txt"]="Discovery/Web-Content/CommonBackupFile.fuzz.txt"
  ["params-common.txt"]="Discovery/Web-Content/burp-parameter-names.txt"
  ["subdomains-top1m.txt"]="Discovery/DNS/subdomains-top1million-110000.txt"
  ["dns-Jhaddix.txt"]="Discovery/DNS/dns-Jhaddix.txt"
  ["usernames.txt"]="Usernames/top-usernames-shortlist.txt"
  ["passwords-top1000.txt"]="Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
  ["lfi.txt"]="Fuzzing/LFI/LFI-Jhaddix.txt"
  ["ssrf-payloads.txt"]="Fuzzing/SSRF/SSRF-Injection.txt"
)

COPIED=0
MISSING=0
for dest in "${!MAP[@]}"; do
  src="$SECLISTS_DIR/${MAP[$dest]}"
  out="$WORDLISTS_LOCAL/$dest"
  if [ -f "$src" ]; then
    # Symlink to avoid duplication
    if [ -L "$out" ] || [ -f "$out" ]; then
      rm -f "$out"
    fi
    ln -s "$src" "$out" 2>/dev/null || cp "$src" "$out"
    ok "linked: $dest"
    COPIED=$((COPIED+1))
  else
    warn "not found in SecLists: ${MAP[$dest]}"
    MISSING=$((MISSING+1))
  fi
done

# ─────────────────────────────────────────────
info "Building combined wordlist..."
# ─────────────────────────────────────────────
COMBINED="$WORDLISTS_LOCAL/combined-common.txt"
cat "$WORDLISTS_LOCAL/common.txt" \
    "$WORDLISTS_LOCAL/quickhits.txt" \
    "$WORDLISTS_LOCAL/raft-small-directories.txt" 2>/dev/null \
  | sort -u > "$COMBINED" 2>/dev/null

if [ -s "$COMBINED" ]; then
  LINES=$(wc -l < "$COMBINED")
  ok "combined-common.txt: $LINES entries"
else
  warn "combined-common.txt empty"
fi

# ─────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}  SecLists update complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo -e "  SecLists location:  ${CYAN}$SECLISTS_DIR${NC}"
echo -e "  Wordlists linked:   ${CYAN}$COPIED${NC}"
echo -e "  Not found:          ${CYAN}$MISSING${NC}"
echo ""