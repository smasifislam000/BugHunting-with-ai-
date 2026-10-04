#!/bin/bash
# ============================================================
# Dream Framework - Snapshot / Restore Script
# ============================================================
# Usage:
#   ./scripts/snapshot.sh create [name]
#   ./scripts/snapshot.sh list
#   ./scripts/snapshot.sh restore <name>
#   ./scripts/snapshot.sh delete <name>
#   ./scripts/snapshot.sh auto   (create daily auto snapshot)
# ============================================================

set -e

GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
NC='\033[0m'

SNAPSHOT_DIR="snapshots"
KEEP=10   # keep last N auto snapshots

ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

mkdir -p "$SNAPSHOT_DIR"

# ─────────────────────────────────────────────
create_snapshot() {
  local name="$1"
  if [ -z "$name" ]; then
    name="snap_$(date +%Y%m%d-%H%M%S)"
  fi
  local archive="$SNAPSHOT_DIR/$name.tar.gz"
  local tmp="$SNAPSHOT_DIR/$name.tmp"

  mkdir -p "$tmp"

  # Copy config (if exists)
  [ -f "config.json" ] && cp config.json "$tmp/" 2>/dev/null || true

  # Copy DB (if exists) using SQLite backup for consistency
  if [ -f "bug_bounty.db" ]; then
    if command -v sqlite3 >/dev/null 2>&1; then
      sqlite3 bug_bounty.db ".backup '$tmp/bug_bounty.db'" 2>/dev/null || \
        cp bug_bounty.db "$tmp/" 2>/dev/null
    else
      cp bug_bounty.db "$tmp/" 2>/dev/null
    fi
  fi

  # Copy results (metadata only — avoid huge scans)
  if [ -d "results" ]; then
    mkdir -p "$tmp/results"
    # Copy small meta files only
    find results -maxdepth 3 -type f \
      \( -name "*.json" -o -name "subdomains.txt" -o -name "live_hosts.txt" \
      -o -name "tech_stack.json" -o -name "recon_summary.json" \) \
      -exec cp --parents {} "$tmp/" \; 2>/dev/null || true
  fi

  # Copy logs (last 1000 lines per log file)
  if [ -d "logs" ]; then
    mkdir -p "$tmp/logs"
    for f in logs/*.log; do
      [ -f "$f" ] || continue
      tail -n 1000 "$f" > "$tmp/$f" 2>/dev/null || true
    done
  fi

  # Metadata
  cat > "$tmp/MANIFEST.txt" <<EOF
Snapshot:   $name
Created:    $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Hostname:   $(hostname 2>/dev/null || echo unknown)
Kernel:     $(uname -r 2>/dev/null || echo unknown)
Framework:  Dream Framework v1.0
EOF

  tar -czf "$archive" -C "$tmp" . 2>/dev/null
  rm -rf "$tmp"

  if [ -f "$archive" ]; then
    SIZE=$(du -h "$archive" | cut -f1)
    ok "Snapshot created: $archive ($SIZE)"
  else
    fail "Snapshot failed"
    exit 1
  fi
}

# ─────────────────────────────────────────────
list_snapshots() {
  echo -e "${CYAN}Snapshots in $SNAPSHOT_DIR:${NC}"
  if [ ! -d "$SNAPSHOT_DIR" ] || [ -z "$(ls -A "$SNAPSHOT_DIR" 2>/dev/null)" ]; then
    warn "No snapshots found"
    return
  fi
  ls -lh "$SNAPSHOT_DIR"/*.tar.gz 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
}

# ─────────────────────────────────────────────
restore_snapshot() {
  local name="$1"
  local archive="$SNAPSHOT_DIR/$name.tar.gz"
  if [ ! -f "$archive" ]; then
    archive="$SNAPSHOT_DIR/$name"
  fi
  if [ ! -f "$archive" ]; then
    fail "Snapshot not found: $name"
    exit 1
  fi

  # Safety backup of current state
  local pre="pre_restore_$(date +%Y%m%d-%H%M%S)"
  warn "Creating pre-restore safety snapshot: $pre"
  create_snapshot "$pre" >/dev/null

  local tmp="$SNAPSHOT_DIR/.restore_tmp"
  rm -rf "$tmp" && mkdir -p "$tmp"
  tar -xzf "$archive" -C "$tmp"

  # Restore DB
  if [ -f "$tmp/bug_bounty.db" ]; then
    cp "$tmp/bug_bounty.db" "bug_bounty.db"
    ok "Database restored"
  fi

  # Restore config (do NOT overwrite if user has edited)
  if [ -f "$tmp/config.json" ]; then
    if [ ! -f "config.json" ]; then
      cp "$tmp/config.json" "config.json"
      ok "Config restored"
    else
      warn "config.json exists — snapshot config saved as config.snapshot.json"
      cp "$tmp/config.json" "config.snapshot.json"
    fi
  fi

  # Restore results (safe-merge)
  if [ -d "$tmp/results" ]; then
    cp -rn "$tmp/results/." "results/" 2>/dev/null || true
    ok "Results merged"
  fi

  rm -rf "$tmp"
  ok "Restore complete"
}

# ─────────────────────────────────────────────
delete_snapshot() {
  local name="$1"
  local archive="$SNAPSHOT_DIR/$name.tar.gz"
  if [ -f "$archive" ]; then
    rm -f "$archive"
    ok "Deleted: $archive"
  else
    fail "Not found: $name"
  fi
}

# ─────────────────────────────────────────────
auto_snapshot() {
  create_snapshot "auto_$(date +%Y%m%d)"

  # Trim old auto snapshots
  local count
  count=$(ls -1 "$SNAPSHOT_DIR"/auto_*.tar.gz 2>/dev/null | wc -l)
  if [ "$count" -gt "$KEEP" ]; then
    ls -1t "$SNAPSHOT_DIR"/auto_*.tar.gz | tail -n +$((KEEP + 1)) | xargs -r rm -f
    warn "Trimmed old auto snapshots (kept last $KEEP)"
  fi
}

# ─────────────────────────────────────────────
# Command dispatch
# ─────────────────────────────────────────────
case "${1:-}" in
  create)
    create_snapshot "$2"
    ;;
  list)
    list_snapshots
    ;;
  restore)
    [ -z "$2" ] && { fail "Usage: $0 restore <name>"; exit 1; }
    restore_snapshot "$2"
    ;;
  delete)
    [ -z "$2" ] && { fail "Usage: $0 delete <name>"; exit 1; }
    delete_snapshot "$2"
    ;;
  auto)
    auto_snapshot
    ;;
  *)
    echo "Dream Framework - Snapshot Utility"
    echo ""
    echo "Usage:"
    echo "  $0 create [name]     Create a snapshot"
    echo "  $0 list              List all snapshots"
    echo "  $0 restore <name>    Restore a snapshot"
    echo "  $0 delete <name>     Delete a snapshot"
    echo "  $0 auto              Create auto snapshot (keeps last $KEEP)"
    echo ""
    echo "Examples:"
    echo "  $0 create before_11B"
    echo "  $0 list"
    echo "  $0 restore before_11B"
    ;;
esac