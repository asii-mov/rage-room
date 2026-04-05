#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=false
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "[dry-run] No changes will be made."
    echo
fi

installed=()
skipped=()
backed_up=()

log() { echo "  $*"; }

backup_if_exists() {
    local target="$1"
    if [[ -f "$target" ]]; then
        if $DRY_RUN; then
            log "[dry-run] Would back up $target to ${target}${BACKUP_SUFFIX}"
        else
            cp "$target" "${target}${BACKUP_SUFFIX}"
            log "Backed up $target -> ${target}${BACKUP_SUFFIX}"
        fi
        backed_up+=("$target")
    fi
}

install_file() {
    local src="$1" dest="$2"
    if $DRY_RUN; then
        log "[dry-run] Would copy $src -> $dest"
    else
        cp "$src" "$dest"
        log "Installed $dest"
    fi
    installed+=("$dest")
}

# --- npm ---
echo "==> npm (.npmrc)"
NPM_TARGET="$HOME/.npmrc"
backup_if_exists "$NPM_TARGET"
install_file "$SCRIPT_DIR/.npmrc" "$NPM_TARGET"
echo

# --- uv (Python) ---
echo "==> uv (uv.toml)"
UV_DIR="$HOME/.config/uv"
UV_TARGET="$UV_DIR/uv.toml"
if $DRY_RUN; then
    log "[dry-run] Would create directory $UV_DIR"
else
    mkdir -p "$UV_DIR"
fi
backup_if_exists "$UV_TARGET"
install_file "$SCRIPT_DIR/uv.toml" "$UV_TARGET"
echo

# --- Go ---
echo "==> Go (GOPROXY, GOSUMDB in ~/.profile)"
PROFILE="$HOME/.profile"
GO_VARS_INSTALLED=true
for var in GOPROXY GOSUMDB; do
    if grep -q "^export ${var}=" "$PROFILE" 2>/dev/null; then
        log "$var already set in $PROFILE — skipping"
        skipped+=("$var in $PROFILE")
        GO_VARS_INSTALLED=false
    fi
done
if $GO_VARS_INSTALLED; then
    if $DRY_RUN; then
        log "[dry-run] Would append Go env vars to $PROFILE"
    else
        {
            echo ""
            echo "# Go supply-chain hardening (added by rage-room)"
            echo 'export GOPROXY="proxy.golang.org,off"'
            echo 'export GOSUMDB="sum.golang.org"'
        } >> "$PROFILE"
        log "Appended Go env vars to $PROFILE"
    fi
    installed+=("$PROFILE (Go vars)")
fi
echo

# --- Summary ---
echo "==============================="
echo "  Supply-chain hardening summary"
echo "==============================="
if (( ${#installed[@]} )); then
    echo "Installed:"
    for f in "${installed[@]}"; do echo "  + $f"; done
fi
if (( ${#backed_up[@]} )); then
    echo "Backed up:"
    for f in "${backed_up[@]}"; do echo "  ~ $f"; done
fi
if (( ${#skipped[@]} )); then
    echo "Skipped (already present):"
    for f in "${skipped[@]}"; do echo "  - $f"; done
fi
if $DRY_RUN; then
    echo
    echo "Run without --dry-run to apply changes."
fi
