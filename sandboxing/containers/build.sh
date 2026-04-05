#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAGE_ROOM_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> Copying org configs into build context..."
mkdir -p "$SCRIPT_DIR/org-configs"
cp "$RAGE_ROOM_ROOT/claude-code/settings.json" "$SCRIPT_DIR/org-configs/settings.json"
cp "$RAGE_ROOM_ROOT/claude-code/CLAUDE.md" "$SCRIPT_DIR/org-configs/CLAUDE.md"
cp "$RAGE_ROOM_ROOT/codex/config.toml" "$SCRIPT_DIR/org-configs/codex-config.toml"

echo "==> Copying hardening configs into build context..."
cp "$RAGE_ROOM_ROOT/hardening/.npmrc" "$SCRIPT_DIR/org-configs/.npmrc"
cp "$RAGE_ROOM_ROOT/hardening/uv.toml" "$SCRIPT_DIR/org-configs/uv.toml"
cp "$RAGE_ROOM_ROOT/hardening/go-env.sh" "$SCRIPT_DIR/org-configs/go-env.sh"

echo "==> Building rage-room-sandbox image..."
docker build -t rage-room-sandbox:latest "$SCRIPT_DIR"

echo "==> Build complete: rage-room-sandbox:latest"
