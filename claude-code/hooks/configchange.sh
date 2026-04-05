#!/usr/bin/env bash
# Claude Code configchange hook
# Alerts when configuration is modified outside managed settings
# Deploy via server-managed settings: https://code.claude.com/docs/en/server-managed-settings

set -euo pipefail

CHANGE_TYPE="${1:-unknown}"
LOG_FILE="${HOME}/.claude/config-changes.log"

mkdir -p "$(dirname "$LOG_FILE")"

timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[$timestamp] Config change detected: $CHANGE_TYPE" >> "$LOG_FILE"

# In a managed fleet, this could:
# 1. Send to a SIEM/logging endpoint
# 2. Block the change by exiting non-zero
# 3. Alert via Slack/PagerDuty webhook

# Uncomment the next line to block all config changes in a locked-down fleet:
# echo "ERROR: Configuration changes are managed centrally. Contact platform-eng." >&2 && exit 1
