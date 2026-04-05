# Claude Code Org-Managed Settings

This directory contains the centralized Claude Code configuration for managed developer environments. It includes server-managed settings, a configchange hook, and coding standards (CLAUDE.md).

## Contents

```
claude-code/
├── settings.json              # Server-managed settings (deny rules, hooks, permissions)
├── CLAUDE.md                  # Org coding standards injected into every session
├── hooks/
│   └── configchange.sh        # Hook script triggered on configuration changes
└── README.md                  # This file
```

---

## no-keys Secret Redaction

The no-keys secret redaction proxy lives at [`no-keys/`](../no-keys/) in the repo root. See the [no-keys README](../no-keys/README.md) for installation, configuration, and usage.

---

## How .env Blocking Works

The `settings.json` file contains `permissions.deny` rules that prevent Claude Code from reading or editing sensitive files. These rules are enforced by the Claude Code runtime before any tool call executes.

### Denied Operations

| Pattern | What it blocks |
|---------|---------------|
| `Read(.env*)` / `Edit(.env*)` | All `.env` files (`.env`, `.env.local`, `.env.production`, etc.) |
| `Read(credentials.json)` / `Edit(credentials.json)` | GCP service account files and similar |
| `Read(**/secrets/**)` / `Edit(**/secrets/**)` | Any `secrets/` directory tree |
| `Read(**/*.pem)` / `Edit(**/*.pem)` | TLS/SSH certificates |
| `Read(**/*.key)` / `Edit(**/*.key)` | Private key files |
| `Read(**/.aws/credentials)` | AWS credential files |
| `Read(**/.gcloud/**)` | GCP CLI configuration and tokens |
| `Read(**/.azure/**)` | Azure CLI configuration and tokens |

### Verification

```bash
# Start Claude Code and attempt to read a blocked file:
claude "read .env"
# Expected: operation denied by permissions.deny rule

# Verify the deny rules are in the active settings:
grep ".env" claude-code/settings.json
```

### Adding Additional Patterns

Edit `settings.json` and add entries to the `permissions.deny` array:

```json
"deny": [
  "Read(**/.vault-token)",
  "Read(**/service-account.json)",
  "Edit(**/*.secret)"
]
```

---

## Cloud IAM Auth Instructions

When using Claude Code with cloud-hosted model providers, authenticate using short-lived credentials and IAM roles. Never use long-lived access keys or embed secrets in environment variables.

### AWS Bedrock

Use IAM roles or SSO. Do NOT use long-lived access keys (`AKIA...`).

```bash
# Authenticate via SSO
aws sso login --profile your-profile

# Set environment for Claude Code
export CLAUDE_CODE_USE_BEDROCK=1
export AWS_REGION=us-east-1
export AWS_PROFILE=your-profile
```

For EC2/ECS/Lambda, attach an IAM role with `bedrock:InvokeModel` permissions directly to the compute resource. No explicit credential configuration needed.

### GCP Vertex AI

Use Application Default Credentials via `gcloud`. Do NOT embed service account key JSON files.

```bash
# Authenticate
gcloud auth application-default login

# Set environment for Claude Code
export CLAUDE_CODE_USE_VERTEX=1
export CLOUD_ML_REGION=us-east5
export ANTHROPIC_VERTEX_PROJECT_ID=your-project-id
```

For GCE/GKE/Cloud Run, use the attached service account identity. For CI/CD, use Workload Identity Federation.

### Azure

Use `az login` with managed identity or workload identity federation. Do NOT use connection strings with embedded keys.

```bash
# Authenticate
az login

# For managed identity on Azure VMs/AKS:
# No explicit credential configuration needed -- identity is attached to the resource
```

> **Note**: If your organization does not use cloud-hosted Claude (Bedrock/Vertex/Azure), this section is N/A. You can remove it or keep it for reference.

---

## Managed Settings Reference and configchange Hook

### Server-Managed Settings

Reference: https://code.claude.com/docs/en/server-managed-settings

Server-managed settings allow platform teams to push a `settings.json` to all developer machines. The file is merged with any local user settings, with server-managed deny rules taking precedence (they cannot be overridden locally).

### What `settings.json` Controls

- **`permissions.deny`**: File patterns that Claude Code is forbidden from reading or editing. These rules are additive and cannot be removed by end users.
- **`permissions.defaultMode`**: The default permission mode (`allowEdits` requires user approval for dangerous operations like shell commands).
- **`hooks`**: Event-triggered scripts that run when specific actions occur.
- **`env`**: Environment variables injected into Claude Code sessions.

### The configchange Hook

The `configchange` hook fires whenever Claude Code's configuration is modified. It is defined in `settings.json`:

```json
"hooks": {
  "configchange": [
    {
      "command": "/bin/bash hooks/configchange.sh",
      "description": "Alert on unapproved configuration changes"
    }
  ]
}
```

**What triggers it**: Any modification to Claude Code's local configuration files.

**Where it logs**: `~/.claude/config-changes.log` (timestamped entries).

**How to customize**: Edit `hooks/configchange.sh` to:
1. Send events to a SIEM or logging endpoint
2. Alert via Slack or PagerDuty webhook
3. Block changes entirely (exit non-zero)

### Deployment

Push `settings.json` to `~/.claude/settings.json` on managed machines using your configuration management tool (Ansible, Chef, Puppet, MDM, etc.):

```bash
# Example: deploy to a fleet via rsync/scp
scp claude-code/settings.json target-host:~/.claude/settings.json
scp -r claude-code/hooks target-host:~/.claude/hooks
```

### Locking Down Configuration

To block all local configuration changes in a locked-down fleet, uncomment the block line in `hooks/configchange.sh`:

```bash
echo "ERROR: Configuration changes are managed centrally. Contact platform-eng." >&2 && exit 1
```

---

## Plugin Marketplace Policy

**Policy**: Developers must use the company's internal marketplace for all Claude Code plugins and skills. Do not install plugins from external or unvetted sources.

**Current enforcement status**: There is **no programmatic enforcement mechanism** in Claude Code for restricting plugin sources. Claude Code does not currently support an allowlist or blocklist for plugins/skills.

**How this is enforced today**:
- Manual policy communicated during developer onboarding
- MDM/endpoint management controls where applicable
- Periodic audits of installed plugins on developer machines
- `CLAUDE.md` coding standards (included in this directory) remind developers of the policy

**Future**: If/when Claude Code adds plugin allowlist or marketplace restriction support, update `settings.json` with the appropriate configuration and update this section.

---

## Sandbox Enable/Disable Instructions

Claude Code includes a sandbox (bubblewrap on Linux) that restricts file system and network access for tool executions.

### In the Container Sandbox

The container sandbox (see `../sandboxing/`) runs Claude Code inside an isolated Docker container. In this configuration:
- `bypassPermissions` mode is set because the container itself IS the security boundary
- The container's filesystem isolation, network policies, and resource limits provide defense-in-depth
- Claude Code operates with full permissions inside the container, but the container restricts what it can reach

### On Bare-Metal / Developer Machines

On uncontainerized machines, `settings.json` sets `defaultMode: "allowEdits"`:
- Claude Code can read and edit files (subject to deny rules)
- Shell commands and other risky operations require explicit user approval
- The bubblewrap sandbox (if available) provides additional OS-level isolation

### Full Sandbox Options

For stronger isolation beyond the built-in bubblewrap sandbox:
- **Container sandbox**: See `../sandboxing/` for Docker-based isolation with resource limits and network controls
- **Remote VM**: See `../sandboxing/` for ephemeral VM-based execution via the remote CLI

Choose the isolation level appropriate to your threat model and workflow requirements.
