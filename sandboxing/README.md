# Sandboxing

Sandboxed execution environments for AI coding tools (Claude Code, Codex CLI). Provides both local Docker containers and remote DigitalOcean VMs with identical security configurations.

Inspired by [dropkit](https://github.com/trailofbits/dropkit) by Trail of Bits.

## Container Sandbox

Runs AI coding tools inside a Docker container with network isolation, org-enforced settings, and `bypassPermissions` mode (the container **is** the sandbox).

### What it provides

- Pre-installed Claude Code and Codex CLI
- Org-baseline settings, CLAUDE.md, and Codex config baked in
- Supply-chain hardening: `.npmrc` (ignore-scripts, 7-day release age), `uv.toml` (exclude-newer 7 days), Go proxy/sumdb enforcement
- Per-project persistent volumes for shell history, Claude state, Codex state, and GitHub CLI auth
- SSH agent forwarding from the host
- Network isolation capabilities (NET_ADMIN, NET_RAW)

### Prerequisites

- Docker

### Build

```bash
./containers/build.sh
```

This copies org configs and hardening configs from the `rage-room/` root into the build context, then builds the `rage-room-sandbox:latest` image.

### Run

```bash
./containers/run.sh /path/to/project
```

Create a `.env` file in `containers/` first (copy from `env.example` and fill in your API keys).

## Remote Sandbox

Provisions a DigitalOcean VM with the same security configuration as the container sandbox, accessible via SSH or Tailscale VPN.

### What it provides

- Hardened Ubuntu 24.04 VM with UFW firewall, fail2ban, and SSH hardening
- Claude Code and Codex CLI pre-installed
- Org configs applied automatically via cloud-init
- Supply-chain hardening applied at the OS level
- Optional Tailscale VPN with SSH locked to Tailscale-only
- Hibernate/wake workflow (snapshot + destroy to save cost)
- Multi-user sharing via GitHub SSH keys

### Prerequisites

- DigitalOcean account with API token
- Python 3.11+
- SSH key pair

### Setup

```bash
uv pip install -e remote/
```

### CLI usage

```bash
# Configure credentials and defaults
rage-room-remote config

# Create a new sandbox VM
rage-room-remote create my-project

# List all sandbox VMs
rage-room-remote list

# SSH into a sandbox
rage-room-remote ssh my-project

# Hibernate (snapshot + destroy)
rage-room-remote hibernate my-project

# Wake from snapshot
rage-room-remote wake my-project

# Share with teammates via GitHub usernames
rage-room-remote share my-project user1,user2

# Destroy a sandbox and its snapshots
rage-room-remote destroy my-project
```

Configuration is stored at `~/.config/rage-room-remote/config.yaml` with `0600` permissions.

## Supply-chain hardening

Both container and VM sandboxes automatically apply:

- **npm**: `ignore-scripts=true`, `save-exact=true`, `prefer-binary=true`, `min-release-age=7` (via `.npmrc` and `NPM_CONFIG_*` env vars as belt-and-suspenders)
- **Python/uv**: `exclude-newer = "7 days"` (via `uv.toml`)
- **Go**: `GOPROXY="proxy.golang.org,off"`, `GOSUMDB="sum.golang.org"` (proxy-only with checksum verification, no direct fallback)

These settings prevent installation of packages published less than 7 days ago, disable install scripts, and enforce checksum verification through official proxies.

## Sandboxing is ON by default

Both Claude Code (`bypassPermissions` mode inside container) and Codex CLI (`read-only` sandbox mode) run sandboxed by default in these environments.

**Warning**: Disabling sandboxing removes the primary security boundary. Only do this if you understand the risks. To disable:

- Claude Code: change `defaultMode` from `bypassPermissions` to `allowEdits` in `~/.claude/settings.json` inside the container
- Codex CLI: change `sandbox.mode` from `read-only` to `off` in `~/.codex/config.toml`
