# Rage Room

Like a rage room, break things all you want — it doesn't matter.

A suite of tools for enabling developers and teams to use AI coding assistants without compromising on security. Sandboxing made easy, automated secret redaction, supply-chain hardening, and org-managed policy — all in one place.

Use this as a starting point. Extend it with your own MDM policies, container images, and tooling integrations.

## Modules

| Module | Description | Docs |
|--------|-------------|------|
| [`hardening/`](hardening/) | Supply-chain configs for npm, Python/uv, and Go — age-gated packages, pinned versions, checksum enforcement | [README](hardening/README.md) |
| [`sandboxing/`](sandboxing/) | Local Docker containers and remote DigitalOcean VMs with identical security configs | [README](sandboxing/README.md) |
| [`sandboxing/containers/`](sandboxing/containers/) | Docker sandbox image with all hardening baked in, per-project volumes, SSH agent forwarding | [README](sandboxing/README.md#container-sandbox) |
| [`sandboxing/remote/`](sandboxing/remote/) | `rage-room-remote` CLI — provision, hibernate, wake, share, and destroy hardened VMs on DigitalOcean | [README](sandboxing/README.md#remote-sandbox) |
| [`claude-code/`](claude-code/) | Org-managed Claude Code settings: deny rules, hooks, coding standards | [README](claude-code/README.md) |
| [`no-keys/`](no-keys/) | MITM proxy that intercepts and redacts 13 secret pattern types before they reach any API | [README](no-keys/README.md) |
| [`codex/`](codex/) | Codex CLI org config: read-only sandbox, env var exclusions, marketplace policy | [README](codex/README.md) |

## Quick Start

### Sandbox Container (recommended)

```bash
cd sandboxing/containers
./build.sh
./run.sh /path/to/your/project
```

### Bare-Metal

```bash
cd hardening && ./apply.sh --dry-run   # Preview, then: ./apply.sh
cp claude-code/settings.json ~/.claude/settings.json
cp claude-code/CLAUDE.md ~/.claude/CLAUDE.md
mkdir -p ~/.codex && cp codex/config.toml ~/.codex/config.toml
```

### Remote VM (DigitalOcean)

```bash
cd sandboxing/remote && uv pip install -e .
rage-room-remote config
rage-room-remote create my-sandbox
rage-room-remote ssh my-sandbox
```

## Guiding Principles

- **Sandbox by default.** Users must explicitly opt-in to disable sandboxing.
- **No secrets in context.** No tool may read `.env` files or any credential file.
- **Minimal trust, verified supply chain.** All packages pinned, age-gated, and checksum-verified.
- **One folder per tool.** Each integration lives in its own directory with its own documentation.

## MDM / Fleet Checklist

Items that cannot be enforced via config files alone — these require MDM policies, IT processes, or manual verification.

### Supply Chain Hardening

- [ ] MDM policy to deploy `hardening/.npmrc` to `~/.npmrc` on all developer machines and remote machines
- [ ] MDM policy to deploy `hardening/uv.toml` to `~/.config/uv/uv.toml` on all developer machines and remote machines
- [ ] MDM policy to set `GOPROXY=proxy.golang.org,off` and `GOSUMDB=sum.golang.org` in shell profiles
- [ ] Quarterly review of pinned dependency versions across all projects

### Cloud IAM Authentication

- [ ] AWS: enforce IAM roles or SSO for Bedrock access — no long-lived access keys
- [ ] GCP: enforce `gcloud auth application-default login` for Vertex AI — no embedded service account keys
- [ ] Azure: enforce managed identity or workload identity federation — no connection strings with embedded keys

### Plugin / Skills Marketplace

- [ ] Claude Code: enforce company internal marketplace for all plugins and skills (no programmatic enforcement exists — manual policy + audit), look at [trailofbits](https://github.com/trailofbits/skills) as an example
- [ ] Codex: enforce company internal marketplace for all plugins and skills (no programmatic enforcement exists — manual policy + audit)
- [ ] Include marketplace policy in developer onboarding materials
- [ ] Schedule periodic audits for plugins/skills installations

### Fleet Management

- [ ] Deploy `claude-code/settings.json` as server-managed settings to all developer machines
- [ ] Potentially configure `configchange` hook log collection to central SIEM/logging
- [ ] Decide whether to enable config change blocking (uncomment block line in `hooks/configchange.sh`)

### Onboarding

- [ ] New developers receive sandbox setup instructions (container or remote VM)
- [ ] New developers acknowledge supply-chain and credential policies

## Contributing

- Each tool gets its own directory with its own `README.md`
- If you identify a hardening opportunity for an ecosystem not yet covered, add it to `hardening/README.md`
- If a control cannot be enforced programmatically, add it to the MDM checklist above
- Do not make sandboxing opt-out by default
- Do not silently skip a hardening step

## Credits

Sandboxing infrastructure inspired by [dropkit](https://github.com/trailofbits/dropkit) by Trail of Bits. Secret redaction middleware from [no-keys](https://github.com/asii-mov/no-keys).
