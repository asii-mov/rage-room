# Supply-Chain Hardening Configs

Part of the **Rage Room** secure AI tooling project. These configurations harden package managers against supply-chain attacks across multiple ecosystems.

All configs in this directory are automatically baked into Rage Room sandboxes (containers and remote VMs).

## Config Files

### `.npmrc` — npm / Node.js

| Setting | Value | Purpose |
|---------|-------|---------|
| `ignore-scripts` | `true` | Blocks `preinstall`/`postinstall` scripts that packages use to run arbitrary code on your machine during `npm install`. Most supply-chain attacks rely on install scripts. If a package legitimately needs scripts, run them explicitly after review. |
| `save-exact` | `true` | Pins dependencies to exact versions (e.g., `1.2.3` instead of `^1.2.3`). Prevents silent upgrades to compromised patch releases. |
| `prefer-binary` | `true` | Downloads pre-built native binaries instead of compiling from source. Avoids executing arbitrary build toolchains during install. |
| `min-release-age` | `7` | Refuses to install package versions published less than 7 days ago. New malicious versions are typically caught and removed within this window. |

### `uv.toml` — Python (uv package manager)

| Setting | Value | Purpose |
|---------|-------|---------|
| `exclude-newer` | `7 days` | Equivalent to npm's `min-release-age`. Prevents installing Python packages published in the last 7 days. |

### `go-env.sh` — Go modules

| Setting | Value | Purpose |
|---------|-------|---------|
| `GOPROXY` | `proxy.golang.org,off` | Forces all module downloads through Google's official proxy. The `,off` suffix means if the proxy doesn't have the module, the download fails rather than falling back to fetching directly from the source repository (which could be compromised). |
| `GOSUMDB` | `sum.golang.org` | Verifies module checksums against Google's transparency log. Detects if a module's content was tampered with after initial publication. |

## Applying Configs

### Automated (recommended)

```bash
# Preview what will change
./apply.sh --dry-run

# Apply
./apply.sh
```

The script:
- Copies `.npmrc` to `~/.npmrc`
- Creates `~/.config/uv/` and copies `uv.toml` there
- Appends Go env vars to `~/.profile` (if not already present)
- Backs up any existing files before overwriting (with timestamped `.bak` suffix)

### Manual

```bash
# npm
cp hardening/.npmrc ~/.npmrc

# uv
mkdir -p ~/.config/uv
cp hardening/uv.toml ~/.config/uv/uv.toml

# Go — add to your shell profile (~/.profile, ~/.bashrc, ~/.zshrc, etc.)
export GOPROXY="proxy.golang.org,off"
export GOSUMDB="sum.golang.org"
```

## MDM Deployment

For managed machines, deploy these files to the following locations:

| Config | Destination | Notes |
|--------|-------------|-------|
| `.npmrc` | `~/.npmrc` per user, or set `NPM_CONFIG_USERCONFIG` env var | Per-project `.npmrc` files override global; consider also setting in `/etc/npmrc` for system-wide enforcement |
| `uv.toml` | `~/.config/uv/uv.toml` | Or set `UV_CONFIG_FILE` env var |
| Go env vars | `/etc/profile.d/go-hardening.sh` | System-wide; users can still override per-session |

## Verifying Configs Are Active

```bash
# npm — all four settings should appear
npm config list

# uv — should show exclude-newer
uv pip install --dry-run some-package  # observe that recent packages are rejected

# Go — verify proxy and sumdb
go env GOPROXY   # should print: proxy.golang.org,off
go env GOSUMDB   # should print: sum.golang.org
```

## Opting Out

You can override individual settings if a specific workflow requires it. Understand the risks before doing so.

**npm:**
```bash
# Per-command override (does not change your .npmrc)
npm install --ignore-scripts=false some-package

# Per-project: create a .npmrc in the project root with overrides
```
Risk: `ignore-scripts=false` allows packages to execute arbitrary code during install.

**uv:**
```bash
# Override for a single install
uv pip install --exclude-newer="" some-package
```
Risk: Removes the quarantine window; you may install a package version that was published minutes ago and has not been vetted.

**Go:**
```bash
# Temporary direct fetch (bypasses proxy)
GONOSUMCHECK=example.com/private GOPROXY=direct go get example.com/private/module
```
Risk: Fetching directly from a repository skips the proxy cache and transparency log. Only use for private/internal modules.

## Other Ecosystems

The following ecosystems are not yet covered but have their own hardening options. These are documented here for awareness.

**Rust (cargo):**
- Use `cargo-audit` to check for known vulnerabilities
- Use `cargo-deny` to enforce policies on licenses, sources, and advisories
- Pin dependencies in `Cargo.lock` and commit it

**Ruby (bundler):**
- `bundle config set frozen true` prevents Gemfile.lock from being updated unexpectedly
- Use `bundler-audit` to scan for known vulnerabilities
- Consider `bundle config set only production` in CI/production

**Java (Maven/Gradle):**
- Use Maven Enforcer Plugin or Gradle dependency verification
- Enable checksum verification with `--strict-checksums` (Maven) or `dependencyVerification` (Gradle)
- Use a repository proxy (Nexus, Artifactory) as a single source of truth

**PHP (Composer):**
- Use `composer audit` to check for known vulnerabilities
- Pin versions in `composer.lock` and commit it
- Set `secure-http: true` (default) to require HTTPS for all downloads
