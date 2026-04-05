# Codex CLI - Org Configuration

## Quick Start

1. Install Codex CLI:

   ```bash
   npm install -g @openai/codex
   ```

2. The org baseline config lives in this repo at `codex/config.toml`.

3. Deployment: the config is copied to `~/.codex/config.toml` on managed machines, or baked into Rage Room sandbox containers during image build.

---

## Sandbox Configuration and Opt-Out Instructions

### What read-only sandbox mode means

The org default sandbox mode is `read-only`. In this mode, Codex can read files on
the filesystem but cannot write, rename, or delete them. Any command Codex generates
that attempts to modify the filesystem will be blocked by the sandbox layer before
execution.

### Why read-only is the default

Read-only mode minimizes the blast radius if Codex generates a harmful or incorrect
command. It prevents accidental file deletion, overwrites of production configs, and
other destructive operations on the host machine.

### How to change sandbox mode

To override the sandbox mode, edit your **personal** config file (not the org file in
this repo):

```toml
# ~/.codex/config.toml

[sandbox]
mode = "standard"   # allows writes
# mode = "lenient"  # fewer restrictions
```

Available modes:

| Mode        | Behavior                                      |
|-------------|-----------------------------------------------|
| `read-only` | Filesystem reads only (org default)           |
| `standard`  | Allows writes within the working directory    |
| `lenient`   | Fewer restrictions on filesystem operations   |
| `off`       | No sandbox at all                             |

**Warning:** Weakening the sandbox removes a critical security boundary. Only change
this if you understand the risks and have approval from the platform team.

Setting `mode = "off"` is strongly discouraged and should require manager approval.

### Sandbox mode inside Rage Room containers

Inside Rage Room sandbox containers, the container itself IS the sandbox. The
container runs with limited privileges, an isolated filesystem, and no access to the
host. In that context, `standard` mode is acceptable because the container boundary
provides equivalent protection.

---

## Secret File Blocking Approach

### Environment variable exclusions

The `[shell_environment]` section in `config.toml` prevents sensitive environment
variables from being passed to Codex subprocesses. The following variables are
excluded:

| Variable                | Reason                                         |
|-------------------------|------------------------------------------------|
| `ANTHROPIC_API_KEY`     | Third-party AI provider credentials            |
| `OPENAI_API_KEY`        | OpenAI API credentials                         |
| `AWS_SECRET_ACCESS_KEY` | AWS IAM secret key                             |
| `AWS_SESSION_TOKEN`     | AWS temporary session credentials              |
| `GITHUB_TOKEN`          | GitHub API / Actions token                     |
| `STRIPE_SECRET_KEY`     | Payment processor credentials                  |

The `inherit = "core"` setting ensures only essential shell variables (PATH, HOME,
etc.) are passed through, with the above exclusions applied on top.

### Limitations

Codex does not currently support file-level deny rules comparable to Claude Code's
`permissions.deny`. This means:

- `.env` files **cannot** be blocked from Codex's context programmatically.
- Developers must be trained not to reference `.env` files in Codex prompts.
- Ensure `.env` files are listed in `.gitignore` and are not present in working
  directories where Codex runs.

Inside Rage Room sandbox containers, `.env` files are not mounted into the container.
Environment variables are passed via `--env-file` to Docker at runtime, so the file
contents never exist on the container filesystem.

---

## Plugin / Skills Marketplace Policy

### Policy

Developers must use the company's internal marketplace for all Codex plugins and
skills. Installing plugins from external or unvetted sources is prohibited.

### Enforcement status

No programmatic enforcement mechanism currently exists in Codex CLI. There is no
allowlist, policy file, or registry lock that prevents a developer from installing
arbitrary plugins.

This is a **manual / MDM control**:

- Include the marketplace-only policy in developer onboarding documentation.
- Include plugin compliance checks in periodic security audits.
- Monitor for unauthorized plugin installations via endpoint management tooling.

If and when Codex adds allowlist or policy support for plugins, update this section
and the org `config.toml` accordingly.
