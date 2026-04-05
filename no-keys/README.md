# no-keys

An HTTPS proxy that automatically detects and redacts secrets in API requests before they reach AI model providers. Sits between your AI coding tools (Claude Code, Codex) and their API endpoints using standard proxy environment variables.

## How It Works

```
Claude Code
    |
    |-- CONNECT api.anthropic.com:443 --> no-keys proxy (localhost:8119)
    |                                         |
    |   <-- 200 Connection Established -------|
    |                                         |
    |== TLS handshake (proxy's CA cert) ======|
    |                                         |
    |-- POST /v1/messages ------------------>|
    |   (plaintext, proxy reads body)         |-- scan for secrets
    |                                         |-- redact any found
    |                                         |
    |                                         |-- POST /v1/messages --> api.anthropic.com
    |                                         |   (secrets replaced with placeholders)
    |                                         |
    |                                         |<-- response -----------|
    |<-- response ----------------------------|
```

The proxy terminates TLS using a locally-generated CA certificate, reads the plaintext request, redacts secrets, then forwards over HTTPS to the real API. Secrets never leave your machine.

## Detected Patterns

| Pattern | Example | Placeholder |
|---------|---------|-------------|
| OpenAI API Key | `sk-abc123...` | `<OPENAI_KEY_REDACTED_xxxx>` |
| Anthropic API Key | `sk-ant-api03-...` | `<ANTHROPIC_KEY_REDACTED_xxxx>` |
| AWS Access Key | `AKIAIOSFODNN7...` | `<AWS_ACCESS_KEY_REDACTED_xxxx>` |
| GitHub Token | `ghp_xxxxx...` | `<GITHUB_TOKEN_REDACTED_xxxx>` |
| Stripe Key | `sk_live_xxxxx...` | `<STRIPE_KEY_REDACTED_xxxx>` |
| Slack Token | `xoxb-xxxxx...` | `<SLACK_TOKEN_REDACTED_xxxx>` |
| Google API Key | `AIzaxxxxx...` | `<GOOGLE_API_KEY_REDACTED_xxxx>` |
| JWT Token | `eyJhbGci...` | `<JWT_TOKEN_REDACTED_xxxx>` |
| Private Key | `-----BEGIN PRIVATE KEY-----` | `<PRIVATE_KEY_REDACTED_xxxx>` |

## Quick Start

```bash
cd no-keys
uv venv && source .venv/bin/activate
uv pip install -e .

# Start the proxy (runs in foreground, Ctrl+C to stop)
no-keys start
```

In another terminal:

```bash
HTTPS_PROXY=http://127.0.0.1:8119 \
NODE_EXTRA_CA_CERTS=~/.no-keys/ca.pem \
claude
```

On first run, the proxy generates a CA certificate at `~/.no-keys/ca.pem`. Claude Code trusts it via `NODE_EXTRA_CA_CERTS`.

## Usage

### Start / Stop / Status

```bash
# Start in foreground
no-keys start

# Start with --log to see before/after for every redaction
no-keys start --log

# Start on a custom port
no-keys start --port 9090

# Start with debug logging
no-keys start --verbose

# Check if running
no-keys status

# Stop a backgrounded proxy
no-keys stop
```

### Background Mode

```bash
# Start in background
no-keys start &

# Or use nohup for persistence
nohup no-keys start > ~/.no-keys/proxy.log 2>&1 &
```

### Health Check

```bash
curl http://127.0.0.1:8119/health
```

Returns:

```json
{
  "status": "ok",
  "uptime_seconds": 3600,
  "requests_total": 142,
  "secrets_redacted": 3
}
```

## Integration with Claude Code

### Option 1: Environment Variables (recommended)

Per the [Claude Code network config docs](https://code.claude.com/docs/en/network-config#proxy-configuration):

```bash
HTTPS_PROXY=http://127.0.0.1:8119 \
NODE_EXTRA_CA_CERTS=~/.no-keys/ca.pem \
claude
```

### Option 2: Shell Alias

Add to `~/.zshrc` or `~/.bashrc`:

```bash
alias claude-safe='HTTPS_PROXY=http://127.0.0.1:8119 NODE_EXTRA_CA_CERTS=~/.no-keys/ca.pem claude'
```

### Option 3: Export in Shell Profile

```bash
# Add to ~/.zshrc or ~/.bashrc
export HTTPS_PROXY=http://127.0.0.1:8119
export NODE_EXTRA_CA_CERTS=~/.no-keys/ca.pem
```

## What Gets Scanned

The proxy intercepts HTTPS CONNECT tunnels and scans these parts of Anthropic Messages API request bodies:

- `messages[].content` (string content)
- `messages[].content[].text` (content blocks)
- `system` (string or content blocks)

Headers (including your API key in `x-api-key` / `Authorization`) are forwarded as-is — they are not scanned or modified.

## The `--log` Flag

Run `no-keys start --log` to see detailed before/after output for every request that contains secrets:

- **Step 1**: the original request content with secrets visible
- **Step 2**: the redacted version actually sent to the API, with placeholders
- **Step 3**: the model's response, plus running stats

Clean requests (no secrets) pass through silently — no log noise.

## Configuration

The proxy uses sensible defaults. All secret patterns are enabled except generic/hex patterns (too noisy). To customize, modify the `RedactionConfig` in `redaction/config.py`:

```python
patterns_config = {
    "openai": {"enabled": True, "log_only": False},
    "anthropic": {"enabled": True, "log_only": False},
    "aws_access_key": {"enabled": True, "log_only": False},
    "github_pat": {"enabled": True, "log_only": False},
    # Set log_only=True to detect without redacting
    "generic_api_key": {"enabled": False, "log_only": True},
}
```

## CA Certificate

On first run, no-keys generates:

- `~/.no-keys/ca.pem` — CA certificate (share with developers, deploy via MDM)
- `~/.no-keys/ca-key.pem` — CA private key (keep secure, 0600 permissions)

Per-host certificates are generated on-the-fly and cached in memory.

## Logging

When a secret is redacted, the proxy logs:

```
12:34:56 [WARNING] REDACTED OPENAI_KEY (len=51) in outbound request
12:34:56 [INFO] POST /v1/messages -> 200 (1 secrets redacted, 342ms)
```

Secret values are never logged — only the type and length.
