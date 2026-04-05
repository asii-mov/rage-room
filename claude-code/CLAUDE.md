# Org Coding Standards

## Security

- Never commit secrets, API keys, passwords, or tokens to source control
- Do not read or modify `.env`, credential files, or private keys
- Do not use `--force` or `--no-verify` on git operations without explicit approval
- Avoid introducing OWASP Top 10 vulnerabilities (injection, XSS, SSRF, etc.)
- Do not log or print sensitive data (PII, credentials, session tokens)
- Use the no-keys secret redaction middleware when building AI-facing APIs

## Code Quality

- Write clear, minimal code — avoid over-engineering
- Follow existing patterns and conventions in the codebase
- Add tests for new functionality
- Keep PRs focused — one concern per change

## Supply Chain

- Pin all dependencies to exact versions
- Use hash-verified lockfiles where supported
- Do not add dependencies without team review

## PII Handling

- Do not store PII in logs, comments, or test fixtures
- Use placeholder/mock data in examples and tests
- Flag any code that processes PII for review
