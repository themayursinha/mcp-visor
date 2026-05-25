# Changelog

## v1.0.0 (unreleased)

### Core

- MCP JSON-RPC 2.0 protocol parser with stdio transport
- Transparent bidirectional proxy with MCP handshake negotiation
- Session tracking with concurrent-safe call history

### Policy Engine

- YAML-based policy schema with validation and defaults
- 11 argument rule types: deny_path, allow_path, deny_command_pattern, allow_command_pattern, deny_query_pattern, allow_query_pattern, allowed_repos, deny_recipient_domain, allow_recipient_domain, max_file_size, max_rows
- Tool allowlist/denylist with default-deny posture
- Risk classification (critical/high/medium/low) via policy or inference
- Approval requirement detection

### Chain Detection

- Sliding window session tracking (configurable size)
- Regex-based source→sink pattern matching
- Deny or require-approval actions for matched chains
- Audit events with chain context

### Redaction Engine

- Regex-based secret stripping (API keys, tokens, JWTs, connection strings, private keys, internal IPs)
- Argument redaction before forwarding to MCP server
- Output redaction before returning to client
- Sensitive file blocking (.env, credentials, .pem, .key, .ssh)
- Deep map and array scanning for nested secrets

### Audit Logging

- JSONL format with O_SYNC writes
- 7 event types with redacted data
- Session lifecycle tracking
- Configurable output path

### Approval Workflow

- File-based approval engine
- Request files with full context
- Configurable timeout with fail-closed default
- Automatic cleanup of request/response files

### Developer Experience

- `--demo` flag for zero-config demo mode
- `version` subcommand with build metadata
- Interactive demo runner (`examples/demo-runner/`)
- Mock MCP server (`examples/demo-mcp-server/`)
- Example policies and malicious prompt scenarios
- Makefile with build, test, vet, demo, fmt, clean targets

### Infrastructure

- GitHub Actions CI: build, test, vet, golangci-lint, gosec, govulncheck
- GoReleaser for cross-platform binary releases
- Multi-stage Docker image (Alpine, ~5 MB)
- 68 tests covering all components
