# Changelog

## Unreleased

### Documentation

- Reconciled architecture, policy model, threat model, security policy, and public roadmap with the live v1.2 enforcement path.
- Scoped audit hash linkage to healthy writes within one logger lifetime and documented incomplete per-call audit coverage.
- Marked remote HTTP+SSE and built-in SIEM export experimental pending Phase 1 security and interoperability gates; earlier release notes overstated production readiness.

## v1.2.0 (2026-07-05)

> Note: This release contains the session-taint egress-control feature from `v2.1.0`, but stays on the `v1.x` line so `go install github.com/themayursinha/mcp-visor/cmd/mcp-visor@v1.2.0` works without a `/v2` module path migration.

### Added

- Session taints for sensitive source tool access.
- Egress controls that deny or approval-gate sink tools after a session is tainted.
- Audit metadata for taint-triggered decisions, including session taints, taint source, taint reason, policy rule, sink, and decision.
- Example policy for session-taint egress control: `examples/policies/session-taint-egress.yaml`.
- Demo-runner scenario for sensitive read → session taint → egress denial.
- Policy documentation for `taints[]` and `egress_controls[]`.

### Changed

- README positioning now includes session-aware egress controls as a core action-boundary capability.
- Policy evaluation order documents stateful egress enforcement **before** tool-chain detection (see `docs/policy-model.md` evaluation order and `internal/proxy/tools_call.go`).

## v2.0.1 (2026-06-30)

### Added

- Prometheus scrape endpoint (`--metrics-addr`, `/metrics`)
- OTLP gRPC export for traces and per-tool-call metrics (`--otel-endpoint`, `--otel-service-name`, `--otel-trace-sample`, `--otel-insecure`)
- OpenTelemetry spans on `mcp.tools/call` with policy attributes only (no tool arguments)
- Shared `processToolsCall` path for stdio and remote transports
- Example lab: `examples/otel-lgtm`
- Runtime evidence bundle under `evidence/runtime/` for paper evaluation reproducibility

### Fixed

- Release workflow: GoReleaser action version `v2.7.6` (404) replaced with `~> v2` ([#21](https://github.com/themayursinha/mcp-visor/pull/21))
- OpenTelemetry SDK bumped to v1.40.0 (GO-2026-4394)
- CI `govulncheck` bumped to v1.5.0 (panic on Go 1.26.4)
- Supply-chain workflow govulncheck version alignment
- Gitleaks allowlist for redaction test fixtures (no real secrets)

### Changed

- README: research and blog links, roadmap clarity, public positioning sections
- `.gitignore` hardened (secrets, private notes, build artifacts, OS junk)
- Pre-commit hook blocks sensitive filenames and private keys before commit
- Removed tracked `dist/` binaries, `.DS_Store`, and stray `v2` file from the repo

## v1.1.0 (2026-05-27)

### Policy Linting

- Policy validation CLI (`mcp-visor lint`) for static analysis of policy YAML
- 16 known rule type validators with severity classification
- `--json`, `--strict`, `--no-info`, `--no-warnings` output flags
- Detection of invalid regex, unknown rule types, missing required fields
- Composite command pattern validation

### Trace Logging

- MCP message-level tracing with pluggable formatters
- Text format (human-readable directional output: C->S, S->C, INT)
- JSONL format for machine processing
- Summary format with message counters
- `--trace` and `--trace-format` CLI flags
- Configurable granularity (handshake, decisions, redactions, chains)

### Performance Benchmarks

- 26 benchmarks across 5 packages (policy, redaction, audit, mcp, signer)
- Policy evaluation: 587 ns single rule, 2.9 us chain detection
- Argument redaction: 1.8 us with secrets, 579 ns clean
- Audit logging: 2.6 us per event with chaining
- JSON-RPC parsing: 1 us decode, 180 ns encode
- Ed25519 signing: 12.9 us sign, 28.4 us verify
- `make bench` target for one-command benchmark run

### Remote HTTP/SSE Transport

- Proxying remote MCP servers over HTTP with SSE event streaming
- `--server-url`, `--sse-path`, `--insecure-tls` CLI flags
- Full TLS/mTLS support with client certs, CA pool, and server name verification
- SSE connection management with reconnect and timeout guards
- Mock transport with `ServeMCP()` HTTP handler for testing
- Backward compatible: stdio transport unchanged, auto-detected from config

### Vault Transit Integration

- HashiCorp Vault Transit secrets engine integration for cryptographic signing
- `TransitSigner` implementing `signer.Signer` interface
- `TransitVerifier` implementing `signer.Verifier` interface
- `--vault-addr`, `--vault-token`, `--vault-key-name`, `--vault-namespace`, `--vault-ca-cert`, `--vault-skip-verify` CLI flags
- Vault health check endpoint integration
- Public key retrieval from Vault Transit key metadata
- Ed25519 signature verification through Vault Transit verify endpoint

### Integration Tests

- End-to-end tests for sensitive file access denial, audit log redaction, unknown tool denial
- Remote transport handshake test with mock HTTP+SSE server
- Chain detection tests (exfiltration, no-match, database-to-slack, audit events)
- Multiple tool call sequencing tests
- Tools list and allowed file access verification tests

### Documentation

- Updated CLI reference with all 20+ flags
- Updated architecture diagram with v2 components
- Feature documentation for tracing, benchmarks, remote transport, and Vault integration
- Policy linting CLI reference
- Corrected argument rule type count from 11 to 16

## v1.0.0 (2026-05-25)

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
- Policy hot-reload via fsnotify with 2-second debounce and atomic swaps

### Chain Detection

- Sliding window session tracking (configurable size)
- Regex-based source->sink pattern matching
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
- Makefile with build, test, vet, demo, fmt, clean, coverage targets

### Documentation

- Comprehensive README with architecture diagram, quickstart, and feature overview
- Architecture documentation with component diagrams and decision pipeline
- Policy model reference with full YAML schema documentation
- STRIDE threat model with attack scenarios and hardening guide
- Comparison guide with mcp-llm-security-evaluator
- Contributing guide, security policy, and CHANGELOG

### Infrastructure

- GitHub Actions CI: build, test, vet, golangci-lint, gosec, govulncheck
- GoReleaser for cross-platform binary releases (linux/darwin, amd64/arm64)
- Multi-stage Docker image (Alpine, ~5 MB) pushed to ghcr.io
- Pre-commit hook for go vet + govulncheck + go mod tidy
- 74 tests covering all components
