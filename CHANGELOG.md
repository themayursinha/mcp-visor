# Changelog

## Unreleased

### Fixed

- Emit standalone JSONL `tool_call_allowed` for plain allow decisions (H14); recover audit hash chain on reopen and fail closed on incomplete/corrupt tails (H11).
- Terminal-only decision audit path: remove premature redaction allow events (H15).
- Reject incomplete TLS client cert/key pairs; split HTTP transport read/write mutexes to avoid SSE/POST deadlock class (H16).
- Atomic policy hot reload of redactor, audit redaction patterns, and approval timeout with engine/registry swap (H17); invalid reloads keep prior runtime surfaces.
- Block notification-form `tools/call` on stdio and remote client paths; shared envelope classification in `internal/mcp/envelope.go` and `internal/proxy/client_envelope.go`.
- Fail closed on recognizable malformed `tools/call` envelopes that include a response `id` (error response, no relay).
- Fail closed on duplicate `method` keys where any value resolves to `tools/call`, preventing parser differential attacks between Go (last-wins) and JavaScript (also last-wins, but first-wins servers also blocked).
- Block JSON-RPC batches containing any `tools/call` element before relay; non-tools batches forward unchanged.
- Apply the same `tools/call` envelope gate to the post-initialize handshake slot on stdio and remote transports.
- Terminate and reap the stdio MCP server when handshake enforcement fails, preventing cleanup from hanging on a child waiting for initialization.

### Documentation

- Reconciled architecture, policy model, threat model, security policy, and public roadmap with the live v1.2 enforcement path.
- Documented SIEM as reduced/plaintext export (H18), not hash-linked audit retention.
- Scoped residual risks: output-only redaction audit, durable approval not default serve path, SIEM TLS/auth still absent.

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
- 15 rule names recognized by the linter; 14 have enforcement cases and `deny_command_pattern_composite` is currently linter-only
- `--json`, `--strict`, `--no-info`, `--no-warnings` output flags
- Detection of invalid regex, unknown rule types, missing required fields
- `deny_command_pattern_composite` is recognized as a known linter name but is not validated or enforced

### Trace Logging (incomplete correction)

- Text, JSONL, and summary formatter types plus `--trace` / `--trace-format` flags exist
- The proxy initializes a trace logger but does not invoke it from handshake, relay, or decision paths; runtime trace output is therefore not a shipped enforcement capability

### Performance Benchmarks

- 26 benchmarks across 5 packages (policy, redaction, audit, mcp, signer)
- Policy evaluation: 587 ns single rule, 2.9 us chain detection
- Argument redaction: 1.8 us with secrets, 579 ns clean
- Audit logging: 2.6 us per event with chaining
- JSON-RPC parsing: 1 us decode, 180 ns encode
- Ed25519 signing: 12.9 us sign, 28.4 us verify
- `make bench` target for one-command benchmark run

### Remote HTTP/SSE Transport (experimental correction)

- HTTP POST + SSE transport implementation; current production evidence is limited to handshake
- `--server-url`, `--sse-path`, `--insecure-tls` CLI flags
- TLS options for client certs, CA pool, and server name verification; incomplete cert/key pairs are not yet rejected
- No verified reconnect behavior; a shared read/write mutex can block post-handshake calls
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
- Documented the current split between 14 enforced rule types and one linter-only composite name

## v1.0.0 (2026-05-25)

### Core

- MCP JSON-RPC 2.0 protocol parser with stdio transport
- Transparent bidirectional proxy with MCP handshake negotiation
- Session tracking with concurrent-safe call history

### Policy Engine

- YAML-based policy schema with validation and defaults
- Initial argument-rule inventory; the current engine enforces 14 rule types listed in `docs/policy-model.md`
- Tool allowlist/denylist with default-deny posture
- Risk classification (critical/high/medium/low) via policy or inference
- Approval requirement detection
- Engine/registry hot-reload via fsnotify with 2-second debounce and atomic swaps; redaction and approval settings remain startup snapshots

### Chain Detection

- Sliding window session tracking (configurable size)
- Regex-based source->sink pattern matching
- Deny or require-approval actions for matched chains
- Audit events with chain context

### Redaction Engine (scope correction)

- Regex-based replacement for configured matches (API keys, tokens, JWTs, connection strings, private-key headers, internal IPs)
- Argument redaction before forwarding to MCP server
- Text-only output redaction for MCP `Content[].Text`; structured data and JSON-RPC error fields are not comprehensive
- Sensitive-file patterns for qualified paths; basename-only matching has known gaps
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
