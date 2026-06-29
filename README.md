```
___  ________ ______   _   _ _____ _____  ___________ 
|  \/  /  __ \| ___ \ | | | |_   _/  ___||  _  | ___ \
| .  . | /  \/| |_/ / | | | | | | \ `--. | | | | |_/ /
| |\/| | |    |  __/  | | | | | |  `--. \| | | |    / 
| |  | | \__/\| |     \ \_/ /_| |_/\__/ /\ \_/ / |\ \ 
\_|  |_/\____/\_|      \___/ \___/\____/  \___/\_| \_|
```

Runtime Policy Enforcement & Audit Control Plane for MCP Tool Execution

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/themayursinha/mcp-visor/actions/workflows/ci.yml/badge.svg)](https://github.com/themayursinha/mcp-visor/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/themayursinha/mcp-visor)](https://goreportcard.com/report/github.com/themayursinha/mcp-visor)
[![Release](https://img.shields.io/github/v/release/themayursinha/mcp-visor?color=34d399)](https://github.com/themayursinha/mcp-visor/releases)

> *"The model is persuadable. Policy enforcement shouldn't be."*

**Research & writing**

| | Link |
|---|------|
| **Paper** | [MCP Visor: Deterministic Runtime Enforcement for Governing Tool-Using AI Agents](https://www.researchgate.net/publication/407908047_MCP_Visor_Deterministic_Runtime_Enforcement_for_Governing_Tool-Using_AI_Agents) (ResearchGate) |
| **Blog** | [Runtime policy enforcement for AI agents](https://themayursinha.com/architecture/2026/05/25/mcp-visor-runtime-policy-enforcement-for-ai-agents/) · [Spec engineering](https://themayursinha.com/architecture/2026/06/27/spec-engineering-the-missing-layer-in-ai-agent-security/) · [Three trust paths](https://themayursinha.com/architecture/2026/06/15/three-trust-paths-for-governing-ai-agent-architectures/) · [MCP supply-chain risk](https://themayursinha.com/architecture/2026/05/06/mcp-security-the-new-supply-chain-risk-for-ai-agents/) |
| **Author** | [themayursinha.com](https://themayursinha.com) |

---

## Quick Stats

| Metric | Value |
|--------|-------|
| **Policy evaluation** | 587 ns |
| **Chain detection** | 2.9 µs |
| **Redaction** | 1.8 µs |
| **JSON-RPC decode** | 1 µs |
| **Binary size** | ~7 MB |
| **Dependencies** | 2 (fsnotify + yaml.v3) |
| **Test coverage** | 15 packages, all passing |

---

## Problem

Autonomous AI agents are increasingly granted execution authority over critical infrastructure via MCP. They can modify cloud states, execute raw shell commands, manipulate databases, and interact with systemic APIs. However, AI agents are non-deterministic, probabilistic engines highly vulnerable to adversarial coercion (prompt injection) and execution drift. 

**~492 MCP servers** have been found exposed on the internet with zero authentication. Tool poisoning — where a malicious server hides instructions inside tool descriptions — is the #1 attack vector, documented by OWASP, NIST, and multiple academic papers. Prompt-based guardrails are provably unreliable — the "Prompts Don't Protect" paper demonstrated 0% unauthorized invocation prevention.

**MCP Visor** is a fail-closed runtime containment primitive. It sits directly between the agent and the system interface, enforcing mathematically deterministic policy **before** payload execution. It does not use an LLM to make decisions. It cannot be bypassed via prompt injection.

> *"The model is persuadable. Policy enforcement shouldn't be."*

## How It Works

```
AI Agent → mcp-visor proxy → policy decision → allow/deny/approve/redact → MCP server
```

Every `tools/call` is intercepted and evaluated:

1. **Redact** — Strip secrets (API keys, tokens, passwords) from arguments
2. **Block** — Deny access to sensitive files (.env, credentials, .ssh)
3. **Check** — Validate against allowlists, denylists, and argument rules
4. **Detect** — Identify dangerous tool chains (read → send)
5. **Approve** — Hold high-risk calls for human confirmation
6. **Log** — Record every decision in a redacted, structured audit trail

## Quick Start

```bash
# Install
go install github.com/themayursinha/mcp-visor/cmd/mcp-visor@latest

# Run with a demo server (60 seconds to first enforcement)
mcp-visor serve --demo

# Or download a pre-built binary from the releases page:
# https://github.com/themayursinha/mcp-visor/releases
```

## Why MCP Visor vs Alternatives

| | MCP Visor | Runlayer | Microsoft Toolkit | Obot AI |
|---|-----------|----------|-------------------|--------|
| **Enforcement** | Deterministic (policy engine) | LLM-as-a-judge | Deterministic (policy) | LLM-based scanning |
| **MCP-aware** | ✅ Protocol-native proxy | ✅ Gateway | ✅ Toolkit | ✅ |
| **Self-hosted** | ✅ Single Go binary | ❌ SaaS only | ✅ TypeScript | ❌ SaaS |
| **Open-source** | ✅ MIT | ❌ Proprietary | ✅ MIT | ❌ Proprietary |
| **Chain detection** | ✅ Sliding window | ❌ | ✅ | ❌ |
| **Secret redaction** | ✅ In/out | ✅ | ❌ | ❌ |
| **SIEM export** | ✅ Syslog/CEF/JSON | ✅ | ❌ | ❌ |
| **Vault/KMS signing** | ✅ HashiCorp Vault | ❌ | ❌ | ❌ |
| **Webhook approvals** | ✅ Slack/Teams/n8n | ✅ | ✅ HITL quorum | ❌ |

**Unique wedge:** The only open-source, deterministic, MCP-native enforcement proxy that ships as a single binary, supports Vault-backed cryptographic signing, and exports to enterprise SIEM — without a SaaS subscription.

## Who Is This For

- **Security teams** hardening AI agent deployments — add an enforcement layer between agents and tools
- **Platform engineers** running MCP infrastructure — audit, policy, and governance for tool access
- **Compliance officers** needing agent audit trails — JSONL logs with hash-chained integrity + SIEM export
- **MCP developers** who want to test their servers safely — proxy with deny-by-default, redact secrets

## Architecture

```
┌──────────────┐     ┌────────────────────────────────────────────────┐     ┌──────────────┐
│  AI Agent    │────▶│                  mcp-visor                      │────▶│  MCP Server  │
│  (MCP Client)│     │                                                  │     │  (Tools)     │
└──────────────┘     │  ┌─────────┐  ┌──────────┐  ┌──────────────┐   │     └──────────────┘
                      │  │Redaction│  │  Policy  │  │    Chain     │   │
                      │  │ Engine  │  │  Engine  │  │  Detector    │   │
                      │  └─────────┘  └──────────┘  └──────────────┘   │
                      │                                                  │
                      │  ┌─────────┐  ┌──────────┐  ┌──────────────┐   │
                      │  │Approval │  │  Audit   │  │    Trace     │   │
                      │  │ Engine  │  │  Logger  │  │   Logger     │   │
                      │  └─────────┘  └──────────┘  └──────────────┘   │
                      │                                                  │
                      │  ┌─────────┐  ┌──────────┐  ┌──────────────┐   │
                      │  │Vault    │  │ Webhook  │  │    SIEM      │   │
                      │  │ Signer  │  │ Emitter  │  │  Exporter    │   │
                      │  └─────────┘  └──────────┘  └──────────────┘   │
                      │                                                  │
                      │  Transport: stdio (local) or HTTP+SSE (remote)   │
                      └────────────────────────────────────────────────┘
```

## Policy Model

Policies are YAML files that define exactly which tools are allowed, under what conditions.

```yaml
version: "1.0"
default_action: deny   # deny everything by default

servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
        rules:
          - type: deny_path
            patterns:
              - "/etc/passwd"
              - "**/.env"
              - "**/*.pem"
          - type: allow_path
            patterns:
              - "/home/**"
              - "/tmp/**"

      - name: "shell_exec"
        allowed: true
        risk: critical
        approval_required: true
        rules:
          - type: deny_command_pattern
            patterns:
              - "bash\\s+-i\\s+>&"
              - "rm\\s+-rf\\s+/"

  - name: "slack"
    allowed: true
    tools:
      - name: "slack_send_message"
        allowed: true
        risk: high
        approval_required: true

# Block read → send chains
tool_chains:
  - name: "prevent_exfiltration"
    sources:
      - server: "*"
        tool_pattern: "file_read"
    sinks:
      - server: "*"
        tool_pattern: "(http_post|slack_send_message)"
    action: deny
    within_calls: 3
```

See [examples/policies/](examples/policies/) for more examples.

## Features

### Policy Enforcement
- Tool allowlist/denylist with default-deny
- 16 argument rule types: deny_path, allow_path, deny_command_pattern, allow_command_pattern, deny_command_keyword, deny_command_pattern_composite, deny_query_pattern, allow_query_pattern, allowed_repos, deny_recipient_domain, allow_recipient_domain, max_file_size, max_result_rows, max_export_rows, require_approval_always
- Risk classification (critical/high/medium/low)
- Identity-based access control per agent
- Time-based access restrictions (business hours, denied days)
- Policy hot-reload with fsnotify watcher

### Policy Linting
- `mcp-visor lint` CLI for static validation of policy YAML
- Detects invalid regex patterns, unknown rule types, missing required fields
- Severity-classified output (error/warning/info)
- `--json`, `--strict`, `--no-info`, `--no-warnings` output options
- Composite command pattern validation

### Chain Detection
- Detects dangerous tool sequences: read → send, query → post
- Configurable sliding window
- Deny or require approval for matched chains
- Session-level tracking

### Redaction
- Strips API keys (`sk-...`), tokens (`ghp_...`), JWTs, connection strings, private keys, internal IPs
- Redacts arguments before forwarding to server
- Redacts outputs before returning to client
- Blocks access to sensitive files (.env, .ssh, credentials, .pem, .key)

### Approval Workflow
- File-based: write `req-<id>.json`, approver creates `req-<id>.ok` to approve
- CLI-based: interactive yes/no prompt on terminal
- Configurable timeout with fail-closed default
- Full audit trail for approval decisions

### Durable Approval (v2)
- Signed Decision Receipts with ed25519 signatures
- Execution IDs with nonce and expiry for replay protection
- Durable retry: persist pending approvals, agent retries with signed receipt
- Pluggable signer interface (built-in ed25519, Vault Transit/KMS ready)

### Webhook Event Emitter (v2)
- Async HTTP delivery of audit and approval events
- HMAC-SHA256 signatures for payload authenticity
- Configurable retry with exponential backoff

### Audit Logging
- JSONL format with redacted data
- 8 event types: tool_call_allowed, tool_call_denied, tool_call_chain_detected, tool_call_approval_required, session_started, session_ended, policy_loaded, policy_reloaded
- Hash-chained entries (SHA-256) for tamper evidence
- O_SYNC writes for durability

### SIEM Export (v2)
- RFC 5424 syslog format
- JSON envelope format for Splunk/Elastic
- CEF (Common Event Format)
- Pluggable writers: file, TCP, UDP

### HTTP/SSE Transport (v2)
- Connect to remote MCP servers over HTTP
- Server-Sent Events (SSE) for server-to-client streaming
- Configurable mTLS support
- Mock transport for testing

### n8n Control Plane Blueprint (v2)
- Ready-to-import n8n workflow for Slack/Teams approval
- SIEM forwarding integration
- Audit database storage (PostgreSQL)

### Trace Logging (v1.1)
- MCP message-level tracing for debugging and forensics
- Three output formats: text (directional C->S/S->C), JSONL (machine-readable), summary (counters)
- Configurable via `--trace` and `--trace-format` CLI flags
- Granular control: handshake, decisions, redactions, chain detections

### Vault Transit Integration (v1.1)
- Cryptographic signing backed by HashiCorp Vault Transit secrets engine
- `TransitSigner` and `TransitVerifier` implementing pluggable signer interfaces
- Configurable via `--vault-addr`, `--vault-token`, `--vault-key-name` CLI flags
- TLS/mTLS support with CA cert and skip-verify options
- Namespace support for Vault Enterprise

### Performance Benchmarks (v1.1)
- 26 benchmarks across 5 hot-path packages
- Policy evaluation: 587 ns, chain detection: 2.9 us, redaction: 1.8 us
- JSON-RPC decode: 1 us, encode: 180 ns
- Ed25519 signing: 12.9 us, verification: 28.4 us
- `make bench` target for one-command benchmark run

### Observability export (v1.2)
- Prometheus `/metrics` from live `ProxyMetrics` (`--metrics-addr`)
- OTLP gRPC traces + tool-call metrics (`--otel-endpoint`); pairs with Grafana LGTM / Tempo / Mimir
- Span model: `mcp.tools/call` with `policy.decision`, `tool.name`, `session.id` (no argument payloads)
- Local lab: [`examples/otel-lgtm`](examples/otel-lgtm/README.md)

## Comparison with mcp-llm-security-evaluator

| | mcp-llm-security-evaluator | mcp-visor |
|---|---|---|
| Purpose | Evaluates LLM security | Enforces tool execution |
| When | CI/CD, on-demand scans | Every tool call at runtime |
| Output | Reports, scores, findings | Allow/deny/approve, audit logs |
| LLM | Tests LLM responses | No LLM interaction |
| MCP | Simulated mock calls | Real MCP protocol proxy |

**Evaluator tells you what can go wrong. Visor stops it at runtime.**

See [mcp-llm-security-evaluator](https://github.com/themayursinha/mcp-llm-security-evaluator)

## CLI Reference

```
mcp-visor serve [flags]
mcp-visor lint [flags] <policy-file>
mcp-visor version

Serve flags:
  -server string          MCP server command to proxy (local stdio)
  -server-name string     Logical server name for policy matching
  -server-arg value       Argument for the MCP server command (repeatable)
  -server-url string      Remote MCP server URL (enables HTTP+SSE transport)
  -sse-path string        SSE endpoint path (default: /sse)
  -insecure-tls           Skip TLS certificate verification for remote servers
  -remote-cert string     Client certificate file for remote MCP mTLS
  -remote-key string      Client private key file for remote MCP mTLS
  -remote-ca string       CA certificate file for remote MCP TLS verification
  -remote-server-name string
                           Expected TLS server name for remote MCP server
  -policy string          Path to policy YAML file (default: built-in deny-all)
  -audit-log string       Path to JSONL audit log file (default: stderr)
  -webhook-url value      Webhook endpoint for audit/approval events (repeatable)
  -webhook-hmac-secret string
                           HMAC secret used to sign webhook payloads
  -siem-target value      SIEM export target: file path, tcp:host:port, or udp:host:port (repeatable)
  -siem-format string     SIEM export format: json, syslog-rfc5424, cef (default: json)
  -approval-dir string    Directory for file-based approval workflow
  -approval-cli           Use interactive CLI prompt for approval
  -approval-signing-key string
                           Ed25519 private key PEM file for signing approval receipts (default: ephemeral key)
  -session-id string      Session identifier
  -client-id string       Client identifier
  -demo                   Start with built-in mock server and permissive policy
  -trace                  Enable MCP message tracing
  -trace-format string    Trace output format: text, jsonl, summary (default: text)
  -log-level string       Log level: debug, info, warn, error (default: info)
  -vault-addr string      Vault server address for Transit signing
  -vault-token string     Vault authentication token
  -vault-key-name string  Vault Transit key name (default: mcp-visor-approval)
  -vault-namespace string Vault namespace (Enterprise)
  -vault-ca-cert string   Vault CA certificate file
  -vault-skip-verify      Skip Vault TLS verification
  -metrics-addr string    Prometheus /metrics listen address (e.g. 127.0.0.1:9091)
  -otel-endpoint string   OTLP gRPC endpoint (e.g. localhost:4317)
  -otel-insecure          Insecure OTLP gRPC (default true, for local LGTM)
  -otel-service-name string
                          OpenTelemetry service.name (default mcp-visor)
  -otel-trace-sample float
                          Trace sampling ratio 0..1 when OTLP enabled (default 1)

Lint flags:
  -json                   Output in JSON format
  -strict                 Treat warnings as errors
  -no-info                Hide info-level findings
  -no-warnings            Hide warning-level findings
```

## Development

```bash
# Build
go build ./cmd/mcp-visor/

# Test
go test ./...

# Benchmark
make bench

# Vet
go vet ./...

# Run demo
go run ./examples/demo-runner/

# Lint a policy
go run ./cmd/mcp-visor lint examples/policies/developer-medium.yaml
```

## Roadmap

- [x] v1.0: MCP proxy, policy engine, audit logging, chain detection, redaction, approval
- [x] v1.1: Identity-based policies, time-based restrictions, CLI approval, policy hot-reload
- [x] v2.0: Signed decision receipts, webhook approvals, hash-chained audit logs, mTLS, SIEM export, HTTP/SSE transport, durable retry approval, n8n control-plane blueprint
- [ ] v3.0: Sandboxed tool execution (WASI), eBPF syscall telemetry, web-based policy dashboard, OPA/Rego policy support
- [ ] v4.0: Deeper host-level enforcement, formal policy verification, multi-agent policy federation

## Security Model

- **Deterministic** — No LLM in the decision path
- **Fail-closed** — Unknown tools denied by default
- **Layered** — Redaction → Policy → Chain → Approval
- **Observable** — Every decision logged with hash-chained integrity
- **Minimal TCB** — Single Go binary, minimal dependencies
- **Tamper-evident** — Signed approval receipts, bound evidence hashes, chained audit hashes

## Limitations

- Relies on host filesystem security for policy file integrity
- Approval webhooks use HMAC; full mTLS between visor and control plane is optional
- Session state is ephemeral (lost on restart); signed approval receipts bind approved calls to request, policy, argument, and chain-context hashes
- Single-agent, single-server deployment model
- No web-based approval dashboard (n8n blueprint provides Slack/Teams path)

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Areas needing work: web-based approval dashboard, Vault/KMS live integration, additional MCP server integrations, WASI sandboxing.

## License

MIT — see [LICENSE](LICENSE)
