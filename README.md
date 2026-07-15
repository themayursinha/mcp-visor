# MCP Visor

**Deterministic authorization for MCP tool calls.**

MCP Visor is a self-hosted policy enforcement proxy for AI agents. It evaluates valid JSON-RPC `tools/call` requests that include an `id` before relay and applies allow, deny, approval, redaction, chain, and session-taint rules without an LLM. Notification-form `tools/call` (no `id`), duplicate `method` keys, and JSON-RPC batches containing `tools/call` are blocked at the proxy; recognizable malformed `tools/call` attempts with an `id` fail closed without relay.

> **MCP Visor is not a model guardrail. It is an action boundary.**
> Models can request actions. MCP Visor decides whether those actions are allowed.

Model guardrails try to shape what the model says or thinks inside the context window. MCP Visor controls what the agent is allowed to do after a tool call is requested. System prompts can describe intended behavior; MCP Visor enforces policy outside the model.

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/themayursinha/mcp-visor/actions/workflows/ci.yml/badge.svg)](https://github.com/themayursinha/mcp-visor/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/themayursinha/mcp-visor?color=34d399)](https://github.com/themayursinha/mcp-visor/releases)

**Paper:** [MCP Visor: Deterministic Runtime Enforcement](https://www.researchgate.net/publication/407908047) · **Writing:** [Spec engineering](https://themayursinha.com/architecture/2026/06/27/spec-engineering-the-missing-layer-in-ai-agent-security/) · [Runtime policy enforcement](https://themayursinha.com/architecture/2026/05/25/mcp-visor-runtime-policy-enforcement-for-ai-agents/)

---

## Why MCP Visor exists

AI agents can now read files, call APIs, run commands, query databases, and modify infrastructure through MCP tools. Prompt-only controls are useful guidance, but they are not an execution boundary.

MCP Visor adds that boundary at the MCP `tools/call` layer:

```text
AI agent → MCP Visor → policy decision → MCP server
```

Valid `tools/call` requests with IDs are evaluated before relay. Notification-form `tools/call` is dropped without response; duplicate `method` keys and JSON-RPC batches containing `tools/call` are blocked before relay. Non-tools MCP notifications and batches still forward unchanged.

## Install

```bash
go install github.com/themayursinha/mcp-visor/cmd/mcp-visor@latest
```

Pre-built binaries and checksums are available on the [Releases](https://github.com/themayursinha/mcp-visor/releases) page.

## Quick start

```bash
# Run the built-in demo proxy
mcp-visor serve --demo

# Supplemental lint. Do not combine --strict with --no-warnings.
# This is not yet a complete fail-closed policy gate; see the threat model.
mcp-visor lint --strict examples/policies/session-taint-egress.yaml

# Proxy a real MCP server through a policy boundary
mcp-visor serve -server <your-mcp-server> -policy policy.yaml
```

Two-minute action-boundary demo: `go run ./examples/demo-runner` · [walkthrough](docs/action-boundary-demo.md)

## What it protects against

- Secret reads followed by outbound exfiltration
- Access to configured sensitive paths such as `/project/.env`, SSH keys, kubeconfigs, credentials, and key files; basename-only and policy-`uri` gaps are documented in the threat model
- Unsafe shell commands and command-injection patterns
- Unknown or newly introduced tools under default-deny policy
- High-risk actions without human approval
- Tool sequences that look safe individually but become dangerous together

## Session-taint egress control

MCP Visor tracks session state, not just individual calls.

```text
file_read("/customer-secrets/tokens.csv")
  → session tainted: sensitive_file_accessed
  → http_post(...) denied by block_sensitive_egress
  → audit log records source, taint, policy rule, sink, and decision
```

Example policy:

```yaml
taints:
  - name: "sensitive_file_accessed"
    source_tools: ["file_read"]
    source_patterns: ["**/customer-secrets/**"]

egress_controls:
  - name: "block_sensitive_egress"
    when_tainted: "sensitive_file_accessed"
    sink_tools: ["http_post", "slack_send_message"]
    action: deny
```

Full example: [`examples/policies/session-taint-egress.yaml`](examples/policies/session-taint-egress.yaml)

## Policy example

```yaml
version: "1.0"
default_action: deny

servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        rules:
          - type: deny_path
            patterns: ["**/.env", "**/*.pem", "/etc/passwd"]
          - type: allow_path
            patterns: ["/home/**", "/tmp/**"]

  - name: "shell_exec"
    allowed: true
    risk: critical
    approval_required: true
    rules:
      - type: deny_command_pattern
        patterns: ["bash\\s+-i\\s+>&", "rm\\s+-rf\\s+/"]

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

More policies: [`examples/policies/`](examples/policies/) · Schema reference: [`docs/policy-model.md`](docs/policy-model.md)

## Core capabilities

| Capability | Purpose |
|------------|---------|
| Default-deny policy | Unknown servers and tools fail closed |
| Argument rules | Restrict paths, commands, queries, recipients, sizes, and repos |
| Pattern redaction | Replace configured matches in arguments and textual `Content[].Text` output; this is not full structured-payload or complete private-key sanitization |
| Tool-chain detection | Block dangerous sequences such as read → exfiltrate |
| Session taints | Change later authorization decisions after sensitive context is touched |
| Human approval | Gate critical tools before execution |
| Audit log | Selected security and session events, hash-linked within one healthy logger lifetime |
| Policy linting | Validate YAML policy before deployment |

Advanced capabilities include signed decision receipts, Vault Transit signing, webhooks, and experimental remote transport, SIEM, metrics/OTLP, and local dashboard surfaces. The `--trace` formatters are not yet connected to runtime message paths. See [`docs/complexity-budget.md`](docs/complexity-budget.md) and [`docs/threat-model.md`](docs/threat-model.md).

## Security model

- **Deterministic:** no LLM in the allow/deny path
- **Fail closed:** unknown tools are denied by default
- **Layered:** redaction → policy → taint-aware egress → chain detection → approval → post-allow taint marking
- **Observable:** selected security events are recorded in JSONL; this is not yet a complete per-call ledger or a chain that survives sink failure/reopen
- **Self-hosted:** single Go binary; no SaaS dependency required
- **Operator-controlled:** optional telemetry exports to your Prometheus, OTLP, webhook, or SIEM stack

## CLI

```text
mcp-visor serve [flags]    Run the proxy
mcp-visor lint [--strict] <policy>  Supplemental policy validation; not a complete fail-closed gate
mcp-visor version          Print version
```

Common flags: `-server`, `-policy`, `-audit-log`, `-approval-dir`, `-approval-cli`, `-demo`

Advanced flags: `-server-url`, `-webhook-url`, `-siem-target`, `-vault-addr`, `-metrics-addr`, `-otel-endpoint`, `-dashboard`, `-trace`

Full reference: `mcp-visor serve -h`

## Documentation

[Architecture](docs/architecture.md) · [Policy model](docs/policy-model.md) · [Threat model](docs/threat-model.md) · [Complexity budget](docs/complexity-budget.md) · [Harness](harness/README.md)

## Development

```bash
go build ./cmd/mcp-visor/      # build
go test ./...                  # test
harness/check.sh               # fmt + vet + test + evidence manifest
make bench                     # benchmarks
```

## Roadmap

- [x] v1.0: Proxy, policy engine, redaction, approval, audit, chain detection
- [x] v1.1: Identity/time policies, partial engine hot-reload, CLI approval, experimental remote transport
- [x] v1.2: Session taints and egress controls
- [ ] v1.3: Documentation truth, security verification, interoperability evidence, and release hardening
- [ ] Future: sandboxing, richer telemetry, optional policy engines

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Run `harness/check.sh` before PRs.

## License
MIT — see [LICENSE](LICENSE)
