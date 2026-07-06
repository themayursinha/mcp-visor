# MCP Visor

**Deterministic authorization for MCP tool calls.**

MCP Visor is a self-hosted policy enforcement proxy for AI agents. It sits between an agent and MCP servers, evaluates every `tools/call` before execution, and enforces allow, deny, approval, redaction, chain, and session-taint rules without an LLM in the decision path. It is not prompt filtering, output moderation, or system-prompt hardening.

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

Every tool call is evaluated before execution. Unknown tools fail closed. Sensitive arguments can be redacted. Dangerous chains can be denied. High-risk actions can require human approval. Audit logs record what happened and why.

## Install

```bash
go install github.com/themayursinha/mcp-visor/cmd/mcp-visor@latest
```

Pre-built binaries and checksums are available on the [Releases](https://github.com/themayursinha/mcp-visor/releases) page.

## Quick start

```bash
# Run the built-in demo proxy
mcp-visor serve --demo

# Validate a policy before using it
mcp-visor lint examples/policies/session-taint-egress.yaml

# Proxy a real MCP server through a policy boundary
mcp-visor serve -server <your-mcp-server> -policy policy.yaml
```

Two-minute action-boundary demo: `go run ./examples/demo-runner` · [walkthrough](docs/action-boundary-demo.md)

## What it protects against

- Secret reads followed by outbound exfiltration
- Access to `.env`, SSH keys, kubeconfigs, credentials, and private keys
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
| Secret redaction | Remove API keys, tokens, JWTs, and private keys from arguments and outputs |
| Tool-chain detection | Block dangerous sequences such as read → exfiltrate |
| Session taints | Change later authorization decisions after sensitive context is touched |
| Human approval | Gate critical tools before execution |
| Audit log | Hash-chained JSONL evidence for every decision |
| Policy linting | Validate YAML policy before deployment |

Advanced capabilities include signed decision receipts, Vault Transit signing, HTTP+SSE remote transport with mTLS, webhooks, SIEM export, Prometheus metrics, OTLP tracing, and a local web dashboard. See [`docs/complexity-budget.md`](docs/complexity-budget.md) for feature tiering.

## Security model

- **Deterministic:** no LLM in the allow/deny path
- **Fail closed:** unknown tools are denied by default
- **Layered:** redaction → policy → chain detection → session taints → approval → audit
- **Observable:** decisions are recorded in hash-chained JSONL audit logs
- **Self-hosted:** single Go binary; no SaaS dependency required
- **Operator-controlled:** optional telemetry exports to your Prometheus, OTLP, webhook, or SIEM stack

## CLI

```text
mcp-visor serve [flags]    Run the proxy
mcp-visor lint <policy>    Validate a policy file
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
- [x] v1.1: Identity/time policies, hot-reload, CLI approval, remote transport
- [x] v1.2: Session taints and egress controls
- [ ] v1.3: Polished demo flows and stronger policy receipts
- [ ] Future: sandboxing, richer telemetry, optional policy engines

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Run `harness/check.sh` before PRs.

## License
MIT — see [LICENSE](LICENSE)
