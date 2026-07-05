```
___  ________ ______   _   _ _____ _____  ___________ 
|  \/  /  __ \| ___ \ | | | |_   _/  ___||  _  | ___ \
| .  . | /  \/| |_/ / | | | | | | \ `--. | | | | |_/ /
| |\/| | |    |  __/  | | | | | |  `--. \| | | |    / 
|  | | \__/\| |     \ \_/ /_| |_/\__/ /\ \_/ / |\ \ 
\_|  |_/\____/\_|      \___/ \___/\____/  \___/\_| \_|
```

Runtime policy enforcement for MCP tool calls. Deterministic. No LLM in the decision path.

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/themayursinha/mcp-visor/actions/workflows/ci.yml/badge.svg)](https://github.com/themayursinha/mcp-visor/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/themayursinha/mcp-visor?color=34d399)](https://github.com/themayursinha/mcp-visor/releases)

> *"The model is persuadable. Policy enforcement shouldn't be."*

**Paper:** [MCP Visor: Deterministic Runtime Enforcement](https://www.researchgate.net/publication/407908047) · **Blog:** [Spec engineering](https://themayursinha.com/architecture/2026/06/27/spec-engineering-the-missing-layer-in-ai-agent-security/) · [Runtime policy enforcement](https://themayursinha.com/architecture/2026/05/25/mcp-visor-runtime-policy-enforcement-for-ai-agents/)

---

## Install

```bash
go install github.com/themayursinha/mcp-visor/cmd/mcp-visor@latest
```

Pre-built binaries: [Releases](https://github.com/themayursinha/mcp-visor/releases).

## Quick start

```bash
# Try it with a built-in mock server
mcp-visor serve --demo

# Point your agent at the visor instead of the raw server
mcp-visor serve -server <your-mcp-server> -policy policy.yaml

# Validate a policy file
mcp-visor lint examples/policies/developer-medium.yaml
```

---

## Why

AI agents with MCP tool access can execute shell commands, read files, call APIs, and modify infrastructure. Prompt-based guardrails don't work — the "Prompts Don't Protect" paper showed 0% prevention of unauthorized tool calls. ~492 MCP servers were found exposed with zero authentication.

MCP Visor sits between the agent and the MCP server. Every `tools/call` is intercepted and evaluated against YAML policy **before** execution. No LLM in the decision path. No persuasion surface. Default deny.

```
AI Agent → mcp-visor → policy decision (allow/deny/approve/redact) → MCP server
```

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

More: [examples/policies/](examples/policies/)

## Features

**Core** (default enforcement path, no extra flags):

- Default-deny tool allowlist/denylist
- 16 argument rule types (path patterns, command patterns, query patterns, size limits, etc.)
- Secret redaction (API keys, tokens, JWTs, private keys) in arguments and outputs
- Sensitive file blocking (`.env`, `.ssh`, credentials, `.pem`)
- Tool chain detection (e.g. read → exfiltrate)
- Session taints and egress controls (sensitive read → later send blocked)
- Human approval gates for high-risk calls
- Hash-chained JSONL audit log
- Policy hot-reload
- `mcp-visor lint` for static policy validation
- Identity-based and time-based access control

**Advanced** (optional flags, same binary):

- Signed decision receipts (Ed25519 / Vault Transit)
- Webhook event emitter (Slack/Teams/n8n)
- SIEM export (syslog/CEF/JSON)
- HTTP+SSE remote transport with mTLS
- Prometheus metrics + OTLP tracing
- Web dashboard
- n8n control-plane blueprint

See [docs/complexity-budget.md](docs/complexity-budget.md) for the feature tiering policy.

## Comparison

| | MCP Visor | Runlayer | Microsoft Toolkit | Obot AI |
|---|-----------|----------|-------------------|--------|
| Enforcement | Deterministic | LLM-as-judge | Deterministic | LLM scanning |
| Self-hosted | ✅ Single binary | ❌ SaaS | ✅ TypeScript | ❌ SaaS |
| Open-source | ✅ MIT | ❌ | ✅ MIT | ❌ |
| Chain detection | ✅ | ❌ | ✅ | ❌ |
| Secret redaction | ✅ | ✅ | ❌ | ❌ |

## Security model

- **Deterministic** — no LLM in the decision path
- **Fail-closed** — unknown tools denied by default
- **Layered** — redaction → policy → chain → approval → audit
- **Observable** — every decision logged with hash-chained integrity
- **Minimal TCB** — single Go binary, 2 dependencies

## CLI

```
mcp-visor serve [flags]    Run the proxy
mcp-visor lint <policy>    Validate a policy file
mcp-visor version          Print version
```

Core flags: `-server`, `-policy`, `-audit-log`, `-approval-dir`, `-approval-cli`, `-demo`

Advanced flags: `-server-url`, `-webhook-url`, `-siem-target`, `-vault-addr`, `-metrics-addr`, `-otel-endpoint`, `-dashboard`, `-trace`

Full reference: `mcp-visor serve -h`

## Development

```bash
go build ./cmd/mcp-visor/      # build
go test ./...                   # test
harness/check.sh                # harness (fmt + vet + test + evidence)
make bench                      # benchmarks
```

## Roadmap

- [x] v1.0: Proxy, policy engine, audit, chain detection, redaction, approval
- [x] v1.1: Identity/time policies, CLI approval, hot-reload
- [x] v2.0: Signed receipts, webhooks, SIEM, mTLS, remote transport
- [ ] v3.0: WASI sandboxing, eBPF telemetry, OPA/Rego support

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Run `harness/check.sh` before PRs.

## License

MIT — see [LICENSE](LICENSE)
