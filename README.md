# MCP Visor

Runtime Policy Enforcement & Audit Control Plane for MCP Tool Execution

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/themayursinha/mcp-visor/actions/workflows/ci.yml/badge.svg)](https://github.com/themayursinha/mcp-visor/actions/workflows/ci.yml)

---

## Problem

AI agents are connected to enterprise tools through MCP. They can read files, query databases, send Slack messages, execute shell commands, and modify cloud infrastructure. But AI agents are probabilistic systems vulnerable to prompt injection. Current MCP architecture has no enforcement point — if an agent calls a tool, it executes.

**MCP Visor** sits between the agent and the tools, enforcing deterministic policy **before** execution. It does not use an LLM to make decisions. Prompt injection cannot bypass it.

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
git clone https://github.com/themayursinha/mcp-visor
cd mcp-visor

# Start the proxy with a built-in demo server
go run ./examples/demo-runner/

# Or proxy a real MCP server with a policy file:
go run ./cmd/mcp-visor serve \
  -server ./my-mcp-server \
  -policy examples/policies/developer-medium.yaml

# With audit logging:
go run ./cmd/mcp-visor serve \
  -server ./my-mcp-server \
  -policy examples/policies/developer-medium.yaml \
  -audit-log audit.jsonl
```

## Architecture

```
┌──────────────┐     ┌─────────────────────────────────────┐     ┌──────────────┐
│  AI Agent    │────▶│           mcp-visor                  │────▶│  MCP Server  │
│  (MCP Client)│     │                                      │     │  (Tools)     │
└──────────────┘     │  ┌─────────┐  ┌─────────────────┐   │     └──────────────┘
                      │  │Redaction│  │  Policy Engine   │   │
                      │  │ Engine  │  │                  │   │
                      │  └─────────┘  │ Allow/Deny       │   │
                      │               │ Risk Classify    │   │
                      │  ┌─────────┐  │ Arg Validate     │   │
                      │  │ Chain   │  │ Chain Detect     │   │
                      │  │Detector│  │                  │   │
                      │  └─────────┘  └─────────────────┘   │
                      │                                      │
                      │  ┌─────────┐  ┌─────────────────┐   │
                      │  │Approval │  │  Audit Logger   │   │
                      │  │ Engine  │  │  (JSONL)        │   │
                      │  └─────────┘  └─────────────────┘   │
                      └─────────────────────────────────────┘
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
- 11 argument rule types: deny_path, allow_path, deny_command_pattern, allow_command_pattern, deny_query_pattern, allow_query_pattern, allowed_repos, deny_recipient_domain, allow_recipient_domain, max_file_size, max_rows
- Risk classification (critical/high/medium/low)
- Identity-based access control
- Time-based restrictions

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
- Configurable timeout with fail-closed default
- Full audit trail for approval decisions

### Audit Logging
- JSONL format with redacted data
- 7 event types: tool_call_allowed, tool_call_denied, tool_call_chain_detected, tool_call_approval_required, session_started, session_ended, policy_loaded
- O_SYNC writes for durability

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

Flags:
  -server string       MCP server command to proxy (required)
  -server-arg string   Argument for the MCP server command (repeatable)
  -policy string       Path to policy YAML file (default: built-in deny-all)
  -audit-log string    Path to JSONL audit log file (default: stderr)
  -approval-dir string Directory for file-based approval workflow
  -session-id string   Session identifier
  -client-id string    Client identifier
```

## Development

```bash
# Build
go build ./cmd/mcp-visor/

# Test (68 tests)
go test ./...

# Vet
go vet ./...

# Run demo
go run ./examples/demo-runner/
```

## Roadmap

- [x] v1.0: MCP proxy, policy engine, audit logging, chain detection, redaction, approval
- [ ] v2.0: Webhook approvals, mTLS, signed audit logs, HTTP/SSE transport
- [ ] v3.0: Sandboxed tool execution (WASI), eBPF syscall telemetry
- [ ] v4.0: Deeper host-level enforcement, formal policy verification

## Security Model

- **Deterministic** — No LLM in the decision path
- **Fail-closed** — Unknown tools denied by default
- **Layered** — Redaction → Policy → Chain → Approval
- **Observable** — Every decision logged
- **Minimal TCB** — Single Go binary, minimal dependencies

## Limitations (v1)

- Relies on host filesystem security for policy/audit file integrity
- No cryptographic attestation of decisions
- No mTLS between visor and remote servers
- Session state is ephemeral (lost on restart)
- Approval is file-based (not web-based)
- Single-agent, single-server deployment

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Areas needing work: HTTP/SSE transport, web-based approval dashboard, mTLS support, additional MCP server integrations.

## License

MIT — see [LICENSE](LICENSE)
