# MCP Visor complexity budget

AI-assisted coding makes enterprise-looking complexity cheap. MCP Visor stays useful only if it remains a **sharp enforcement primitive** at the MCP `tools/call` boundary—not a feature bundle where every integration looks equally “core.”

This document defines **product tiers**, the **complexity budget rule**, and how we treat **feature sprawl** without removing shipped code.

## Product tiers

### Core (the wedge)

What a new adopter must understand in one session. Everything here is on the **60-second path** (`mcp-visor serve --demo`).

| Capability | Packages / surface |
|------------|----------------------|
| Stdio MCP proxy | `internal/proxy`, `internal/mcp`, `internal/transport` (pipe) |
| YAML policy, default-deny | `internal/policy` |
| Argument rules (paths, patterns, etc.) | `internal/policy` |
| Secret redaction + sensitive paths | `internal/redaction` |
| Tool-chain detection | `internal/policy` (engine + session) |
| JSONL audit | `internal/audit` |
| Policy lint CLI | `mcp-visor lint`, `internal/policy/linter` |
| Basic approval (file / CLI) | `internal/approval` |
| Demo mock server + examples | `examples/demo-mcp-server`, `serve --demo` |

**Core decision path:** redaction → policy → chain → approval → audit. No LLM in the allow/deny path.

### Advanced (shipped, optional)

Enterprise and operator integrations. **On by flag only**; not required for the enforcement story.

| Capability | Decision |
|------------|----------|
| HTTP+SSE remote transport | **Keep** — real deployments need remote MCP; document as Advanced |
| Durable approval + signed receipts | **Keep** — strengthens enforcement receipts; Advanced |
| Webhook emitter | **Keep** — control-plane hook; Advanced |
| SIEM export | **Keep** — compliance path; Advanced |
| Vault Transit signing | **Keep** — KMS path; Advanced |
| Embedded dashboard | **Keep** — local operator UI; Advanced (OTLP/Grafana for fleet) |
| Prometheus + OTLP export | **Keep** — proves enforcement in customer observability stacks |
| Trace logging (`--trace`) | **Keep** — forensics; Advanced |
| n8n blueprint | **Keep** — example control plane; Advanced / examples |

### Experimental / roadmap

Not part of the current binary contract. Listed in README roadmap only.

| Item | Decision |
|------|----------|
| WASI sandbox, eBPF telemetry | **Defer** — v3+ roadmap |
| OPA/Rego policies | **Defer** — v3+ roadmap |
| Web policy dashboard (full product) | **Defer** — prefer export + embedded minimal dashboard |
| Multi-agent federation | **Defer** — v4+ |

## Complexity budget rule

**Freeze feature expansion** until a change satisfies this gate:

```text
No new feature unless it strengthens at least one of:
  1. Core enforcement (deterministic allow/deny/redact/chain/audit)
  2. Demo / adoption (60-second path, clearer docs, safer defaults)
  3. Bypass reduction (fewer ways to skip the proxy or weaken default-deny)
  4. Harness coverage (new invariant or integration test proves a security property)
```

If a proposal fails all four, it does not ship in Core and should not expand CLI surface without explicit maintainer intent.

## Feature inventory

Same binary, tiered documentation.

| Area | Tier | On critical demo path? |
|------|------|-------------------------|
| `serve --demo` | Core | Yes |
| Policy YAML + `lint` | Core | Yes |
| Stdio proxy | Core | Yes |
| Chain + `.env` deny rules | Core | Yes (integration tests) |
| Remote `--server-url` | Advanced | No |
| `--vault-*` | Advanced | No |
| `--siem-*`, `--webhook-*` | Advanced | No |
| `--dashboard` | Advanced | No |
| `--metrics-addr`, `--otel-*` | Advanced | No |
| `examples/n8n` | Advanced | No |

**Collapse in docs, not in code:** README and CONTRIBUTING lead with Core; Advanced flags are grouped in CLI reference.

## Harness

Executable verification lives in [`harness/`](../harness/README.md). Run before considering doc or enforcement changes "done":

```bash
harness/check.sh
```

Evidence manifests are written under `evidence/harness/` (gitignored).

## Related

- [Architecture](architecture.md) — decision pipeline and components
- [CONTRIBUTING.md](../CONTRIBUTING.md) — PR gate + harness