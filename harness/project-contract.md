# MCP Visor — project contract

## Purpose

MCP Visor is a **fail-closed, deterministic** MCP proxy that evaluates every `tools/call` against YAML policy **before** the MCP server runs the tool. It is not an LLM guardrail and does not use a model in the decision path.

## Non-negotiable invariants

1. **Default deny** — Unknown tools and unspecified servers are denied unless policy explicitly allows.
2. **No LLM in decisions** — Allow, deny, redact, chain, and approval gating are rule-based only.
3. **Single enforcement path** — Stdio and remote transports share the same `tools/call` processing (metrics, audit, policy).
4. **Fail-closed on bad policy** — Invalid or unloadable policy must not silently open access (lint + loader behavior).
5. **Audit selected security events** — Denies, approvals, chain detections, argument redactions, session taints, and session lifecycle emit structured events. Plain allows and output-only redaction do not yet have standalone JSONL events.
6. **OTLP excludes tool payloads** — OTLP spans carry policy metadata, not raw arguments. Trace and dashboard surfaces can expose redacted-but-still-sensitive payload data and must be access-controlled.

## Public CLI contract (stable)

- `mcp-visor serve` — run proxy
- `mcp-visor lint <policy>` — static policy validation
- `mcp-visor version` — build info

Core flags: `-server`, `-policy`, `-audit-log`, `-demo`, approval flags for high-risk tools.

Advanced flags (Vault, SIEM, webhooks, OTLP, dashboard, remote URL) are optional integrations; see `docs/complexity-budget.md`.

## Security boundary

The visor sits **between** MCP client and MCP server. Trust assumptions: policy file integrity on the host, visor binary integrity, MCP server behind the proxy for enforced clients.

## Complexity budget

New work must pass the rule in `docs/complexity-budget.md` before merging feature code.