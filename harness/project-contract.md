# MCP Visor — project contract

## Purpose

MCP Visor is a deterministic MCP proxy for valid JSON-RPC `tools/call` requests with IDs. Notification-form `tools/call` is blocked before relay on stdio and remote transports; non-tools notifications forward unchanged. Unrelated invalid JSON is not a universal fail-closed surface.

## Non-negotiable invariants

1. **Default deny** — Unknown tools and unspecified servers are denied unless policy explicitly allows.
2. **No LLM in decisions** — Allow, deny, redact, chain, and approval gating are rule-based only.
3. **Single request enforcement path** — Stdio and remote transports share processing for valid `tools/call` requests with IDs. Remote transport remains experimental.
4. **Startup parse/schema failure is closed** — Invalid YAML and schema errors prevent startup. Lint is supplemental, not a complete fail-closed gate: the linter-only composite rule passes strict mode, and `--strict --no-warnings` can suppress warning failures.
5. **Audit selected security events; terminal allows require durable commit** — Denies, approvals, chain detections, argument redactions, session taints, and session lifecycle emit structured events. Every terminal allow (approved allow, explicit allow, default/fallback allow) is durably committed to the trusted audit sink before relay: the final `tool_call_allowed` record is appended in full, explicitly synced, and only then does chain/taint/metric state advance. Any commit failure denies the call with zero relay.

**Audit filesystem trust boundary** — The configured audit directory, its filesystem namespace for the process lifetime, and audit file ownership/host administration are trusted. The ledger is append-only and written only by Visor through the single descriptor opened at startup (regular final component, no-follow open; recovery and all appends use the same fd; the parent directory is synced once unconditionally at startup). Hostile host users, root, operator deletion of the ledger, concurrent rename/unlink/rebind of the audit path or an audit-directory ancestor, pathname reachability after startup, rotation, reopen, and following a moved inode are explicit non-goals: if the audit directory is mutable by an attacker, the deployment violates the trust boundary, and Visor does not compensate with namespace-race, `SameFile`, nlink, `O_EXCL`, or runtime path-revalidation code.
6. **OTLP excludes raw argument maps, not all argument-derived data** — spans omit the argument object, but `policy.reason` can contain values such as a denied path. Trace/dashboard surfaces can expose additional redacted-but-sensitive data.

## Public CLI contract (stable)

- `mcp-visor serve` — run proxy
- `mcp-visor lint --strict <policy>` — supplemental static validation; never combine with `--no-warnings`
- `mcp-visor version` — build info

Core flags: `-server`, `-policy`, `-audit-log`, `-demo`, approval flags for high-risk tools.

Advanced flags (Vault, SIEM, webhooks, OTLP, dashboard, remote URL) are optional integrations; see `docs/complexity-budget.md`.

## Security boundary

The visor sits **between** MCP client and MCP server. Trust assumptions: policy file integrity on the host, visor binary integrity, MCP server behind the proxy for enforced clients.

## Complexity budget

New work must pass the rule in `docs/complexity-budget.md` before merging feature code.