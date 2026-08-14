# MCP Visor — project contract

## Purpose

MCP Visor is a deterministic MCP proxy for valid JSON-RPC `tools/call` requests with IDs. Notification-form `tools/call` is blocked before relay on stdio and remote transports; non-tools notifications forward unchanged. Unrelated invalid JSON is not a universal fail-closed surface.

## Non-negotiable invariants

1. **Default deny** — Unknown tools and unspecified servers are denied unless policy explicitly allows.
2. **No LLM in decisions** — Allow, deny, redact, chain, and approval gating are rule-based only.
3. **Single request enforcement path** — Stdio and remote transports share processing for valid `tools/call` requests with IDs. Remote transport remains experimental.
4. **Startup parse/schema failure is closed** — Invalid YAML and schema errors prevent startup. Lint is supplemental, not a complete fail-closed gate: the linter-only composite rule passes strict mode, and `--strict --no-warnings` can suppress warning failures.
5. **Audit selected security events** — Denies, approvals, chain detections, argument redactions, session taints, and session lifecycle emit structured events. Plain allows emit a standalone JSONL event that must be durably committed to the configured regular `O_SYNC` audit ledger **before** the `tools/call` is relayed downstream (H19 authorization-commit): a failed, short, non-durable, closed, poisoned, or **rotated/rebound** ledger append denies the call with zero relay on both transports. **H19 supported model:** one clean absolute configured pathname (converted once at startup), every component symlink-free, every ancestor a directory, final single-link (`nlink==1`) regular entry identical to the opened descriptor, stable pathname, restart establishes new bindings; online rotation/rebinding, automatic reopen, symlink ledger/ancestors, hard-linked/multi-name ledger, and chasing a moved inode are explicit non-goals. The hash chain is recovered from the exact O_SYNC append fd (fresh exclusive-create starts at genesis; an existing inode is recovered through the fd that will receive appends), and every authorization commit repeats the complete no-follow component, regularity, link-count, and inode-binding validation immediately before and after its write, so any observed disappearance, rename, unlink, replacement, non-regular rebound, final or ancestor symlink, visible hard-link or cross-directory rebound, or durability failure denies with zero relay and no allowed-state mutation. Commit-time validation performs no fsync; the single parent-directory sync that establishes the accepted constructor binding happens exactly once, is immediately revalidated, and on failure never pathname-removes a potentially foreign replacement. Any validation/sync/write failure poisons the logger, and the poisoned state blocks both authorization commits and ordinary Log writes; supported-model violations are rejected, never repaired online. Claim only observed violations: a namespace mutation introduced and fully restored between validation snapshots is not claimed detectable, and a settled same-inode `link→remove→rename` rebind ending at `(dev,ino,nlink==1)` is stat-identical to the original and is documented as an unobservable unsupported mutation (the same ledger inode remains at the configured path, so the H19 one-way durable-commit implication still holds). Output-only redaction has no standalone event beyond the terminal decision.
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