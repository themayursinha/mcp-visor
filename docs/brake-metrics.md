# Visor Brake Metrics v0.1

Control-side measurement contract: count the brakes, not just the engine.
Every metric derives from the enforcement logs that already exist
(`internal/audit` JSONL vocabulary); anything not derivable today is an
explicit gap with the missing field named, not a silent omission.

Status: v0.1 contract + computability audit + derivation proof.
Implementation: `internal/observability/brake.go` (normative names live
there exactly once; this doc references them). Proof:
`internal/observability/brake_test.go` over
`internal/observability/testdata/brake-audit.jsonl`.

Scope: measurement only. Nothing here authorizes or blocks an action, and
v0.1 claims no compliance, no certifications, and no benchmark results.

## Contract table

| Metric | Definition | Source event / field | Window | Status |
|---|---|---|---|---|
| `brake.denied_total` | Terminal policy denials at the tools/call boundary | `tool_call_denied` / `event_type` | per log scope | computable today |
| `brake.denied_by_rule` | Denials grouped by recorded policy rule; paths that record none fall in `unattributed` (free-form reasons are never folded in) | `tool_call_denied` / `policy_rule` | per log scope | computable today, with open refinement below |
| `brake.approval_gates_total` | Calls held for human approval | `tool_call_approval_required` / `event_type` | per log scope | computable today |
| `brake.approval_grants_total` | Holds resolved by human grant, joined to the hold by request hash | `tool_call_allowed` / `approval_receipt_hash` | per log scope | computable today |
| `brake.approval_overrides_total` | Holds resolved without a grant receipt (bypassed or decided off-record) | none — no bypass/override outcome event | — | needs new field |
| `brake.chain_intercepts_total` | Chain-rule interceptions | `tool_call_chain_detected` / `event_type` | per log scope | computable today |
| `brake.taint_blocks_total` | Taint-triggered egress denials (the only branch recording session taints) | `tool_call_denied` / `session_taints` | per log scope | computable today, narrow by construction |
| `brake.unlogged_denials_total` | Declared terminal denials with no matching deny event (mechanism proof; production use needs the join-key gap closed) | reconciliation of declared decisions vs `tool_call_denied` by `request_hash` | per log scope | needs new field |

## Computability audit (OffSec brake classes)

Grounded in what `internal/proxy/tools_call.go` actually emits — every
mapping below was checked against the producer, not the schema wish-list.

1. **Out-of-scope reaches** — computable today via `brake.denied_total` /
   `brake.denied_by_rule`. Only the taint-egress branch records
   `policy_rule`; other deny paths (identity, runtime limits, ordinary
   policy) record none and fall in `unattributed`. Reason strings carry
   authority-transition evidence but are never grouped as rules.
2. **Guardrail hits** — computable today: denials plus approval holds and
   grant receipts (`brake.denied_total` + `brake.approval_gates_total` +
   `brake.approval_grants_total`). Grants join holds by request hash and
   consume one hold each: capability accounting stores receipts in the
   same receipt-hash field on ordinary allows, so receipt presence alone
   never counts — only hold-matched grants do.
3. **Approvals overridden** — NOT computable today. Grants are visible
   (allowed + receipt hash); bypasses and off-record decisions leave no
   outcome event. Gap: emit `tool_call_approved` /
   `tool_call_approval_overridden` with outcome + receipt hash.
4. **Actions outside allowed classes** — computable today at recorded-rule
   granularity via `brake.denied_by_rule` (`unattributed` bucket included);
   a normalized effect-class rollup needs no new fields, only a mapping
   table (open refinement).

Join-key gap: most deny paths emit no `request_hash`, so reconciliation
against production logs stays a gap until they do. The proof demonstrates
the mechanism on joinable records; hashless declared decisions report as
unjoinable, never silently as matched or missing. Reconciliation indexes
denials only — holds share hashes with their eventual denials and must
never satisfy a denial lookup — and consumes one logged occurrence per
declaration, so replayed requests cannot hide a missing second event.

## Negative case

A deny with no emitted event must be caught, not silent.
`Reconcile` matches declared terminal decisions against `tool_call_denied`
by `request_hash`; every unmatched deny increments
`brake.unlogged_denials_total` and names the gap
(`TestReconcileCatchesMissingEvent`). A clean fixture reconciles to zero.

## Determinism and integrity

Same fixture in, same numbers out: no sampling, no estimation, no
model-produced scores. Inputs are append-only sink records outside the
agent's write scope; the proof asserts exact expected values. Parsing is
newline-framed (`ReadBytes`, no line-length cap — production records can
exceed 1 MiB) so missing delimiters fail closed; malformed lines, events
without a type, and truncated tails (final record lacking its framing
newline, per the producer's own incomplete-tail rule) fail closed at load,
while trailing blank space of any length stays legal.

## Links

- Authorization and evaluation order: `docs/policy-model.md` (terminal
  allow/deny/require_approval, durable commit-before-relay).
- Event vocabulary: `internal/audit` (`Event`, hash-chained JSONL).
- Counters for live export: `internal/observability/prometheus.go`,
  `internal/observability/otel.go` (transport-level; brake metrics are
  the analytic layer above them).
- Incident records for consequential episodes: `docs/incident-bundle.md`.

## Open refinements (not v0.1)

- Approval-outcome events (the one hard gap above).
- `request_hash` on all terminal deny events (join-key gap).
- Stable rule identifier on every deny path (shrink `unattributed`).
- Session-taint presence on every denial (widen taint blocks).
- Normalized effect-class rollup mapping.
- Per-principal / per-server windows (fields exist; windows undeclared).
