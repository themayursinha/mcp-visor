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
| `brake.denied_by_rule` | Denials grouped by firing policy rule | `tool_call_denied` / `policy_rule` (fallback `reason`) | per log scope | computable today |
| `brake.approval_gates_total` | Calls held for human approval | `tool_call_approval_required` / `event_type` | per log scope | computable today |
| `brake.approval_overrides_total` | Held calls later overridden | none — no approval-outcome event | — | needs new field |
| `brake.chain_intercepts_total` | Chain-rule interceptions | `tool_call_chain_detected` / `event_type` | per log scope | computable today |
| `brake.taint_blocks_total` | Denials on already-tainted sessions | `tool_call_denied` / `session_taints` non-empty | per log scope | computable today |
| `brake.unlogged_denials_total` | Declared terminal denials with no matching audit event | reconciliation of declared decisions vs `tool_call_denied` by `request_hash` | per log scope | computable today |

## Computability audit (OffSec brake classes)

1. **Out-of-scope reaches** — computable today via `brake.denied_total` /
   `brake.denied_by_rule`. Reason strings carry the authority-transition
   evidence (`MANDATE->EGRESS`, …); grouping is by rule, not by a
   normalized reach taxonomy (open refinement).
2. **Guardrail hits** — computable today: denials plus approval holds
   (`brake.denied_total` + `brake.approval_gates_total`).
3. **Approvals overridden** — NOT computable today. The log records the
   hold (`tool_call_approval_required`) but no outcome. Gap: emit
   `tool_call_approved` / `tool_call_approval_overridden` carrying the
   outcome and the approval receipt hash.
4. **Actions outside allowed classes** — computable today at rule
   granularity via `brake.denied_by_rule`; a normalized effect-class
   rollup (NETWORK, DESTRUCTIVE, …) needs no new fields, only a mapping
   table (open refinement).

## Negative case

A deny with no emitted event must be caught, not silent.
`Reconcile` matches declared terminal decisions against `tool_call_denied`
by `request_hash`; every unmatched deny increments
`brake.unlogged_denials_total` and names the gap
(`TestReconcileCatchesMissingEvent`). A clean fixture reconciles to zero.

## Determinism and integrity

Same fixture in, same numbers out: no sampling, no estimation, no
model-produced scores. Inputs are append-only sink records outside the
agent's write scope; the proof asserts exact expected values. Malformed
lines and events without a type fail closed at load.

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
- Normalized effect-class rollup mapping.
- Per-principal / per-server windows (fields exist; windows undeclared).
