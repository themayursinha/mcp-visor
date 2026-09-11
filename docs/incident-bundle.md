# Visor Incident Bundle v0.1

Proof-quality incident record for one MCP Visor authorization/execution
episode. Grounded in the 2026-09-06 signal: misalignment with external
effects is an incident-response problem, so every consequential episode must
leave a sealed, independently verifiable record — not a retrospective
transcript search.

Status: v0.1 implementable spec. Implementation: `internal/incidentbundle`.
Examples: `examples/incident-bundle/allow.json` (successful call),
`examples/incident-bundle/deny.json` (denied egress with confirmed absence).

## Episode graph

```
principal → delegation → authority → proposed action → policy decision
→ runtime execution → external effect → resulting state → propagation
```

Each node is an event (`internal/incidentbundle.Event`). The four stages the
bundle must never conflate:

| Stage | Event kind | Meaning |
|---|---|---|
| Proposed action | `requested_action` | What the agent asked: tool, arguments (redacted), principal, delegation chain, cited authority |
| Policy decision | `policy_decision` | What Visor decided: allow / deny / require_approval, rule, policy hash |
| Runtime attempt | `runtime_attempt` | What the proxy did: relayed bytes hash, or blocked-before-relay marker |
| External effect | `external_effect` | What independently happened outside Visor, with confirmation state |

`state_delta` (taints added, session refs) and `propagation` (SIEM forward,
receipt refs) complete the episode. A denied call still gets a full bundle:
the external effect is the *confirmed absence* of the effect (e.g. the
server observe-log shows the egress never arrived), never an assumption.

## Fields

Event: `seq`, `prev_hash`, `kind`, `timestamp` (unix), `principal`,
`delegation[]` (user→agent→tool chain, cf. agent-identity-plane),
`authority_ref` (policy rule that grants), `payload` (redacted JSON),
`payload_hash` (sha256 hex digest over canonical payload JSON, enforced on
append; hash-only references must still decode as 32 bytes of hex),
`redaction_note` (which patterns applied), `confirmation`
(`unconfirmed`|`confirmed`, required on external effects),
`supersedes` (seq of the upgraded event; only genuine confirmation
upgrades — a `confirmed` repeat naming a still-`unconfirmed` effect),
`evidence_source` (which subsystem attests this node: proxy-request,
policy-evaluate, proxy-relay, server-response, server-observe-log,
session-state, siem-exporter), `hash` (chain link). `Append` owns framing
(kind, seq, linkage, timestamp): builder callbacks supply content only.

Manifest: `bundle_id` (caller-assigned, e.g. execution id), `spec_version`
(`"0.1"`), `created_at`, `event_count`, `head_hash` (tip event),
`policy_hash` (authorizing policy bytes), `policy_id`, `key_id`,
`algorithm` (`ed25519`), `public_key`, `signature` over every other
manifest field.

## Integrity

- Hash chain mirrors `internal/audit`: each event hash covers the record
  with its own hash blanked and carries the previous hash. Truncation,
  drops, reorders, and byte mutations all fail `Verify`.
- Manifest signature is ed25519 via `internal/signer` interfaces, same
  construction as `internal/receipt` (sign over JSON with signature
  blanked). `Verify` binds the manifest's algorithm/key-id/public-key
  claims to the verifier before checking the signature: reporting
  verifiers must agree exactly (backends label their own variants, e.g.
  `ed25519-vault-transit`, and `TransitVerifier` reports it), while
  non-reporting verifiers accept plain `ed25519` only; empty key ids on
  either side reject. Appending after sealing invalidates the signature
  until re-sealed. Decoding requires valid UTF-8 with no surrogate escapes,
  exact canonical member spellings (case variants rejected), presence of
  every mandatory member with non-null values (zero values marshal back
  identically, so presence and null-ness are what absence attacks remove),
  and rejects duplicate members at every object level — unsigned,
  ambiguous, or incomplete documents cannot ride along; `supersedes`
  is valid only on a genuine confirmation upgrade.
- `Verify` checks: spec version, event count vs manifest, sequence numbers,
  chain linkage, payload bindings, required episode stages in order
  (`requested_action` → `policy_decision` → `runtime_attempt` →
  `external_effect`; premature, repeated, regressed, or unknown kinds
  rejected; the sole exception is a genuine confirmation upgrade — a
  `confirmed` repeat of an `unconfirmed` effect after completion),
  tip hash, signature, and no trailing bytes after the bundle. External
  effects must carry a valid confirmation. `Append` owns framing
  (kind, seq, linkage, timestamp): the builder callback supplies content
  fields only, so callbacks can neither retarget stages nor corrupt the
  chain. Numbers decode as `json.Number`, so 64-bit integers survive the
  marshal→parse→verify round trip. `Verify` does **not** check freshness,
  wall-clock policy, or semantic truth of payloads — open design decisions,
  below.

## Verification

```bash
go test ./internal/incidentbundle/ -count=1
```

Tamper proof (all in `bundle_test.go`): fixtures verify; mutated payload,
dropped event, reordered events, and wrong-key signatures all fail. To
regenerate the checked-in fixtures after a schema change:

```bash
INCIDENT_FIXTURES=write go test ./internal/incidentbundle/ -run TestWriteFixtures
```

Fixtures use a deterministic example-only key and fixed timestamps; they
are illustrations, never trust anchors.

## Redaction, retention, unconfirmed effects

- **Redaction:** only redacted payloads enter a bundle. Callers redact with
  `internal/redaction` first and record the applied patterns in
  `redaction_note`. Raw arguments must never cross into a bundle, an
  approval record, or a terminal log — same rule as the audit logger.
- **Retention (semantics, v0.1):** bundles are evidence, not telemetry.
  Operators retain sealed bundles per incident policy (suggested: denied /
  consequential episodes ≥ 1 year, routine allows per log rotation).
  Pruning must leave a signed tombstone referencing the bundle id and head
  hash; silent deletion is indistinguishable from tampering. No tombstone
  mechanism ships in v0.1 (open decision).
- **Unconfirmed effects:** `confirmation: unconfirmed` means no independent
  source has attested the effect yet (e.g. SIEM forward queued but not
  acked). Policy decisions must never treat unconfirmed as confirmed.
  Confirmation upgrades are new `external_effect` events, never edits.

## Link to the authorization/execution model

- Policy decisions reference `docs/policy-model.md` rules by name and bind
  the exact policy bytes via `policy_hash` (cf. `DecisionReceipt`).
- Stage order follows the proxy evaluation order in `docs/policy-model.md`
  (parse → redaction → policy → taints → chains → approval → durable
  commit → relay): `requested_action` is the canonicalized call object,
  `runtime_attempt` is post-commit, and durable commit-before-relay is what
  lets a denied bundle still claim a complete record.
- Identity/delegation fields align with agent-identity-plane v1.0
  (short-lived single-audience tokens carrying the delegation chain);
  `principal`/`delegation` here are the Visor-observed values, not a
  second token system.
- Audit vocabulary (`tool_call_allowed`, `tool_call_denied`, …) in
  `internal/audit` is the source language for `evidence_source`; the
  bundle does not replace the live JSONL stream.

## Open design decisions

1. No freshness / replay window in v0.1 (`Verify` is timeless).
2. No signed tombstones for retention pruning.
3. No multi-writer merge rule (one sealer per bundle).
4. Confirmation upgrade is append-only; no revocation event kind yet.
