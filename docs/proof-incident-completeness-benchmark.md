# Proof and incident-completeness conformance corpus

This benchmark covers a local synthetic MCP action-boundary model only. It
does not cover or enforce the executor, operating-system, container, network,
DNS, credential store, package registry, tenant service, or host boundary.

Package `internal/incidentbench` is a deterministic, in-memory
conformance/regression corpus. It is not a production authorizer, live
incident responder, exposure scanner, or efficacy benchmark. Ground truth is
the generated scenario table (rows 1–5). It does not change the proxy, policy
engine, H32, approvals, or Incident Bundle v0.1. Numbers characterize only
this fixed synthetic corpus.

Reproduce:

```bash
go test ./internal/incidentbench -count=1 -timeout=120s -v
```

## Six evidence dimensions

These fields are typed and distinct. Reachability is never authority.

1. **Declared environment** — what the trajectory says exists (`environment_id`,
   principal, tenant, `fixture_ids`).
2. **Observed reachability** — whether the local fixture table can technically
   reach the requested target (computed before decision reduction; never
   creates a grant).
3. **Delegated authority** — current principal, delegator, tenant, exact
   grants, and the delegation's policy/authority epochs.
4. **Requested effect** — typed consequential operation (`effect_id`, kind,
   target, tenant). Every generated effect has `consequential=true`.
5. **Observed effect** — what the action-boundary fixture committed or
   blocked (`status`, kind, target, tenant, `boundary_source`, tick). The
   boundary authorizes or blocks; it does not confirm external absence.
   Confirmed `external_effect` evidence comes only from a separate
   `synthetic-fixture-observer` query of the fixture ledger. There is no
   transcript field and no free-text parser.
6. **Policy/authority epoch** — current epochs against which the delegation is
   checked.

A reachable target without a current matching grant is denied and incidented.
An authorized but unreachable target is `deny_unreachable` and is not an
authority incident.

## Effect labels and local fixtures

Closed set (opaque `fixture://` identifiers only; never resolved URLs or host
paths). Adapters mutate in-memory state only. The credential fixture holds
the sentinel `synthetic-placeholder`; it is not loaded from disk, env,
keyring, Vault, or a host store.

| Kind | Fixture form | Local meaning |
|---|---|---|
| `external_network` | `fixture://network/<tenant>` | in-memory send counter |
| `credential_read` | `fixture://credential/synthetic` | in-memory sentinel read |
| `cross_tenant_request` | `fixture://tenant/<destination-tenant>` | in-memory tenant hit; requested/grant tenant is distinct from the declared home tenant |
| `package_publication` | `fixture://registry/<package>` | in-memory publish counter |
| `lateral_movement` | `fixture://host/<host>` | in-memory host-move counter |

Authorization is structural and exact: matching principal and tenant, current
policy and authority epochs, and one grant equal to requested kind, target,
and tenant. No prefix, wildcard, case folding, or transcript inference. A
stale epoch is no current authority even when kind/target/tenant match.

## 100,000-trajectory corpus

`DefaultCorpusSize` is 100,000 (smaller public runs are rejected). Seed
`0x8d26ef04`. IDs `trajectory-000000`..`trajectory-099999`. Kind = `index%5`
(20,000 each). Scenario = `(index/5)%10`. Policy epoch
`40+((index/50)%3)`; authority epoch `700+((index/150)%5)`. Logical ticks
from the index; no wall clock. Generated in memory at test/runtime; not
committed.

| Row | Scenario | Expected |
|---:|---|---|
| 0 | current grant, reachable | allow; committed; no incident |
| 1 | no grant, reachable | deny out of authority; one incident |
| 2 | grant at authority epoch−1, reachable | stale; deny OOA; one incident |
| 3 | no grant, reachable, immediate duplicate | one deny + idempotent duplicate; one incident |
| 4 | no grant, reachable, later replay | one deny + idempotent replay; one incident |
| 5 | no grant, reachable, follow-on telemetry missing | deny OOA; one complete incident |
| 6 | current grant, unreachable | deny unreachable; no authority incident |
| 7 | current grant, reachable, duplicate | allow once; cached committed observation; no incident |
| 8 | current grant, reachable, replay | allow once; cached committed observation; no incident |
| 9 | current grant, reachable | allow; committed; no incident |

Expected unique out-of-authority incidents: 50,000 (rows 1–5). Duplicate and
replay return the cached boundary result: no reevaluation, no second mutation,
no advanced tick, no second incident. Effect-ID reuse with different
content fails the run.

Missing follow-on telemetry still yields one complete record with an
explicit `missing` marker; the synchronous boundary result is the source.
Missing action-boundary observation fails the run closed.

## Exactly-once incidents and Incident Bundle v0.1

An incident is required iff the effect is consequential, the decision is
`deny_out_of_authority`, and `out_of_authority` is true. `dedup_key` is
lowercase SHA-256 of `trajectory_id NUL effect_id NUL kind NUL target NUL
tenant`. `incident_id` is `incident-` plus that digest. The in-memory
recorder is `PutIfAbsent`: first call builds, verifies, and persists; a
byte-equivalent retry returns the first record; a same-key non-equivalent
call fails. `persisted_tick` is `boundary_tick+4` (after the four bundle
events) and is unchanged on retry.

Each `IncidentRecord.bundle` is built with `internal/incidentbundle` (not a
copied schema). A benchmark-only Ed25519 key is derived from
`mcp-visor incidentbench synthetic key v1` (fixture material, not a trust
anchor). Four events, in order: `requested_action` (the five non-observed
dimensions), `policy_decision` (deny, reason, epochs, `authority_valid:false`),
`runtime_attempt` (`relayed:false`, `blocked_at:synthetic_mcp_action_boundary`),
`external_effect` (observed effect, telemetry, `confirmation:confirmed` only
when the independent fixture observer reports the effect ID absent from the
ledger). Confirmed means the observer queried the ledger, not that the
boundary assumed a skip. Redaction note:
`synthetic fixture; no raw credential material`. Bundles are sealed and
verified before persist. Integrity proves recorded bytes and stage structure,
not semantic truth of an external system.

## Metrics

Ground truth is scenario labels, compared as unique dedup-key sets:

`TP = expected ∩ emitted`; `FN = expected − emitted`; `FP = emitted − expected`;
`recall = TP/(TP+FN)`; `precision = TP/(TP+FP)`;
`false_positive_rate = FP / non-incident trajectories`;
`duplicate_rate = duplicate_persist_count / expected_incident_count`;
`receipt_completeness = complete_receipt_count / emitted_incident_count`.

`duplicate_persist_count` is extra physical records per key, not harmless
retries. Latency uses `unit:logical_tick` over true-positive persists as
`persisted_tick − boundary_tick` (nearest-rank percentiles). Default
acceptance: 100000 trajectories, 50000 expected/emitted/TP/complete, 0 FN/FP
/duplicates, recall/precision/completeness 1, FPR/duplicate rate 0, latency
4/4/4/4. These are labeled-corpus conformance results, not production
efficacy, whole-runtime coverage, an executor/network guarantee, or a
compliance claim. Do not read them as “zero false positives” outside this
corpus.

## Limitations and residuals

1. synthetic local corpus; not a production measurement
2. MCP action-boundary model only; executor and network boundaries excluded
3. no live targets, external network, or real credentials
4. does not prove whole-runtime completeness or bypass resistance
5. does not establish Wiz remediation or Wiz-fixed status

A process can bypass an MCP proxy or cause effects beyond this synthetic
boundary; this corpus neither observes nor prevents that. Confirmed blocked
is an independent fixture-observer ledger query, not proof of absence on a
real network, host, registry, credential store, or tenant. No durable/multi-process exactly-once
sink or crash recovery. Epochs are synthetic; no policy loader or revocation
service. Follow-on telemetry loss is represented, not repaired. Shared-state
propagation (A writes poison, B retrieves, C challenges) is residual and is
not simulated or claimed here.
