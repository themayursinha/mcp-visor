# MCP Visor supervised development loop

Repeatable, **supervised** loop for AI-assisted changes. Not an automatic release pipeline.

## Trigger

Enforcement, policy, audit, approval, telemetry, CLI behavior, security-claim docs, release prep.

## Cycle

1. Read `harness/project-contract.md`, `harness/invariants.md`.
2. Write a task JSON from `harness/tasks/template.json` and `validate` it. Security tasks declare `spec_revision`, `attack_classes[]`, and `non_goals[]`. Non-security tasks should drop `spec_revision` to 0; spec-field validation applies only to `security_sensitive:true` tasks.
3. Work in an isolated git worktree when practical.
4. **Reviewer:** for a security task, produce the first spec review under `evidence/workflow/<task>/reviews/` (contiguous `<n>.json`, `phase:"spec"`, `passed:true`, `contract_digest` + `spec_revision` matching the task, `covered_attack_classes[]` covering every class, `counterexamples[]`). No task command runs and no status above `SPECIFIED` derives without a current passing spec review.
5. **Worker:** `run -name red_test` (contract argv), implement inside `allowed_paths`, `run -name target_test`.
6. **Planner:** `scope`, `run -name harness`, `verify -min HARNESS_VERIFIED`.
7. **Reviewer:** append implementation reviews to the same journal (`phase:"implementation"` or omitted, `contract_digest` + `spec_revision`). Review cannot override failed deterministic gates.
8. `report` writes local evidence under `evidence/` by default; custom outputs must remain under `evidence/` or outside the repository. Stop for maintainer merge/tag/release approval.

`run` never accepts a replacement command; argv comes only from the task JSON.
When `-base` is omitted, scope uses the merge base of `HEAD` and `origin/main`; if `origin/main` is unavailable, the tool fails closed and requires an explicit `-base`.
Target and harness records must match the selected base SHA and current snapshot digest. The digest uses byte-preserving length-prefixed framing over the normalized task contract plus all tracked, untracked, and ignored repository files except generated `evidence/workflow/` and `evidence/harness/`. Contract argv must not depend on those generated trees. Embedded repositories are rejected. Scope applies `allowed_paths` to ignored files as well. The latest target execution must pass, and the latest harness execution must pass and follow it. `max_attempts` is counted per required pass-target name.

## Spec-adversarial gate

- Spec reviews bind to the **contract digest + `spec_revision` only** (never head/base/workspace). The latest current review wins; a later failed review invalidates an earlier pass.
- For `security_sensitive:true`, a passing spec review must cover **every** `attack_classes[].failure_class` and include a non-empty counterexample. Malformed, duplicate JSON keys, gapped, or live-spec-taxonomy-invalid review evidence fails closed as `BLOCKED`.
- A current spec pass starts a **fresh evidence cycle**. Freshness is the spec review's journal sequence (`reviews/<n>.json`), not wall-clock or filesystem mtime.
- RED: only `red_test` whose `spec_sequence` matches that journal sequence counts; older RED is invalidated. GREEN/harness then follow that fresh RED by command-log order.
- Implementation reviews bind to head/base/workspace **and** `contract_digest` + `spec_revision`. For `SECURITY_REVIEWED` they must also be journaled **after** the current spec pass (`sequence` > spec pass sequence). An older snapshot-matching review cannot promote a later spec cycle. Unknown `failure_classes` on a live-contract implementation review fail closed; names from a prior digest/revision are ignored so a class rename cannot BLOCK the journal.
- Reviewer findings are evidence for humans and independent review. They do **not** latch, count strikes, or reject task commands. After two findings from the same conceptual failure class, stop implementation and return to Architect (`AGENTS.md`); the workflow tool does not encode that stop as a state machine.

## Derived status (from artifacts only)

| Status | When |
|--------|------|
| SPECIFIED | valid task contract |
| SPEC_REVIEWED | security task + current passing spec review (digest + revision) |
| FAILURE_REPRODUCED | security-sensitive + executed RED fail after the current spec pass |
| TARGET_VERIFIED | scope pass + required pass commands + RED fail if security-sensitive |
| HARNESS_VERIFIED | TARGET_VERIFIED + executed harness pass |
| SECURITY_REVIEWED | HARNESS_VERIFIED + passed implementation review bound to the current `head_sha`, `workspace_digest`, live contract, and journaled after the current spec pass |
| BLOCKED | invalid/non-executed command records, argv mismatch, target attempts above `max_attempts`, or invalid review evidence |

No script sets these by assignment. No `.task/state.env`.

## Tool

```bash
go run ./cmd/visor-workflow <validate|scope|run|verify|report> ...
```

`verify` exposes `derived_status`, `reasons`, `spec_pass`, and `contract_digest`.

## Approval-gated paths

Default patterns include `*_test.go`, `harness/invariants.md`, `go.mod`/`go.sum`, `README.md`, `SECURITY.md`, `.github/workflows/*`. Custom patterns extend these defaults; they never replace them. Changes are **reported**; the maintainer must explicitly accept them.

## Evidence truth

Local evidence is useful and generated from real exits, but editable. CI evidence is the planned stronger merge gate. Roles are enforced by separate profiles, credentials, and GitHub controls—not by local `ROLE=` environment variables.

```text
Workers patch. Planners verify. Reviewers opine. Harnesses check. Humans release.
```
