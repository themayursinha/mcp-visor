# MCP Visor supervised development loop

Repeatable, **supervised** loop for AI-assisted changes. Not an automatic release pipeline.

## Trigger

Enforcement, policy, audit, approval, telemetry, CLI behavior, security-claim docs, release prep.

## Cycle

1. Read `AGENTS.md`, `harness/project-contract.md`, `harness/invariants.md`.
2. Write a task JSON from `harness/tasks/template.json` and `validate` it.
3. Work in an isolated git worktree when practical.
4. **Worker:** `run -name red_test` (contract argv), implement inside `allowed_paths`, `run -name target_test`.
5. **Planner:** `scope`, `run -name harness`, `verify -min HARNESS_VERIFIED`.
6. **Reviewer:** produce `review.json`. Review cannot override failed deterministic gates.
7. `report` writes local evidence. Stop for **Mayur** merge/tag/release approval.

`run` never accepts a replacement command; argv comes only from the task JSON.
Target and harness records must match the current workspace digest; harness must follow the latest successful target.
## Derived status (from artifacts only)

| Status | When |
|--------|------|
| SPECIFIED | valid task contract |
| FAILURE_REPRODUCED | security-sensitive + executed RED fail |
| TARGET_VERIFIED | scope pass + required pass commands + RED fail if security-sensitive |
| HARNESS_VERIFIED | TARGET_VERIFIED + executed harness pass |
| SECURITY_REVIEWED | HARNESS_VERIFIED + review artifact passed |
| BLOCKED | invalid/non-executed command records |

No script sets these by assignment. No `.task/state.env`.

## Tool

```bash
go run ./cmd/visor-workflow <validate|scope|run|verify|report> ...
```

## Approval-gated paths

Default patterns include `*_test.go`, `harness/invariants.md`, `go.mod`/`go.sum`, `README.md`, `SECURITY.md`, `.github/workflows/*`. Changes are **reported**; Mayur must explicitly accept them.

## Evidence truth

Local evidence is useful and generated from real exits, but editable. CI evidence is the planned stronger gate. Roles are enforced by separate profiles, credentials, and GitHub controls—not by local `ROLE=` environment variables.

```text
Workers patch. Planners verify. Reviewers opine. Harnesses check. Humans release.
```
