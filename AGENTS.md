# AGENTS.md — MCP Visor

Before security-sensitive changes, read:

1. `harness/project-contract.md`
2. `harness/invariants.md`
3. `harness/loop.md`
4. An active task contract (`harness/tasks/*.json`)

This is a **supervised agent development workflow**, not an automatic merge/release pipeline.

## Hard rules (need Mayur)

Do not push/merge `main`, tag, publish releases, weaken security tests, rewrite invariants to fit code, add dependencies, or change public security claims without Mayur.

## Tooling

```bash
go run ./cmd/visor-workflow validate -task harness/tasks/<task>.json
go run ./cmd/visor-workflow run      -task ... -name red_test
go run ./cmd/visor-workflow scope    -task ...
go run ./cmd/visor-workflow run      -task ... -name target_test
go run ./cmd/visor-workflow run      -task ... -name harness
go run ./cmd/visor-workflow verify   -task ... -min HARNESS_VERIFIED
go run ./cmd/visor-workflow report   -task ... [-review review.json]
```

`run` executes the task contract `argv` for `-name` only (no command substitution).
GREEN/harness evidence is bound to the current workspace digest.
Status is **derived from artifacts** (task JSON, executed command records, git scope, optional review JSON). There is no stored workflow state machine and no env-var role identity.

## Supervised responsibilities

| Who | Does |
|-----|------|
| Worker | Bounded patch inside `allowed_paths`; propose RED/GREEN evidence via `run` |
| Planner | Runs deterministic `scope` / `verify` / canonical harness |
| Independent reviewer | Writes a review JSON artifact (does not override failed gates) |
| Mayur | Merge, tag, release, approval-gated exceptions |

## Evidence truth

- Command exits come only from processes this tool executes.
- Local `evidence/workflow/` is **editable and advisory**, not tamper-proof.
- CI-generated evidence is the planned stronger merge gate.
- Model prose cannot override command results.
