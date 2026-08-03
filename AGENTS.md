# AGENTS.md — MCP Visor

## Model routing — three-model harness loop

All code changes (features, fixes, refactors) use this model assignment:

| Role | Model | Provider |
|------|-------|----------|
| Architect (design) | `gpt-5.6-sol` | `openai-codex` |
| Builder (implementation) | `deepseek-v4-flash` | `opencode-go` |
| Reviewer (verification) | `qwen3.8-max` | `openai-api` (Token Plan) |

**Loop:** Architect → Builder → Reviewer. FAIL → back to Architect. Max 3 iterations.
**Skip:** Only for single-line typos or when user says "quick fix, no loop."
**Skill:** `three-model-harness-loop`

## Graphify — enforcement chain verification

Before/after any change touching `internal/policy/`, `internal/proxy/`, or `internal/receipt/`:
- Run `graphify path "Policy" "Proxy"` and `graphify path "Policy" "AuditLedger"`
- If the path or hop count changes, flag as a reviewer concern
- Skip for single-file changes and cosmetic changes
- Run `graphify update .` after code changes

## Pre-change checklist

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
GREEN/harness evidence is bound to the selected base SHA and a snapshot digest covering the normalized task contract plus all tracked, untracked, and ignored repository files (except generated `evidence/workflow/` and `evidence/harness/`). Contract argv must not depend on `evidence/workflow/` or `evidence/harness/`.
`max_attempts` is counted per required pass-target name (not total target executions across names).
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
