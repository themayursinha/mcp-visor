# MCP Visor harness

Minimal **harness engineering** for this repo: contract, invariants, and one script that must pass before enforcement or doc changes are considered done.

```bash
# From repository root
harness/check.sh
```

## Contents

| File | Role |
|------|------|
| `project-contract.md` | Purpose and non-negotiables |
| `invariants.md` | Security properties → tests |
| `check.sh` | fmt, vet, full test suite, evidence manifest |

## Evidence

`check.sh` writes `evidence/harness/<timestamp>/manifest.md` (gitignored). Use for PR notes or local audit; do not commit secrets or host paths into public artifacts.

## When to run

- Before opening a PR
- After AI-assisted edits to `internal/proxy`, `internal/policy`, or CLI flags
- After README/architecture changes that claim enforcement behavior

See also `docs/complexity-budget.md`.