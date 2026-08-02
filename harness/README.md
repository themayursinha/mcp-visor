# MCP Visor harness

Contract, invariants, suite check, and a **small supervised workflow tool**.

```bash
harness/check.sh
go test ./internal/workflow/ ./cmd/visor-workflow/
go run ./cmd/visor-workflow validate -task harness/tasks/template.json
```

| Path | Role |
|------|------|
| `project-contract.md` | Non-negotiables |
| `invariants.md` | Security properties → tests |
| `loop.md` | Supervised development loop |
| `check.sh` | fmt + vet + full tests + suite evidence |
| `tasks/*.json` | Task contracts for `visor-workflow` |
| `../cmd/visor-workflow` | validate / scope / run / verify / report |
| `../internal/workflow` | Implementation + tests |

Local workflow evidence: `evidence/workflow/<task_id>/` (gitignored, editable, not tamper-proof).
