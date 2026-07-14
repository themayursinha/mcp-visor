# MCP Visor — harness invariants

Each invariant maps to automated checks in `check.sh` (via `go test`) or manual demo steps.

| ID | Invariant | Verification |
|----|-----------|--------------|
| H1 | Default deny for unknown tools | `TestUnknownToolDenied` — `tests/integration/extended_test.go` |
| H2 | Sensitive paths (e.g. `.env`) denied | `TestSensitiveFileAccessDenied` — `tests/integration/extended_test.go` |
| H3 | Read → send chain denied | `TestChainDetectionFileReadThenHTTPPost`, `TestChainDetectionDatabaseQueryThenSlack` — `tests/integration/chain_detection_test.go` |
| H4 | Chain events audited | `TestChainDetectionAuditEvent` — `tests/integration/chain_detection_test.go` |
| H5 | Audit log redacts secrets | `TestAuditLogRedaction` — `tests/integration/extended_test.go` |
| H6 | Proxy handshake + tools/call path works | `TestProxyIntegrationHandshake`, `TestProxyIntegrationToolsCall` — `tests/integration/proxy_integration_test.go` |
| H7 | Policy lint catches invalid YAML/rules | `go test ./internal/policy/...` (linter package) |
| H8 | No LLM in policy engine | Code review + `internal/policy/engine.go` has no LLM client imports |
| H9 | Session taint after sensitive source read | `TestSessionTaintEgressDenyBlocksSinkAfterSensitiveSource` — `internal/proxy/session_taint_test.go` |
| H10 | Egress deny uses taint + audit metadata | Same test + `TestSessionTaintEgressAllowsSinkBeforeTaint` — `internal/proxy/session_taint_test.go` |
| H11 | Audit hash chain within one logger process (`prev_hash` linkage) | `TestAuditLogHashChain` — `internal/audit/logger_test.go` |
| H12 | Session history = forwarded calls only | `TestSessionHistoryRecordsForwardedCallsOnly` — `internal/proxy/session_taint_test.go` |

**Prompt-injection immunity** is architectural: decisions do not parse natural language from tool descriptions in an LLM. Regression: policy engine tests + integration deny paths; document scenarios in `examples/malicious-prompts/`.

**Malformed policy fail-closed:** loader/linter tests in `internal/policy`; `mcp-visor lint` must error on invalid files before `serve`.

## Adding an invariant

1. Add a row here with a test name or lint rule.
2. Add or extend integration test under `tests/integration/`.
3. Run `harness/check.sh` and attach evidence manifest.