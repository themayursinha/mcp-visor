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
| H9 | An authorized sensitive-source request taints the session | `TestSessionTaintEgressDenyBlocksSinkAfterSensitiveSource` — `internal/proxy/session_taint_test.go` |
| H10 | A tainted egress request is denied with audit metadata before relay | Same test + `TestSessionTaintEgressAllowsSinkBeforeTaint` — `internal/proxy/session_taint_test.go` |
| H11 | Audit hash linkage for healthy writes within one logger lifetime | `TestAuditLogHashChain` — `internal/audit/logger_test.go` |
| H12 | Notification-form `tools/call`, including typed duplicate-key parser differentials, JSON-RPC batching, and the post-initialize handshake slot, is blocked on stdio and remote; non-tools notifications and batches still forward | `TestClassifyClientEnvelopeDeniesTypedDuplicateNotificationToolsCall`, `TestClassifyClientEnvelopeDeniesDuplicateMethodWhenToolsCallAppearsFirst`, `TestClassifyClientEnvelopeDeniesDuplicateMethodWhenToolsCallAppearsLast`, `TestClassifyClientEnvelopeDeniesDuplicateMethodWhenToolsCallAppearsLastWithID`, `TestClassifyClientEnvelopeForwardsNonToolsBatch`, `TestClassifyClientEnvelopeDeniesBatchContainingToolsCallNotification`, `TestClassifyClientEnvelopeDeniesBatchContainingToolsCallRequest`, `TestClassifyClientEnvelopeDeniesBatchWithLeadingWhitespace`, `TestInterceptDeniesNotificationToolsCallStdio`, `TestInterceptDeniesNotificationToolsCallRemoteParity`, `TestInterceptForwardsInitializedNotificationStdio`, `TestInterceptForwardsInitializedNotificationRemote`, `TestInterceptDeniesBatchContainingToolsCall`, `TestInterceptDeniesHandshakeNotificationToolsCall`, `TestInterceptForwardsHandshakeInitialized`, `TestProxyIntegrationNotificationToolsCallNotRelayed` |

**Prompt-injection immunity** is architectural: decisions do not parse natural language from tool descriptions in an LLM. Regression: policy engine tests + integration deny paths; document scenarios in `examples/malicious-prompts/`.

**Policy-validation limitation:** loader rejects YAML/schema errors. `lint --strict` fails reported warnings, but `deny_command_pattern_composite` is recognized without enforcement and `--no-warnings` can neutralize strict warning failures. It is not yet a complete deployment gate.

## Adding an invariant

1. Add a row here with a test name or lint rule.
2. Add or extend integration test under `tests/integration/`.
3. Run `harness/check.sh` and attach evidence manifest.