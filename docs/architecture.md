# MCP Visor Architecture

Runtime architecture and component design for the MCP Visor policy enforcement proxy.

**Product tiers:** Core vs Advanced vs Experimental are defined in [complexity-budget.md](complexity-budget.md). The diagram below includes optional enterprise components (Vault, SIEM, webhooks); the **60-second demo path** uses stdio proxy, policy, redaction, chain detection, and audit only.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                   AI Agent / MCP Client                      │
│              (Claude Desktop, Copilot, etc.)                 │
└───────────────────────────┬─────────────────────────────────┘
                            │ MCP Protocol (stdio/JSON-RPC)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                       mcp-visor                               │
│                                                               │
│  ┌──────────────┐    ┌──────────────────┐                    │
│  │ MCP Parser   │───▶│  Handshake       │                    │
│  │ (stdin/stdout│    │  Negotiation     │                    │
│  └──────────────┘    └────────┬─────────┘                    │
│                                │                              │
│                                ▼                              │
│  ┌───────────────────────────────────────────────┐           │
│  │              interceptor Layer                 │           │
│  │  Parses valid request tools/call with ID:     │           │
│  │  - Tool name, server name, arguments          │           │
│  │  - Session/agent identity                     │           │
│  │  - Call sequence context                      │           │
│  └─────────────────────┬─────────────────────────┘           │
│                        │                                      │
│                        ▼                                      │
│  ┌──────────────────────────────────────────────────┐        │
│  │              Policy Engine                        │        │
│  │                                                   │        │
│  │  ┌───────────┐  ┌───────────┐  ┌──────────────┐ │        │
│  │  │ Tool      │  │ Risk      │  │ Argument     │ │        │
│  │  │ Registry  │  │Classifier │  │ Validator    │ │        │
│  │  └───────────┘  └───────────┘  └──────────────┘ │        │
│  │                                                   │        │
│  │  ┌───────────┐  ┌───────────┐  ┌──────────────┐ │        │
│  │  │ Redaction │  │ Chain     │  │ Approval     │ │        │
│  │  │ Engine    │  │ Detector  │  │ Engine       │ │        │
│  │  └───────────┘  └───────────┘  └──────────────┘ │        │
│  │                                                   │        │
│  └───────────────────────┬───────────────────────────┘        │
│                          │                                     │
│                          ▼                                     │
│  ┌──────────────────────────────────────────────────┐        │
│  │           Decision (allow / deny / redact /       │        │
│  │                    require_approval)              │        │
│  └───────────────────────┬──────────────────────────┘        │
│                          │                                     │
│                     ┌────┴────┐                                │
│                     ▼         ▼                                │
│              ┌───────────┐  ┌───────────┐                     │
│              │ Audit     │  │ MCP Egress│                     │
│              │ Logger    │  │ Parser    │                     │
│              │ (JSONL)   │  └─────┬─────┘                     │
│              └───────────┘        │                            │
│                                   │                             │
└───────────────────────────────────┼─────────────────────────────┘
                                    │ MCP Protocol
                                    ▼
┌─────────────────────────────────────────────────────────────┐
│                     MCP Server                                │
│       (filesystem, database, GitHub, Slack, etc.)            │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
cmd/mcp-visor/main.go          CLI entry point, flag parsing, serve/lint/version
internal/
  mcp/                         MCP protocol implementation
    protocol.go                 Message types (JSON-RPC 2.0, tools/call, tools/list)
    parser.go                   JSON-RPC decoder/encoder over byte stream
  proxy/                       Proxy orchestration
    proxy.go                    Main proxy loop, interception, relay (stdio)
    remote.go                   Remote proxy relay (HTTP+SSE transport)
    session.go                  Per-connection session with call history
    tracing.go                  Trace logging config and metrics
    vault.go                    Vault signer/verifier construction
  policy/                      Policy engine
    types.go                    Policy struct definitions
    loader.go                   YAML policy file loader
    validator.go                Policy argument validation
    engine.go                   Policy evaluation pipeline + chain detection
    registry.go                 In-memory tool/server registry
    linter.go                   Static policy validation CLI
    watcher.go                  fsnotify engine/registry reload; proxy-derived settings remain static
  audit/                       Structured audit logging
    logger.go                   JSONL logger with O_SYNC and healthy-sink, logger-lifetime hash linking
  redaction/                   Sensitive data redaction
    engine.go                   Configurable regex-based secret scanning
  approval/                    Human approval workflow
    engine.go                   File-based / CLI-based approval with timeout
    durable.go                  Durable approval engine with signed receipts
  transport/                   Transport adapters
    transport.go                Transport interface + PipeTransport (stdio)
    http.go                     HTTPTransport (SSE + POST), MockTransport (test)
  trace/                       Message tracing
    trace.go                    TraceLogger interface (Text, JSONL, Summary)
  vault/                       Vault Transit integration
    client.go                   HashiCorp Vault HTTP client
    signer.go                   TransitSigner/TransitVerifier (signer.Signer)
  signer/                      Cryptographic signing
    signer.go                   Signer/Verifier interfaces, Ed25519 key management
  receipt/                     Signed decision receipts
    receipt.go                  DecisionReceipt with nonce, expiry, hash binding
  webhook/                     Event webhook emitter
    emitter.go                  Async HTTP delivery with HMAC + retry
  siem/                        SIEM event export
    siem.go                     Syslog/JSON/CEF formats over TCP/UDP/file
examples/
  demo-mcp-server/              Mock MCP server for testing/demos
  demo-runner/                  Interactive demo walkthrough
  policies/                     5 example policy files
  malicious-prompts/            5 documented prompt injection scenarios
  n8n/                          n8n control plane blueprint
tests/
  integration/                  End-to-end proxy tests
```

## Decision Pipeline

Valid JSON-RPC `tools/call` requests with an `id` are classified in `internal/mcp/envelope.go` and enforced in `internal/proxy/client_envelope.go` → `internal/proxy/tools_call.go` (shared by stdio and remote transports). Notification-form `tools/call`, duplicate `method` keys, and JSON-RPC batches containing `tools/call` are blocked before relay. Recognizable malformed `tools/call` attempts with an `id` fail closed. [`docs/policy-model.md`](policy-model.md#evaluation-order) documents the enforced request path:

```
intercepted tools/call
        │
        ▼
 ┌──────────────────┐
 │ Runtime limits   │──▶ DENY if argument/session caps are exceeded
 └──────┬───────────┘
        ▼
 ┌──────────────────┐
 │ Argument         │──▶ Rewrite forwarded args when secrets match redaction patterns
 │ redaction        │
 └──────┬───────────┘
        ▼
 ┌──────────────────┐
 │ Sensitive path   │──Yes──▶ DENY (built-in sensitive file patterns)
 │ block            │
 └──────┬───────────┘
   No   │
        ▼
 ┌──────────────────┐
 │ Policy evaluate  │──▶ DENY / REQUIRE_APPROVAL / ALLOW (tool + argument rules)
 │ (YAML engine)    │
 └──────┬───────────┘
        ▼
 ┌──────────────────┐
 │ Egress controls  │──Match──▶ DENY or REQUIRE_APPROVAL when session taint + sink tool
 │ (session taints) │
 └──────┬───────────┘
        ▼
 ┌──────────────────┐
 │ Chain detection  │──Match──▶ DENY or REQUIRE_APPROVAL (recent forwarded calls)
 │ (session history)│
 └──────┬───────────┘
        ▼
 ┌──────────────────┐
 │ Final decision   │──DENY / REQUIRE_APPROVAL / ALLOW
 └──────┬───────────┘
   Allow│
        ▼
 ┌──────────────────┐
 │ Post-allow taint │──▶ Matching `taints[]` rules mark session; emit `session_tainted`
 │ marking          │
 └──────┬───────────┘
        ▼
 Forward to MCP server (stdio/remote)
        ▼
 ┌──────────────────┐
 │ Output redaction │──▶ Replace configured matches in textual Content[].Text
 └──────┬───────────┘
        ▼
 Return result to client
```

Denied or approval-rejected calls do not enter the relay write path. Selected events cover denies, approvals, argument redactions, session taints, and session lifecycle. Policy lifecycle constants exist but are not emitted. Output redaction and plain unredacted allows lack standalone JSONL events.

## Core Components

### 1. MCP Parser (`internal/mcp/`)

Implements the MCP JSON-RPC 2.0 protocol over line-delimited stdio. The parser handles:

- **Request/response decoding**: `tools/call`, `tools/list`, `initialize`, `initialized` notifications
- **Error responses**: Generate standard JSON-RPC error objects with error codes
- **Raw message passthrough**: Non-intercepted messages pass through unmodified for performance
- **Bidirectional relay**: Two goroutines handle client→server and server→client independently

### 2. Proxy Orchestration (`internal/proxy/`)

The main proxy loop (`Run`) manages the full lifecycle:

1. Start the MCP server as a child process with stdin/stdout pipes
2. Run the MCP handshake (forward `initialize` request/response, `initialized` notification)
3. Spawn two relay goroutines:
   - `relayClientToServer`: classifies client envelopes, blocks notification-form `tools/call`, then enforces valid request-form `tools/call`
   - `relayServerToClient`: reads server responses, redacts outputs, forwards to client
4. Graceful shutdown on SIGINT/SIGTERM via `signal.NotifyContext`

### 3. Session Tracking (`internal/proxy/session.go`)

Per-proxy-connection session state:

- **Call history** (`ToolCalls`): calls are appended after authorization but before `EncodeRaw`. Denied, approval-rejected, and malformed calls are not recorded, but a transport-write failure can leave an authorized call in history. Chain detection therefore sees calls authorized for relay, not a confirmed execution ledger.
- **Session taints** (`Taints`): set after an allowed source tool matches a `taints[]` rule (`markMatchingTaints` in `session_taint.go`).
- Thread-safe (`sync.RWMutex`); exposes `RecentCallChain(windowSize)` for chain detection.
- Ephemeral — lost on proxy restart.

### 4. Policy Engine (`internal/policy/`)

Deterministic, YAML-driven policy evaluation. No LLM involvement.

- **Loader** (`loader.go`): Reads YAML policy files, validates schema, applies defaults
- **Validator** (`validator.go`): Schema validation — rejects invalid policies with clear errors
- **Engine** (`engine.go`): Core evaluation methods:
  - `Evaluate(server, call)` → `Decision{Action, Reason}`
  - `EvaluateChain(server, call, previousCalls)` → chain detection
  - `GetRiskLevel(server, tool)` → risk classification
- **Registry** (`registry.go`): In-memory lookup maps built from policy for fast tool/server resolution
- **14 enforced argument rule types**: `deny_path`, `allow_path`, `deny_command_pattern`, `allow_command_pattern`, `deny_command_keyword`, `deny_query_pattern`, `allow_query_pattern`, `deny_recipient_domain`, `allow_recipient_domain`, `allowed_repos`, `max_file_size`, `max_result_rows`, `max_export_rows`, `require_approval_always`

### 5. Redaction Engine (`internal/redaction/`)

Configurable regex-based secret detection:

- **Built-in patterns**: OpenAI keys (`sk-`), GitHub tokens (`ghp_`), Slack tokens (`xoxb-`), AWS keys (`AKIA`), JWTs, private-key headers, database connection strings, and internal IPs. The private-key pattern does not remove an entire PEM body.
- **Argument redaction**: Scans tool arguments before forwarding to the MCP server
- **Output redaction**: scans textual MCP result entries (`Content[].Text`); structured `Data`, JSON-RPC errors, and other fields are not comprehensively scanned
- **Sensitive file blocking**: `**/.env`, `**/credentials`, `**/*.pem`, `**/.ssh/**`, etc.
- **Deep scanning**: Recursively scans nested maps, arrays, and slices

### 6. Chain Detector (`internal/policy/` — part of engine)

Tracks tool call sequences within a session to detect dangerous patterns:

- **Sliding window**: Configurable size (default: 10 calls)
- **Source→sink pattern matching**: Regex-based tool name matching
- **Actions on match**: `deny` or `require_approval`
- **Example chains**:
  - `file_read` → `http_post` (data exfiltration)
  - `database_query` → `slack_send_message` (data exfiltration)
  - `file_read` → `file_delete` (read-then-destroy)
- Thread-safe with concurrent sessions

### 7. Approval Engine (`internal/approval/`)

Human-in-the-loop approval for high-risk tool calls:

- **File-based backend**: Writes `req-<id>.json` to approval directory; waits for `req-<id>.ok` file
- **Request files**: Contain full context (tool, server, arguments, reason, risk level, session)
- **Configurable timeout**: Default-deny after timeout (fail-closed)
- **Automatic cleanup**: Removes request/response files after decision

### 8. Audit Logger (`internal/audit/`)

Structured JSONL audit trail (`internal/audit/logger.go`):

- **Event constants**: nine types are defined, but `policy_loaded` and `policy_reloaded` are not currently emitted. A plain unredacted allow and output-only redaction also lack standalone audit events.
- **Healthy-sink logger-lifetime chain**: successful writes link within one `Logger` instance. The logger advances chain state before confirming persistence, so a failed write can leave the next stored event pointing to a missing hash. Another logger instance or file reopen starts a new segment. Regression: `TestAuditLogHashChain` covers only healthy writes.
- **Redacted data**: arguments, reasons, and result previews scrubbed before write
- **O_SYNC** append-only file writes
- **Decision fields**: timestamp, session/agent IDs, server, tool, redacted arguments, `policy_decision`, reason, risk, chain context; egress denials add `session_taints`, `taint_source`, `taint_reason`, `policy_rule`

## Key Design Decisions

### Go (not TypeScript, not Rust)

- **Single static binary**: No runtime dependencies. `./mcp-visor serve` is the entire deployment
- **Strong stdio support**: `os/exec` pipes for MCP server child processes
- **Good concurrency**: Goroutines per relay direction, channels for inter-component communication
- **Memory safety**: No buffer overflows or use-after-free in the TCB
- **Performance**: More than sufficient for MCP call frequencies (seconds between calls, not microseconds)

### Deterministic Policy (no LLM)

The policy engine uses exact match, prefix/suffix, regex, and rule-chain logic. Prompt injection cannot manipulate it. The LLM may be tricked into attempting a dangerous call, but the visor evaluates `tools/call` by tool name, arguments, and policy rules — not by LLM intent.

### Fail-Closed Default

- Unknown tools/servers are denied by default
- YAML/schema startup errors and approval timeouts deny, but unsupported rules and some invalid regexes can be ignored or no-match
- Approval timeouts deny by default
- No "default-allow" posture is possible without explicit configuration

### Minimal TCB

- **Core enforcement path** (policy, proxy, audit, redaction): no LLM; policy parsing uses `gopkg.in/yaml.v3` only among direct deps for the decision hot path.
- **Optional integrations** (see `go.mod`): OpenTelemetry export, partial `fsnotify` engine reload, and gRPC OTLP are not required for default stdio proxy + YAML policy.
- Single static binary; no ORM or application framework.

## Runtime Decision Examples

See [docs/action-boundary-demo.md](action-boundary-demo.md) and [examples/demo-runner/](../examples/demo-runner/) for the two-minute stateful authorization proof:

1. **Allow**: `file_read` on a benign path succeeds.
2. **Taint**: `file_read` on a sensitive source marks the session `sensitive_file_accessed`.
3. **Deny**: later `http_post` is blocked by `block_sensitive_egress` before it reaches the MCP server.
4. **Audit**: JSONL evidence records source action, taint, policy rule, sink action, and decision.

## Transport

### stdio (Local)

The default transport. The proxy starts the MCP server as a child process and communicates over stdin/stdout pipes. Newline-delimited JSON-RPC messages are relayed bidirectionally. This is the standard MCP transport for locally installed tools.

### HTTP + SSE (Remote, experimental)

Enabled via `--server-url`. The code supports SSE reads and POST writes, but Phase 1 evidence currently covers handshake only. A shared read/write mutex can block post-handshake calls while the SSE reader waits, so this path is not production-supported until the transport concurrency test and interoperability matrix pass.
- **SSE endpoint** (GET) for server-to-proxy streaming of responses and notifications
- **Message endpoint** (POST) for proxy-to-server requests
- Optional TLS configuration exists, but a one-sided client certificate/key configuration is not currently rejected; operators must provide both files and use HTTPS
- `--sse-path` to customize the SSE endpoint, `--insecure-tls` for development

The `Transport` interface (`ReadRaw`, `EncodeRaw`, `Close`) is implemented by both `PipeTransport` (stdio) and `HTTPTransport` (remote). A `MockTransport` provides an in-memory channel-based transport for testing.

## Trace Logging (incomplete)

Text, JSONL, and summary formatter types exist, and `--trace` / `--trace-format` initialize a tracer. The handshake, relay, decision, redaction, and chain paths do not currently call that tracer, so the flags do not provide runtime message tracing. Treat this surface as incomplete until integration tests prove real event capture.

## Observability surfaces (experimental)

`ProxyMetrics` defines seven counters, but they use unsynchronized `int64` fields while relay and HTTP handlers can access them concurrently. Prometheus and dashboard metrics are therefore not production-grade until a race-safe snapshot or atomic counters are implemented.

- **Prometheus** (`--metrics-addr`): scrape `/metrics` for `ProxyMetrics` counters.
- **OTLP gRPC** (`--otel-endpoint`): per-`tools/call` spans omit the raw argument map, but `policy.reason` can include argument-derived values such as a sensitive path.
- Export failures are non-blocking; enforcement stays on the hot path.

The embedded dashboard is a separate local rendering surface. Its API has no built-in authentication and can expose redacted arguments/result previews; bind it locally or place it behind authenticated access control.

`bytes_redacted_total` currently adds the full raw request length whenever any field is redacted; it is not a count of bytes actually removed.

See `examples/otel-lgtm` for a Grafana LGTM local stack.

## Vault Transit Integration

HashiCorp Vault Transit secrets engine provides cryptographic signing without exposing private keys to the visor:

- `TransitSigner` implements the `signer.Signer` interface for remote Ed25519 signing
- `TransitVerifier` implements the `signer.Verifier` interface for signature verification
- Vault client supports token auth, TLS/mTLS, namespace (Enterprise), and health checks
- Public key is retrieved from Vault Transit key metadata at initialization
- Configure via `--vault-addr`, `--vault-token`, `--vault-key-name` CLI flags
