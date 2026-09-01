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
    logger.go                   JSONL logger: durable allow-commit (append + Sync) before relay; hash-chain recovery on reopen
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

Valid JSON-RPC `tools/call` requests with an `id` are classified in `internal/mcp/envelope.go` and enforced in `internal/proxy/client_envelope.go` → `internal/proxy/tools_call.go` (shared by stdio and remote transports). The same envelope gate protects the post-initialize handshake slot. Notification-form `tools/call`, duplicate `method` keys, and JSON-RPC batches containing `tools/call` are blocked before relay. Recognizable malformed `tools/call` attempts with an `id` fail closed. [`docs/policy-model.md`](policy-model.md#evaluation-order) documents the enforced request path:

```
intercepted tools/call
        │
        ▼
 ┌──────────────────────────┐
 │ Server identity         │──Deny──▶ one terminal deny event with identity
 │ attestation (optional)  │          evidence; no arguments, no relay
 └──────┬───────────────────┘
  No pin│ (or matched)
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
 │ Durable allow    │──fail──▶ DENY (zero relay; taint/chain/allowed state
 │ commit (H19)     │          does not advance)
 └──────┬───────────┘
  ok    │
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

When a server policy pins an attestation (`kind: stdio_invocation_sha256_v1`), the proxy resolves the launched stdio invocation exactly once at proxy construction and compares that cached lifecycle identity against the current policy snapshot on every `tools/call` before runtime limits, redaction, argument policy, taint, chains, approval, or relay. The digest always binds the locally resolved launcher executable and every literal argv value in order; only the policy-declared entry argument positions (`attestation.entry_arg_positions`, zero-based indexes into `ServerArgs` excluding the executable) additionally bind the resolved local regular-file content at that position, so mutable runtime data arguments (logs, databases, datasets, output paths) are never opened or hashed. Recognized canonical dynamic registry runners (`npx`, `uvx`, `bunx`, `pnpx`, `pnx`, `npm exec`, `npm x`, `yarn dlx`, `pnpm dlx`, `bun x`, `uv tool run`) are unpinnable: the literal package spec does not bind the registry artifact that will execute, so resolution fails and a configured attestation denies through the unresolved-identity path. Only exact canonical executable names and exact leading subcommand tuples are recognized; options-before-subcommand, renamed launchers, and shell wrappers are not inferred, and ordinary non-registry subcommands (`npm run`, `npm install`, `npm ci`, `yarn add`, `pnpm add`, `pnpm exec`, `bun run`, `bun add`, `uv run`, `uv tool install`) remain resolvable. A configured mismatch or unresolved identity fails closed with one terminal deny event, no arguments, and identity-bound audit fields. A matching local identity continues and emits `server_attested=true` on the terminal event. Policies without an attestation preserve legacy behavior, omit the verdict, and perform zero identity-resolution work at construction. Attestation is restart-bound: identity is measured once for the launched stdio child and is NEVER re-derived on hot reload. Reloading launcher or payload paths cannot attest a replacement artifact as the already-running child; a pin introduced after an unattested start, a changed resolution shape (attestation kind or normalized entry positions), or a same-shape digest replacement all fail closed until a server restart. Unrelated policy/redactor/audit/approval reloads remain atomic. Tool descriptions, schemas, instructions, and handshake `serverInfo` are untrusted presentation data and never satisfy identity. This is local invocation pinning, not remote/hardware attestation; server startup behavior and TOCTOU by a privileged filesystem attacker remain out of scope.

Denied or approval-rejected calls do not enter the relay write path. Terminal **allows** emit a standalone JSONL `tool_call_allowed` event that must be fully appended and `Sync()`'d before relay (H19). Denies, `approval_required`, session taints, and session lifecycle use `Log()` (full append, no `Sync`). `policy_reloaded` is emitted on a successful hot reload; `policy_loaded` is defined but not emitted. Output-only redaction has no dedicated JSONL event.

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

### 2.5 Server Identity Attestation (`internal/serveridentity/`, proxy gate)

Optional, deterministic stdio server identity binding. For a server policy that pins `attestation: {kind: stdio_invocation_sha256_v1, digest: sha256:<64-hex>, entry_arg_positions: [0]}`, the proxy resolves the launched stdio invocation (`internal/serveridentity/identity.go`): the launcher command is resolved via PATH, symlinks are followed, and the regular executable file is streamed into SHA-256 over a versioned, injectively framed serialization (`stdio_invocation_sha256_v1`): a format-marker field, one field for the executable bytes, and one field per literal argv value carrying its ordinal index, each field prefixed by a component tag, a fixed-width big-endian index, and an explicit byte length (see the contract in `internal/serveridentity/identity.go`). Only the positions listed in `entry_arg_positions` (zero-based indexes into `ServerArgs`, excluding the executable) additionally bind the resolved local regular-file content at that position — `[0]` for `node server.js`, `python server.py`, or another local single-entry runner; multiple unique positions are allowed and are normalized by sorting a copy, so YAML list order is not part of identity. Undeclared file-valued args (logs, databases, datasets, output paths) are bound by their literal bytes only and are never opened or hashed, so mutable runtime data cannot change the identity. Binding the local invocation means two servers launched through the same local runner with different declared local payloads get different identities, closing the confused-deputy gap for shared launchers. Recognized canonical dynamic registry runners (`npx`, `uvx`, `bunx`, `pnpx`, `pnx`, `npm exec`, `npm x`, `yarn dlx`, `pnpm dlx`, `bun x`, `uv tool run`) are unpinnable: they select a package from a registry at runtime, so the literal spec cannot be content-bound and resolution fails closed. The classifier recognizes only exact canonical executable names and exact leading subcommand tuples; options-before-subcommand, renamed launchers, and shell wrappers are not inferred, and ordinary non-registry subcommands remain resolvable. Operators who need attestation must launch a locally installed/content-pinned executable or declare the local payload positions instead of a dynamic registry runner. The resolved digest is captured exactly once at proxy construction and is immutable for the proxy/stdio-child lifecycle; the same resolution shape (attestation kind plus normalized entry_arg_positions) is retained with it. Every `tools/call` compares the snapshot policy's pin against that cached identity as the first gate, before runtime limits, redaction, argument policy, taint, chains, approval, or relay. Mismatch or unresolved identity fails closed with one terminal deny audit event carrying identity fields and no arguments. Matching identity continues and emits `server_attested=true` on the terminal allow event. Policies without an attestation omit the verdict, preserve legacy behavior, and perform zero identity-resolution work: construction and reload never call the resolver for an unattested logical server. Attestation is restart-bound: hot reload never re-hashes launcher or payload paths. A pin introduced after an unattested start, a changed resolution shape, or a same-shape digest replacement compares against the cached startup identity and fails closed as unresolved/restart-required; removal may restore the explicitly requested unattested legacy path; a startup resolution failure stays unresolved and is not retried on reload. Approval terminal allow/deny events carry the complete policy plus identity snapshot captured before the runtime barrier was released. Tool descriptions, schemas, instructions, and handshake `serverInfo` are untrusted presentation data and never satisfy identity. This is local invocation pinning, not remote/hardware attestation.

**Boundary (explicit, decision A 2026-08-12):** attestation is entry-artifact attestation, not dependency-closure attestation. The digest binds the resolved launcher executable, the literal invocation args, and only the policy-declared entry payload positions; it does NOT bind the transitive dependency closure of interpreted runtimes (for example a `node server.js` entry importing `helper.js`, or a Python script importing installed packages). Replacing an imported module without changing the launcher, argv, or declared entry file preserves the digest. This is a documented limitation: full transitive pinning is future work and must not be claimed today.

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
- **18 enforced argument rule types**: `deny_path`, `allow_path`, `require_path_literal`, `allow_path_slot`, `deny_command_pattern`, `allow_command_pattern`, `deny_command_keyword`, `deny_query_pattern`, `allow_query_pattern`, `deny_recipient_domain`, `allow_recipient_domain`, `allow_recipient`, `allow_resource_owner`, `allowed_repos`, `max_file_size`, `max_result_rows`, `max_export_rows`, `require_approval_always`

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

- **Event constants**: `policy_reloaded` is emitted on successful hot reload. `policy_loaded` is defined and not emitted. Output-only redaction has no dedicated JSONL event. Plain allows emit `tool_call_allowed` (H14) via `CommitAuthorization` (H19).
- **Durable allow-commit**: `CommitAuthorization` prepares a hash-linked `tool_call_allowed` record without mutating chain state, appends the full line, calls `Sync()`, and only then advances `prevHash`/`chainIndex`. Any marshal/write/short-write/sync/non-durable failure poisons the sink, returns an error, and the proxy denies with zero relay. `Log()` also withholds chain advance until a full append succeeds, but it does **not** `Sync()`. The file is opened `O_RDWR|O_APPEND|O_CREATE|O_NOFOLLOW` — not `O_SYNC`.
- **Hash-chain recovery**: `NewLogger` recovers `prev_hash`/`chain_index` from the same fd. Incomplete tails and corrupt last records fail closed. Regression: `TestNewLoggerRecoversHashChainAcrossRestart`, `TestCommitAuthorizationWritesThenSyncsBeforeAdvancing`.
- **Redacted data**: arguments, reasons, and result previews scrubbed before write
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

See [examples/demo-runner/](../examples/demo-runner/) for the two-minute stateful authorization proof:

1. **Allow**: `file_read` on a benign path succeeds.
2. **Taint**: `file_read` on a sensitive source marks the session `sensitive_file_accessed`.
3. **Deny**: later `http_post` is blocked by `block_sensitive_egress` before it reaches the MCP server.
4. **Audit**: JSONL evidence records source action, taint, policy rule, sink action, and decision.

## Transport

### stdio (Local)

The default transport. The proxy starts the MCP server as a child process and communicates over stdin/stdout pipes. Newline-delimited JSON-RPC messages are relayed bidirectionally. This is the standard MCP transport for locally installed tools.

### HTTP + SSE (Remote, experimental)

Enabled via `--server-url`. The code supports SSE reads and POST writes. Post-handshake relay is proven against a local loopback SSE mock (`TestInteropRemotePostHandshake`) and uses the same `interceptClientToServerEnvelope` → `processToolsCall` enforcement gate as stdio. Third-party hosted remote servers remain **experimental**: no real hosted-service parity test exists yet, so do not use `--server-url` against a production service without additional validation. The transport uses separate `readMu` / `writeMu` so a blocked SSE read cannot deadlock concurrent POSTs (`TestHTTPTransportAllowsConcurrentReadAndWrite`).
- **SSE endpoint** (GET) for server-to-proxy streaming of responses and notifications
- **Message endpoint** (POST) for proxy-to-server requests
- Optional TLS configuration exists; an incomplete client certificate/key pair is rejected fail-closed (`TestTLSConfigRejectsIncompleteClientKeyPair`). Operators must provide both files and use HTTPS
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
