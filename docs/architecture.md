# MCP Visor Architecture

Runtime architecture and component design for the MCP Visor policy enforcement proxy.

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
│  │  Parses every tools/call, extracts:           │           │
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
cmd/mcp-visor/main.go          CLI entry point, flag parsing, --demo mode
internal/
  mcp/                         MCP protocol implementation
    protocol.go                 Message types (JSON-RPC 2.0, tools/call, tools/list)
    parser.go                   JSON-RPC decoder/encoder over stdio byte stream
  proxy/                       Proxy orchestration
    proxy.go                    Main proxy loop, interception, relay
    session.go                  Per-connection session with call history
    proxy_test.go               Unit tests for proxy logic
  policy/                      Policy engine
    types.go                    Policy struct definitions (servers, tools, chains, redaction)
    loader.go                   YAML policy file loader
    validator.go                Policy schema validation
    engine.go                   Policy evaluation pipeline + chain detection
    registry.go                 In-memory tool/server registry built from policy
    engine_test.go              Policy engine unit tests
  audit/                       Structured audit logging
    logger.go                   JSONL logger with O_SYNC writes, 7 event types
    logger_test.go              Audit logger unit tests
  redaction/                   Sensitive data redaction
    engine.go                   Configurable regex-based secret scanning
    engine_test.go              Redaction engine unit tests
  approval/                    Human approval workflow
    engine.go                   File-based approval with timeout
    engine_test.go              Approval engine unit tests
examples/
  demo-mcp-server/              Mock MCP server for testing/demos
  demo-runner/                  Interactive demo walkthrough
  policies/                     5 example policy files
  malicious-prompts/            5 documented prompt injection scenarios
tests/
  integration/                  End-to-end proxy tests with mock MCP server
```

## Decision Pipeline

Every intercepted `tools/call` passes through this ordered pipeline:

```
intercepted tools/call
        │
        ▼
 ┌──────────────────┐
 │ Redaction first  │──▶ Strip secrets from arguments before evaluation
 └──────┬───────────┘
        ▼
 ┌──────────────────┐
 │ Known tool?      │──No──▶ DENY (unknown tool)
 └──────┬───────────┘
   Yes  │
        ▼
 ┌──────────────────┐
 │ Tool denylisted? │──Yes──▶ DENY (explicit deny)
 └──────┬───────────┘
   No   │
        ▼
 ┌──────────────────┐
 │ Not in allowlist?│──Yes──▶ DENY (not allowlisted, if default-deny)
 └──────┬───────────┘
   No   │
        ▼
 ┌──────────────────┐
 │ Arguments pass   │──No──▶ DENY (argument validation failed)
 │ validation?      │
 └──────┬───────────┘
   Yes  │
        ▼
 ┌──────────────────┐
 │ Dangerous chain  │──Yes──▶ DENY (chain detected)
 │ detected?        │
 └──────┬───────────┘
   No   │
        ▼
 ┌──────────────────┐
 │ Sensitive data   │──Yes──▶ Redact, then continue
 │ in args?         │
 └──────┬───────────┘
   No   │
        ▼
 ┌──────────────────┐
 │ Requires         │──Yes──▶ REQUIRE_APPROVAL
 │ approval?        │
 └──────┬───────────┘
   No   │
        ▼
     ALLOW
        │
        ▼
 ┌──────────────────┐
 │ Sensitive data   │──Yes──▶ Redact output before returning to client
 │ in output?       │
 └──────┬───────────┘
        ▼
 Return result to client
```

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
   - `relayClientToServer`: reads client messages, intercepts `tools/call`, enforces policy
   - `relayServerToClient`: reads server responses, redacts outputs, forwards to client
4. Graceful shutdown on SIGINT/SIGTERM via `signal.NotifyContext`

### 3. Session Tracking (`internal/proxy/session.go`)

Per-proxy-connection session state:

- Records every `tools/call` in chronological order with tool name, server, arguments, and result preview
- Maintains a thread-safe call history (`sync.RWMutex`)
- Exposes `RecentCallChain(windowSize)` for the chain detector
- Session state is ephemeral — lost on proxy restart

### 4. Policy Engine (`internal/policy/`)

Deterministic, YAML-driven policy evaluation. No LLM involvement.

- **Loader** (`loader.go`): Reads YAML policy files, validates schema, applies defaults
- **Validator** (`validator.go`): Schema validation — rejects invalid policies with clear errors
- **Engine** (`engine.go`): Core evaluation methods:
  - `Evaluate(server, call)` → `Decision{Action, Reason}`
  - `EvaluateChain(server, call, previousCalls)` → chain detection
  - `GetRiskLevel(server, tool)` → risk classification
- **Registry** (`registry.go`): In-memory lookup maps built from policy for fast tool/server resolution
- **11 argument rule types**: deny_path, allow_path, deny_command_pattern, allow_command_pattern, deny_query_pattern, allow_query_pattern, allowed_repos, deny_recipient_domain, allow_recipient_domain, max_file_size, max_rows

### 5. Redaction Engine (`internal/redaction/`)

Configurable regex-based secret detection:

- **Built-in patterns**: OpenAI keys (`sk-`), GitHub tokens (`ghp_`), Slack tokens (`xoxb-`), AWS keys (`AKIA`), JWTs, private keys, database connection strings, internal IPs, email addresses
- **Argument redaction**: Scans tool arguments before forwarding to the MCP server
- **Output redaction**: Scans server responses before returning to the client
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

Structured JSONL audit trail:

- **7 event types**: `tool_call_allowed`, `tool_call_denied`, `tool_call_chain_detected`, `tool_call_approval_required`, `session_started`, `session_ended`, `policy_loaded`
- **Redacted data**: All logged arguments are scrubbed of secrets before writing
- **O_SYNC writes**: Durability (append-only semantics)
- **Each event includes**: timestamp, session ID, agent ID, server, tool, arguments (redacted), decision, reason, risk level, chain context

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
- If the policy engine encounters an error, it denies
- Approval timeouts deny by default
- No "default-allow" posture is possible without explicit configuration

### Minimal TCB

- One non-stdlib dependency: `gopkg.in/yaml.v3` for policy parsing
- No frameworks, no ORMs, no HTTP routers
- Small binary size (~8 MB stripped)

## Runtime Decision Examples

See [examples/demo-runner/](../examples/demo-runner/) for an interactive walkthrough of all decision types:

1. **Allow**: `file_read` on an allowed path with no chain concern
2. **Deny**: `shell_exec` with a reverse shell command matching deny regex
3. **Chain denial**: `file_read` followed by `http_post` within a 3-call window
4. **Approval required**: `slack_send_message` requires human confirmation
5. **Redaction**: API keys and tokens stripped from arguments and outputs

## Transport

v1 supports stdio transport only. The proxy starts the MCP server as a child process and communicates over stdin/stdout pipes. This is the standard MCP transport for local tools.

v2 will add HTTP/SSE transport for remote MCP servers.
