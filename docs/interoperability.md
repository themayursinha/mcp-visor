# MCP Visor — Real MCP Interoperability Matrix

Status: **maintained evidence** (Phase 1, verified 2026-08-03 on `main`).

This page records which real MCP servers and client invocation paths have been
run through MCP Visor, what enforcement cells are proven, and what remains
experimental. It is the non-mock counterpart to the demo and mock-server tests:
the demo proves the product story, the matrix proves the product talks to real
MCP implementations.

## Why this exists

Internal hardening proves Visor fails closed in our own harness. Interop proves
real MCP servers speak shapes Visor can mediate, real invocation paths still
hit the action boundary, and a second person can reproduce at least one
non-mock path from this document.

## Server and client pins (locked 2026-08-03)

| Component | Pin | Install | Transport |
|---|---|---|---|
| Filesystem reference server | `@modelcontextprotocol/server-filesystem@2026.7.10` | `npx -y` | stdio |
| Fetch reference server | `mcp-server-fetch@2026.7.10` | `uvx --with mcp==1.26.0` | stdio |
| Client path A | raw JSON-RPC 2.0 over stdio (Go test harness) | built-in `tests/integration/interop_real_servers_test.go` | stdio |
| Client path B | official Python MCP SDK (`mcp==1.26.0`) | `tests/interop/python_sdk_client.py` | stdio |

> Fetch pin note: `mcp-server-fetch@2026.7.10` imports `McpError` from the MCP
> SDK in a way that is broken with `mcp>=1.27`; pin `mcp==1.26.0` (verified
> 2026-08-03).

## Matrix

| # | Client path | Server | Transport | Cases | Result |
|---|---|---|---|---|---|
| S1 | A (raw JSON-RPC) | Filesystem | stdio | initialize, tools/list, allowed `read_file` reaches server, denied read outside sandbox, audit allow+deny | ✅ `TestInteropFilesystemStdio` |
| S2 | A (raw JSON-RPC) | Fetch | stdio | initialize, tools/list, allowed fetch to local sink, denied unregistered tool, audit | ✅ `TestInteropFetchStdio` |
| S3 | A (raw JSON-RPC) | Filesystem | stdio | sensitive read taints session → `write_file` egress denied before server execution, audit cites taint + egress control | ✅ `TestInteropFilesystemTaintEgress` |
| S4 | B (Python SDK) | Filesystem | stdio | initialize, tools/list, allowed `read_file` returns content through Visor | ✅ manual smoke (see reproduce) |
| R1 | A (raw JSON-RPC) | Local SSE mock remote | HTTP+SSE | initialize, tools/list, allowed `tools/call` reaches remote, denied tool blocked before relay, audit | ✅ `TestInteropRemotePostHandshake` |
| R2 | A | Third-party hosted remote | HTTP+SSE | not tested | ⛔ experimental — see Remote honesty |

The mock demo server remains the regression baseline but does **not** count
toward the "≥ 2 real servers" requirement.

## Enforcement cells proven on real servers

- **initialize / initialized** — both reference servers complete the MCP
  handshake through the proxy. Observed server info: filesystem
  `secure-filesystem-server 0.2.0`, fetch `mcp-fetch 1.26.0`.
- **tools/list** — real tool names relay through the proxy; policies are keyed
  to names discovered from `tools/list` (filesystem exposes `read_file`,
  `read_text_file`, `write_file`, `list_directory`, …; fetch exposes exactly
  `fetch`).
- **Allowed call reaches the server** — `read_file` on a sandbox file returns
  real content; `fetch` to a local loopback sink returns real content.
- **Denied call does not reach the server** — an unregistered tool
  (`http_post`) is denied with `default_action: deny` before relay; the
  filesystem test asserts the deny reason cites the allow-path rule.
- **Taint → egress deny** — a sensitive read (`secrets/customer-secrets.env`)
  marks the session; a later egress-shaped `write_file` is denied at the proxy
  before server execution, and the audit event carries `policy_rule =
  block_egress_after_sensitive_read` with `taint_source` and `taint_reason`.
- **Audit explains decisions** — every cell asserts `tool_call_allowed` /
  `tool_call_denied` / `session_tainted` events in the JSONL audit log with
  decision, tool, server, and reason fields.

## Policies

Under `examples/policies/interop/`:

- `filesystem-sandbox.yaml` — sandbox `allow_path` roots, sensitive-read taint
  source, egress control over registered sinks (`write_file`, `edit_file`,
  `fetch`, `http_post`).
- `fetch-egress.yaml` — fetch tool registered, sensitive-URL taint source,
  egress control denying further fetch after a sensitive fetch.
- `remote-mock.yaml` — tools for the local SSE mock remote cell.

## Reproduce

### Client path A — automated stdio matrix (filesystem + fetch + remote)

Requirements: Go 1.26+, `npx`, `uvx` (Python 3.12+). The tests skip (not fail)
when `npx` or `uvx` is missing, so the default `go test ./...` gate stays
hermetic.

```bash
cd <repo>
go test -tags interop ./tests/integration/ -run 'TestInterop' -v -count=1
```

This spawns the real filesystem and fetch servers through a built
`mcp-visor`, uses only `/tmp/interop-sandbox` and loopback HTTP as targets, and
writes audit logs to a temp dir.

### Client path B — official Python MCP SDK (manual smoke)

```bash
# 1. prepare a sandbox (never point the filesystem server at a real home dir)
mkdir -p /tmp/interop-sandbox/docs /tmp/interop-sandbox/secrets
echo "hello world" > /tmp/interop-sandbox/docs/readme.txt

# 2. start visor proxying the real filesystem server
cd <repo>
go build -o /tmp/visor ./cmd/mcp-visor
/tmp/visor serve \
  -server npx -server-arg -y \
  -server-arg @modelcontextprotocol/server-filesystem@2026.7.10 \
  -server-arg /tmp/interop-sandbox -server-name filesystem \
  -policy examples/policies/interop/filesystem-sandbox.yaml \
  -audit-log /tmp/visor-audit.jsonl

# 3. in another terminal, drive visor with the official Python MCP SDK client
uvx --with mcp==1.26.0 python3 tests/interop/python_sdk_client.py \
  /tmp/visor serve -server npx -server-arg -y \
  -server-arg @modelcontextprotocol/server-filesystem@2026.7.10 \
  -server-arg /tmp/interop-sandbox -server-name filesystem \
  -policy examples/policies/interop/filesystem-sandbox.yaml \
  -audit-log /tmp/visor-audit.jsonl

# expected: SERVER_INFO, TOOLS list, READ_RESULT: "hello world\n"
# audit log contains tool_call_allowed for read_file
```

The client's `read_file` argument is the same `/tmp/interop-sandbox/docs/readme.txt`
used by path A, so both client paths assert the same boundary with real tools.

### Manual single-server smoke (no test harness)

```bash
go run ./cmd/mcp-visor serve \
  -server npx -server-arg -y \
  -server-arg @modelcontextprotocol/server-filesystem@2026.7.10 \
  -server-arg /tmp/interop-sandbox -server-name filesystem \
  -policy examples/policies/interop/filesystem-sandbox.yaml \
  -audit-log /tmp/visor-audit.jsonl
```

Then connect any MCP client (e.g. `npx @modelcontextprotocol/inspector` or a
desktop client) to the `mcp-visor` command. This is the human/desktop
invocation path; it is not part of the automated CI gate.

## Remote honesty

Current remote status is deliberately narrow:

- **Local SSE mock remote (R1)** — post-handshake `tools/call` relay is proven
  with a loopback HTTP+SSE mock in `TestInteropRemotePostHandshake`. The remote
  path uses the same `interceptClientToServerEnvelope` → `processToolsCall`
  gate as stdio, so deny-before-relay and audit behavior are shared.
- **Third-party hosted remote (R2)** — **not** tested and **not**
  production-supported. No cloud MCP server is required by this matrix, no
  tokens are used, and no public internet dependency exists in the automated
  gate. Treat `--server-url` against a hosted service as experimental until a
  real remote parity test is added.
- The architecture and threat model documents previously stated that remote
  transport used a shared read/write mutex that could block post-handshake
  calls and that incomplete TLS client key pairs were not rejected. Both are
  **stale**: `HTTPTransport` uses separate `readMu` / `writeMu`
  (`internal/transport/http.go`) with `TestHTTPTransportAllowsConcurrentReadAndWrite`,
  and `buildTLSConfig` rejects incomplete client key pairs
  (`TestTLSConfigRejectsIncompleteClientKeyPair`). Remote remains experimental
  for hosted services, but not for the reasons those lines claimed.

## CI and determinism rules

- `go test -tags interop ./tests/integration/ -run TestInterop` is the
  CI-runnable gate; it is skip-safe when `npx`/`uvx` are absent.
- No public internet dependency: fetch cells use a local loopback HTTP sink.
- Temp dirs only: `/tmp/interop-sandbox` (never a real home directory).
- No secrets, tokens, or private paths in any policy, test, or doc.

## Known bypass boundaries

- The filesystem→fetch taint cell cannot be formed in a single `serve` process
  because the CLI proxies one server per process. The taint→egress cell is
  therefore proven with the filesystem server's registered egress sinks
  (`write_file`/`edit_file`) and, separately, on the fetch server
  (`fetch`→`fetch` after a sensitive URL). See `TestInteropFilesystemTaintEgress`
  and `TestInteropFetchStdio`.
- Remote hosted-server parity is the largest remaining interop gap (R2).
- Batch `tools/call` and mixed-batch authorization are not implemented; the
  envelope gate rejects batches containing `tools/call` (see threat model).

## Related

- [`docs/architecture.md`](architecture.md) — transport design
- [`docs/threat-model.md`](threat-model.md) — threat model and remaining limits
- [`docs/complexity-budget.md`](complexity-budget.md) — capability decisions
- `tests/integration/interop_real_servers_test.go` — the automated matrix
- `tests/interop/python_sdk_client.py` — client path B
- `examples/policies/interop/` — interop policies
