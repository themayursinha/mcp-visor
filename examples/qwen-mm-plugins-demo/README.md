# Qwen-MM-Plugins demo — real third-party MCP enforcement

Fail-closed proof that MCP Visor enforces a capability allowlist against a
real, third-party MCP tool ecosystem: the Qwen-MM-Plugins `core` server
(github.com/QwenLM/Qwen-MM-Plugins, Apache-2.0, git commit
`ec9fbd1e11a30841685b949863e9d9d30cd7a4d8`, tag
`qwen-mm-plugins-core-v1.0.2`).

The policy (`examples/policies/qwen-mm-plugins.yaml`) is a capability
allowlist: read-only media tools (`read_image`, `read_video`,
`media_info`) are allowed; unlisted producers/visualizers (`crop`,
`draw_bbox`, `save_view`, `visualize`) are denied by `default_action: deny`
at the proxy.

The proof client exits non-zero unless JSON-RPC outcomes and the durable
audit ledger both match that contract. It does not wrap the third-party
server with an observe-log; non-relay of denied calls is visor's
deny-before-relay invariant, evidenced here by a visor JSON-RPC error
(not a tool result) plus `tool_call_denied`.

`tools/list` still advertises all 7 core tools. Visor does not filter the
list; enforcement is on `tools/call`.

## Run

```bash
# 1. Build visor at the repo root (binary is not checked in)
make build

# 2. Run the proof client (creates a temp workdir, fixtures, and audit ledger)
python3 examples/qwen-mm-plugins-demo/demo-client.py
```

Requires: `uv` (uvx), ffmpeg/ffprobe, network on first run (uvx fetches the
pinned commit). The client fails closed if any of those are missing.

The client speaks id-matched JSON-RPC over stdio: initialize,
`notifications/initialized` (no id), tools/list, then two allowed
`tools/call` (read_image, media_info) and two denied (crop, visualize).

## Expected result

| Call | Result |
|------|--------|
| `tools/list` | all 7 Qwen core tools advertised |
| `read_image` | JSON-RPC result (not error); audit `tool_call_allowed` |
| `media_info` | JSON-RPC result (not error); audit `tool_call_allowed` |
| `crop` | JSON-RPC error `-32000` citing `not registered`; audit `tool_call_denied` |
| `visualize` | JSON-RPC error `-32000` citing `not registered`; audit `tool_call_denied` |

On success the client prints `PASS audit ledger <path>` and leaves the
temp workdir in place for inspection. Any mismatch prints `FAIL:` and
exits 1.

## Manual server invocation

```bash
mcp-visor serve \
  -server "$(command -v uvx)" \
  -server-arg --from \
  -server-arg "qwen-mm-plugins[core] @ git+https://github.com/QwenLM/Qwen-MM-Plugins.git@ec9fbd1e11a30841685b949863e9d9d30cd7a4d8" \
  -server-arg qwen-mm-plugins-core \
  -server-name qwen-mm-plugins-core \
  -policy examples/policies/qwen-mm-plugins.yaml \
  -audit-log /tmp/qwen-demo/audit.jsonl
```

Create `/tmp/qwen-demo` first: visor does not mkdir the audit parent, and
a missing parent falls back to a non-durable stderr sink that fail-closes
every allow.
