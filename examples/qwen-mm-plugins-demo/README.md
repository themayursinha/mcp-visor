# Qwen-MM-Plugins demo — real third-party MCP enforcement

Deterministic proof that MCP Visor enforces policy against a real,
third-party MCP tool ecosystem: the Qwen-MM-Plugins `core` server
(github.com/QwenLM/Qwen-MM-Plugins, Apache-2.0, git tag
`qwen-mm-plugins-core-v1.0.2`).

The policy (`examples/policies/qwen-mm-plugins.yaml`) is a capability
allowlist: read-only media tools (`read_image`, `read_video`,
`media_info`) are allowed; producers/visualizers (`crop`, `draw_bbox`,
`save_view`, `visualize` — which write files to disk) are denied by
`default_action: deny` before relay.

## Run

```bash
# 1. Build visor (or use the checked-in binary)
make build

# 2. Run the proof client (spawns visor wrapping the Qwen server)
python3 examples/qwen-mm-plugins-demo/demo-client.py
```

The client speaks id-matched JSON-RPC over stdio: initialize, tools/list,
then two allowed `tools/call` (read_image, media_info) and two denied
(crop, visualize).

## Expected result

| Call | Result |
|------|--------|
| `tools/list` | all 7 Qwen core tools advertised |
| `read_image` | real result: text + base64 image relayed through the proxy |
| `media_info` | real ffprobe metadata relayed |
| `crop` | JSON-RPC error `-32000 tool 'crop' … is not registered` (denied before relay) |
| `visualize` | JSON-RPC error `-32000 tool 'visualize' … is not registered` (denied before relay) |

The audit ledger (pass `-audit-log <path>` to `serve`) records
`tool_call_allowed` / `tool_call_denied` with a hash chain
(`prev_hash`, `chain_index`) — tamper-evident evidence of every
decision.

## Manual server invocation

```bash
mcp-visor serve \
  -server "$(command -v uvx)" \
  -server-arg --from \
  -server-arg "qwen-mm-plugins[core] @ git+https://github.com/QwenLM/Qwen-MM-Plugins.git@qwen-mm-plugins-core-v1.0.2" \
  -server-arg qwen-mm-plugins-core \
  -server-name qwen-mm-plugins-core \
  -policy examples/policies/qwen-mm-plugins.yaml \
  -audit-log /tmp/qwen-demo/audit.jsonl
```

Requires: `uv` (uvx), ffmpeg/ffprobe for media tools, network on first
run (uvx resolves the git tag).
