# Investor 90-second proof

This is the **real Visor proxy**, not the marketing-site walkthrough.

The site lens is an illustration. This command runs a local mock MCP server, sends three `tools/call` requests through Visor, and checks the audit log plus the server observe-log. The post is denied before relay; the mock server never receives it.

```bash
go run ./examples/demo-runner -investor
```

Record a branded silent film of that same command (from repo root):

```bash
python3 demos/investor-90s/record.py
```

Output: `demos/investor-90s/investor-90s.mp4`

## How to use it in the room

1. Open https://visor-site.vercel.app/ for five seconds. Read the line. Stop.
2. Play `investor-90s.mp4`, **or** run `-investor` live and speak the track below.
3. If they ask “is this production?”, say: synthetic local server, real policy engine, real deny-before-relay. Not a hosted control plane.

Do not show the Proof Console (`-ui`) as the product. It is an examples-only local view.

## Talk track (~80s)

Speak over the beats. Do not improvise a bigger product.

| When | Say |
|------|-----|
| Build line | Visor is a proxy. The model can request any MCP tool. Visor decides before the server sees the call. No LLM in that decision. |
| POLICY | Default deny. After a sensitive read, egress is forbidden for the rest of the session. |
| 1 ALLOW | Harmless read. Allowed. Relayed. |
| 2 ALLOW + TAINT | Customer secrets. Still allowed — we are not hiding the read. The session is now tainted. |
| 3 DENY | The model tries to POST out. Denied. Zero relay. |
| SERVER OBSERVED | Two reads reached the server. The post did not. That is the proof, not a log line we wrote by hand. |
| DECISION EVIDENCE | Taint, rule, deny — committed to the audit log. |
| Closing three lines | Model proposed. Policy authorized. Proxy enforced. |

If they want more: one live `mcp-visor serve` against their own server, not a Trust Plane slide.
