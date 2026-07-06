# Two-minute action-boundary demo

This demo shows MCP Visor as an action boundary, not a model guardrail.

The model can ask for a tool call. MCP Visor decides whether that action is allowed before the MCP server executes it.

## Run it

```bash
go run ./examples/demo-runner
```

The runner builds a temporary mock MCP server and a temporary `mcp-visor` binary, starts the proxy with a default-deny policy, drives JSON-RPC `tools/call` requests through the proxy, then prints the relevant audit evidence.

No real credentials, external services, or network calls are used. The apparent egress destination uses `.invalid`, and the denied call never reaches the mock MCP server.

## What it proves

```text
benign file_read
  -> allowed

sensitive file_read
  -> allowed
  -> session tainted: sensitive_file_accessed

later http_post
  -> denied by block_sensitive_egress
  -> never reaches MCP server
  -> audit log records source, taint, policy rule, sink, and decision
```

## Expected shape

The important lines are:

```text
[1/4] Benign read: allowed
ALLOW: Mock result for tool 'file_read': executed successfully

[2/4] Sensitive read: allowed, but session becomes tainted
ALLOW + TAINT: Mock result for tool 'file_read': executed successfully
session_taint: sensitive_file_accessed

[3/4] Later egress: denied because the session is tainted
DENY: egress control 'block_sensitive_egress'...
This call never reaches the MCP server.

[4/4] Audit proof
session_tainted | tool=file_read | decision=allow
policy_rule: sensitive_file_accessed

tool_call_denied | tool=http_post | decision=deny
policy_rule: block_sensitive_egress
```

## Demo narrative

Use this voice-over or walkthrough script:

1. "This is not prompt filtering. The agent is allowed to ask for actions."
2. "A normal read goes through. MCP Visor is not blocking everything."
3. "The agent then touches a sensitive area, so the session state changes."
4. "A later egress action is denied because the session is now tainted."
5. "The audit log explains the decision: source action, taint, policy rule, sink action, and deny reason."

The punchline:

> The model was triggered. The tool path was blocked.

## Files involved

- `examples/demo-runner/main.go` — scripted demo driver
- `examples/demo-mcp-server/main.go` — mock MCP server
- `examples/policies/session-taint-egress.yaml` — standalone example policy
- `internal/proxy/session_taint.go` — taint and egress-control evaluation
- `internal/proxy/session.go` — session state
- `internal/policy/types.go` — policy schema
