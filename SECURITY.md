# Security Policy

## Reporting a Vulnerability

Do not open a public issue. Email the maintainer directly with:

- Affected version or commit hash
- Reproduction steps
- Impact assessment
- Suggested mitigation if available

## Security Model

MCP Visor is a deterministic policy enforcement proxy. It does not use an LLM to make decisions and cannot be sweet-talked by prompt injection.

### Trust Boundaries

- **Trusted:** The visor binary, policy file, and audit log directory
- **Untrusted:** The MCP client/agent, MCP server, and all tool implementations
- **Partially trusted:** The approval operator (authenticated via filesystem access)

### Defense Layers

1. **Deterministic policy** — No AI in the decision path
2. **Fail-closed** — Unknown tools denied by default
3. **Pattern redaction** — Replaces configured matches in arguments and textual outputs; encoded, structured, and unmatched secrets can pass
4. **Chain detection** — Blocks read→send patterns regardless of individual tool policies
5. **Audit logging** — O_SYNC JSONL for selected events; healthy writes are hash-linked within one logger lifetime

### Known Limitations

- Policy file integrity relies on host filesystem permissions
- No complete per-call audit ledger; plain allows and output-only redaction lack standalone events
- Audit hash linkage resets for each logger instance and on file reopen
- Audit write failure can leave a later stored event referencing an event that was not persisted
- Policy hot reload does not atomically refresh redaction and approval settings
- Remote HTTP+SSE is experimental; post-handshake relay and complete mTLS configuration need hardening
- Built-in TCP/UDP SIEM export is plaintext and uses a reduced pre-logger event that does not inherit JSONL logger redaction or hash-link fields
- No end-to-end cryptographic attestation of all policy decisions
- Session state is ephemeral (in-memory, lost on restart)
- No built-in rate limiting or DoS protection
- Approval is file-based; an attacker with write access to the approval directory can forge approvals
- Invalid deny/chain/redaction regexes and unknown rule types are not fully fail-closed at `serve` time
- Declared destination fields are not enforced; path rules omit `uri`, and basename-only sensitive-file matching has gaps
- OTLP `policy.reason`, dashboard/trace data, and pre-logger SIEM/webhook events can expose values not removed by configured redaction
- Notification-form `tools/call` is blocked on stdio and remote client paths (no relay, no JSON-RPC response).
- Recognizable malformed `tools/call` envelopes with an `id` receive an error response and are not relayed; unrelated invalid JSON is still forwarded unchanged.
- Strict lint is not a complete enforcement gate; the linter-only composite rule passes, and `--no-warnings` can neutralize strict warning failures

### Hardening Recommendations

Before deploying beyond local development:

1. Run the visor as a dedicated user with minimal privileges
2. Store the policy file with root/administrator ownership, readable by the visor user
3. Place audit logs on a separate volume with append-only permissions
4. Use the `--approval-dir` flag with a directory only writable by trusted operators
5. Run the MCP server as a separate user with least-privilege access
6. Monitor audit logs for unusual patterns (chains, denials, approval timeouts)
7. Deploy behind a process supervisor (systemd, Docker, Kubernetes)
