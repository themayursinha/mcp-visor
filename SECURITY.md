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
3. **Secrets redaction** — Strips credentials before they reach tools or logs
4. **Chain detection** — Blocks read→send patterns regardless of individual tool policies
5. **Audit logging** — Append-only O_SYNC writes for every decision

### Known Limitations (v1)

- Policy file integrity relies on host filesystem permissions
- No cryptographic attestation of policy decisions
- No mTLS between visor and remote MCP servers
- Session state is ephemeral (in-memory, lost on restart)
- No built-in rate limiting or DoS protection
- Approval is file-based; an attacker with write access to the approval directory can forge approvals

### Hardening Recommendations

Before deploying beyond local development:

1. Run the visor as a dedicated user with minimal privileges
2. Store the policy file with root/administrator ownership, readable by the visor user
3. Place audit logs on a separate volume with append-only permissions
4. Use the `--approval-dir` flag with a directory only writable by trusted operators
5. Run the MCP server as a separate user with least-privilege access
6. Monitor audit logs for unusual patterns (chains, denials, approval timeouts)
7. Deploy behind a process supervisor (systemd, Docker, Kubernetes)
