# ADR: VerifiedActorContext v1 transport (AIP → Visor)

Status: accepted  
Date: 2026-09-14  
Card: `t_aebbba96` (AIP+Visor Phase 1)

## Decision

The trusted AIP → Visor seam is a **process-start file descriptor** (`mcp-visor serve -verified-actor-fd 3`). `visor-session` writes one JSON `VerifiedActorContext` object to a pipe, `dup2`s the read end onto fd 3 with `FD_CLOEXEC` cleared, then `exec`s visor. Visor reads and closes that fd during `serve` startup. The MCP JSON-RPC stream on stdin is unchanged.

## Rejected transports

| Option | Why not |
|---|---|
| MCP `tools/call` arguments / `_meta` / `_verified_actor` | The model and the MCP client can populate it. Invariant 1 forbids this. |
| In-proxy JWT/DPoP on every `tools/call` (the “proposed later seam” in AIP `docs/visor-integration.md`) | Same: the MCP client supplies the token. |
| Environment variables | Inherited from the process that launched visor; a caller who can start visor can set them. |
| A path the agent can write | TOCTOU on a shared filesystem; same-UID overwrite between write and read. |
| Stdin preamble | `visor-session` `exec`s visor so stdin **is** the MCP client stream. Injecting a preamble requires remaining a wrapper, which breaks signal delivery. |

Direct `mcp-visor serve -client-id …` without `visor-session` remains spoofable. That is residual Mode A risk, not this seam.

## H44

`lineage_require` stays an optional policy constraint over the session identity. It is not a second identity authority and not a third capability-token format. AIP owns identity/delegation facts; Visor owns the `tools/call` decision.

## `server_received_call`

Phase 1 proves deny-before-relay at `interceptAndModify` (same honesty bar as H49). A recording mock MCP helper is a named observer of whether a `tools/call` was forwarded, not a Phase 2 network-isolation topology. Complete mediation (agent has no route to the backend) is Phase 2.

## Standalone Visor

`--client-id` remains for non-AIP deployments. `settings.require_verified_actor: true` fails closed when the process-start context is missing, expired, or structurally invalid.
