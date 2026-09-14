# Compatibility

This table records combinations that automated tests actually exercise. It is
not a support matrix and it does not claim an integrated Agent Identity Plane
× MCP Visor deployment.

No released AIP and mcp-visor pair has yet been exercised together end to end.
The first row proves the AIP launcher contract in default CI. The second proves
Visor's MCP interoperability independently via the `interop` build tag; that
tag is **not** part of the default `go test ./...` CI job. Cross-compilation
artifacts for other operating systems are not compatibility tests.

| AIP version | mcp-visor version | MCP protocol tested | Deployment mode tested | OS tested | Evidence |
|---|---|---|---|---|---|
| `v1.0.0` | Unversioned launcher stub; no Visor binary exercised | — | Loopback identity-only gateway → `visor-session` argument construction and stub process launch | Ubuntu 24.04 CI (`go test ./...`) | AIP `TestFetchIdentityOnlyMapping`, `TestCommandThenStubVisor`, `TestCommandRejectsIdentityFlags` |
| — | `v1.4.1` | Not asserted (clients offer `2024-11-05`; `interopInit` does not check the negotiated `result.protocolVersion`) | Real filesystem/fetch servers over stdio; local loopback HTTP+SSE mock | Ubuntu 24.04; tagged interop suite, not default CI; reproduce recipe in [interoperability.md](interoperability.md) | Visor `TestInteropFilesystemStdio`, `TestInteropFilesystemTaintEgress`, `TestInteropFetchStdio`, `TestInteropRemotePostHandshake` |

Not listed, because they are not automated compatibility evidence:

- Qwen-MM-Plugins demo (maintainer-run, not CI)
- Python MCP SDK smoke (`tests/interop/python_sdk_client.py`, manual)
- Darwin/Windows (release cross-compile only)
- Hosted remote MCP (explicitly untested; see [interoperability](interoperability.md))
- MCP protocol revisions newer than `2024-11-05`

AIP `v1.0.0` is operator-ready, not a Production claim. mcp-visor `--client-id`
is operator-supplied and is not authenticated. `visor-session` is the supported
launcher path; typing those flags by hand remains spoofable. Complete mediation
(`agent → MCP server` impossible) is a later phase and is not claimed here.
