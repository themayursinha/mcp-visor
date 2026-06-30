# Contributing

## Setup

```bash
git clone https://github.com/themayursinha/mcp-visor
cd mcp-visor
go mod download
```

## Development

```bash
make build     # Build
make test      # Run all tests (68 tests)
make vet       # Run go vet
make demo      # Run the interactive demo
make fmt       # Format code
```

## Before Submitting a PR

```bash
.hermes/harness/check.sh
```

That runs `make fmt`, `make vet`, and `make test`, and writes a local evidence manifest under `evidence/harness/` (gitignored).

## Complexity budget

Do not add features without reading [docs/complexity-budget.md](docs/complexity-budget.md). New work must strengthen core enforcement, demo/adoption, bypass reduction, or harness coverage. Advanced integrations (Vault, SIEM, OTLP, dashboard, remote transport) stay **flag-gated** and documented as optional.

## Code Organization

```
cmd/mcp-visor/         CLI entry point
internal/
  mcp/                 MCP protocol types and JSON-RPC parser
  proxy/               Proxy orchestration, session tracking
  policy/              Policy engine, loader, validator, registry
  audit/               JSONL audit logger with redaction
  redaction/           Argument/output redaction engine
  approval/            File-based human approval workflow
tests/
  integration/         End-to-end proxy tests with mock MCP server
examples/
  demo-mcp-server/     Mock MCP server for testing and demos
  demo-runner/         Interactive security demo
  policies/            Example policy files
  malicious-prompts/   Documented prompt injection scenarios
```

## Harness

- Contract: `.hermes/harness/project-contract.md`
- Invariants → tests: `.hermes/harness/invariants.md`
- Runner: `.hermes/harness/check.sh`

## Adding Features

Pass the complexity budget gate in `docs/complexity-budget.md` first.

- New policy rule types go in `internal/policy/engine.go` (`evaluateRule`)
- New audit event types go in `internal/audit/logger.go`
- Proxy interception logic goes in `internal/proxy/proxy.go` (`interceptAndModify`)
- CLI flags go in `cmd/mcp-visor/main.go`

## Testing

- Unit tests: `go test ./internal/...`
- Integration tests: `go test ./tests/integration/`
- Integration tests build the mock server and visor binaries, then run them as subprocesses
- The mock MCP server at `examples/demo-mcp-server/` speaks the MCP JSON-RPC protocol over stdio

## Dependency Policy

Minimal. The only non-stdlib dependency is `gopkg.in/yaml.v3` for policy parsing. Avoid pulling in frameworks. The visor is a security tool; the TCB must remain small.
