# MCP Visor Runtime Evidence

- Captured at: 20260622T095749Z UTC
- Code repo: /home/mayur/code/mcp-visor
- Output directory: /home/mayur/research/mcp-visor/evidence/runtime/20260622T095749Z

## Evidence Files

- `go-test-all.txt`: full package test suite.
- `go-vet-all.txt`: static vet pass.
- `proxy-runtime-evidence.txt`: focused proxy tests for fail-closed approval, signed receipt audit evidence, runtime limits, chain approval, output truncation, and webhook/SIEM fan-out.
- `receipt-evidence.txt`: focused receipt tests for signer abstraction, tamper failure, expiry, and nonce uniqueness.

## Interpretation

These files are intended as paper evidence for deterministic runtime enforcement. They are not a benchmark suite; they capture executable checks for the trust-path hardening claims in the manuscript and hardening plan.
