# MCP Visor development loop

This document defines the repeatable loop for AI-assisted changes to MCP Visor. It keeps agent work bounded, testable, and reviewable.

## Trigger

Run this loop for:

- changes to enforcement, policy, audit, approval, dashboard, telemetry, or CLI behavior
- documentation changes that claim enforcement behavior
- bug fixes that affect allow, deny, chain, taint, approval, or audit decisions
- release preparation or public demo changes

Small typo-only edits may skip the full loop, but should still avoid changing product claims.

## Scope

The loop may inspect and modify the repository only. It must not depend on private notes, local machine paths, credentials, or personal agent tooling.

Public repo artifacts must stay neutral:

- no private paths
- no secrets
- no internal AI tooling names
- no unpublished competitive intelligence
- no unsupported claims about universal enforcement or future roadmap items

## Cycle

1. Read `harness/project-contract.md` and `harness/invariants.md`.
2. Identify the invariant or contract surface touched by the change.
3. For behavior changes, write or update the failing test first.
4. Implement the smallest change that satisfies the test and preserves the contract.
5. Run the harness from the repository root:

   ```bash
   harness/check.sh
   ```

6. Inspect the diff for security, privacy, and positioning risk.
7. Repeat until the harness passes or a clear blocker is recorded.

## Verification

A change is not complete until it has fresh evidence from `harness/check.sh` or an explicit reason why the harness could not run.

The evidence path is:

```text
evidence/harness/<timestamp>/manifest.md
```

Do not commit evidence artifacts.

## Stop conditions

Stop and report the result when one of these is true:

- the relevant tests pass and the full harness passes
- the change is blocked by a missing dependency, failing external service, or unclear requirement
- three fix attempts fail on the same issue
- the requested change would weaken an invariant or expand scope beyond the complexity budget

## Human approval gates

Require explicit maintainer approval before:

- pushing to `main`
- creating or moving release tags
- rewriting git history
- changing public security claims in the README
- weakening default-deny, fail-closed, audit, or no-LLM decision invariants
- adding new external services, network dependencies, or telemetry payload fields

## Final report format

Every completed run should report:

- files changed
- tests or harness command run
- pass/fail result
- evidence manifest path, if produced
- remaining risks or unverified areas

## Relationship to the harness

The loop controls how work repeats. The harness decides whether the result is acceptable.

```text
Loops iterate. Harnesses verify.
```
