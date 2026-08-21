# Boundary Failure Injection — isolated-vm containment attestation

Demonstrates the core principle from GHSA-864f-rcv7-6rh4 (isolated-vm sandbox escape):

> **The security of a sandbox is bounded by the security of its capability bridge.**
> **Containment proofs are compositional. The bridge is part of the boundary.**

## What it shows

The same agent workload runs in two identical environments that differ **only** in
the isolated-vm version:

| Environment | isolated-vm | Bridge status | Result |
|---|---|---|---|
| `envs/vulnerable` | 7.0.0 | Vulnerable (GHSA-864f-rcv7-6rh4) | 💥 HOST CRASHED (SIGSEGV) |
| `envs/fixed` | 7.0.1 | Fixed | Clean exception, no crash |

The guest holds exactly **one** host capability — an `ivm.Reference` to a tool proxy
(the standard way any sandbox is given any capability). It then reproduces the
published `ExternalCopy` TOCTOU: a stateful index getter returns a real
`ArrayBuffer` on the validating walk and the SMI `0x41414141` on the unchecked
walk, driving the `As<ArrayBuffer>()` cast to dereference an attacker-influenced
address in the host process.

## Why this matters

A Trust Plane that says "sandbox = isolated-vm, therefore contained" is wrong.
Containment is a property of the **entire boundary** — isolate + bindings +
serialization + callbacks + references + host process. The V8 Isolate did not
fail; the marshaling bridge did.

The Visor Trust Plane therefore maintains a **Containment Boundary Manifest** and
treats every guest→host bridge as an independently attestable component. When a
vulnerable runtime version appears, the containment proof is **invalidated
immediately** — even if the agent mandate, tool authority, and network policy are
all valid.

## Quick start

```bash
npm run setup   # installs isolated-vm 7.0.0 + 7.0.1 into envs/
npm run run     # runs the demo: escape repro + Visor boundary decision
npm test        # self-test: asserts vulnerable=affected, fixed=not affected
```

## Expected output (verified on Node 22 / Linux)

```
--- vulnerable env (isolated-vm@7.0.0) ---
💥 HOST CRASHED (SIGSEGV exit 139) — escape reproduced

--- fixed env (isolated-vm@7.0.1) ---
escape-trigger: exception: illegal access

=== Visor Trust Plane: boundary manifest ===
[vulnerable] execution requested
  boundary manifest: isolated-vm 7.0.0
  security attestation: GHSA-864f-rcv7-6rh4 affected
  guest/host containment: UNPROVEN
  execution: DENY
  receipt:
    Agent mandate: VALID
    Tool authority: VALID
    Network policy: VALID
    Sandbox primitive: V8 Isolate
    Bridge implementation: VULNERABLE
    Containment composition proof: INVALID
    Reason: guest-to-host authority cannot be bounded under this runtime

[fixed] execution requested
  boundary manifest: isolated-vm 7.0.1
  security attestation: no known boundary advisory
  guest/host containment: PROVEN
  execution: ALLOW
```

## Safety note

This is a **contained demonstration** of a published advisory's PoC. It runs
untrusted code in a subprocess and observes the crash; it performs no real
host-side action beyond the minimal trigger. The crash is contained to the child
process (the harness survives). Do not run untrusted code against production
isolated-vm 7.0.0 — upgrade to 7.0.1 / 6.2.0.

## Files

- `scripts/setup-envs.js` — installs both isolated-vm versions into isolated env dirs
- `scripts/run-demo.js` — harness: escape repro + Visor boundary manifest decision
- `scripts/guest-payload.js` — the TOCTOU trigger (official advisory PoC)
- `envs/` — isolated-vm 7.0.0 (vulnerable) and 7.0.1 (fixed) installs

## Related

- GHSA-864f-rcv7-6rh4 — https://github.com/laverdet/isolated-vm/security/advisories/GHSA-864f-rcv7-6rh4
- Endor Labs writeup — https://www.endorlabs.com/learn/ghsa-864f-rcv7-6rh4-critical-type-confusion-vulnerability-in-isolated-vm
- Obsidian: `isolated-vm Sandbox Escape — Boundary Composition and Containment Attestation`
