# Boundary Failure Injection — containment attestation

Two demonstrations of the same thesis — **containment is compositional and must
be attested, never assumed** — driven by two real sandbox-disclosure events:

> **The security of a sandbox is bounded by the security of its capability bridge.**
> **Containment proofs are compositional. The bridge is part of the boundary.**

## Why this directory holds two demos

| Demo | Trigger | What it proves |
|---|---|---|
| **boundary-failure-injection** (below) | GHSA-864f-rcv7-6rh4 (isolated-vm type confusion) | The bridge is part of the boundary; a single vulnerable component invalidates the whole containment proof. |
| **containment-degradation** (below) | NVIDIA Aug 26 bulletin (NemoClaw/OpenShell) | `sandboxed = true` is a binary that does not hold. Containment is a **vector** of independently attestable properties, so authority degrades dimension-by-dimension instead of assuming one generic bit. |

---

## Demo 1 — Boundary Failure Injection (isolated-vm)

Demonstrates the core principle from GHSA-864f-rcv7-6rh4 (isolated-vm sandbox escape).

### What it shows

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

### Why this matters

A Trust Plane that says "sandbox = isolated-vm, therefore contained" is wrong.
Containment is a property of the **entire boundary** — isolate + bindings +
serialization + callbacks + references + host process. The V8 Isolate did not
fail; the marshaling bridge did.

The Visor Trust Plane therefore maintains a **Containment Boundary Manifest** and
treats every guest→host bridge as an independently attestable component. When a
vulnerable runtime version appears, the containment proof is **invalidated
immediately** — even if the agent mandate, tool authority, and network policy are
all valid.

### Quick start

```bash
npm run setup   # installs isolated-vm 7.0.0 + 7.0.1 into envs/ (needs a build toolchain)
npm run run     # runs the demo: escape repro + Visor boundary decision
npm run test:boundary   # self-test: vulnerable crashes SIGSEGV/139; fixed refuses cleanly
```

### Safety note

This is a **contained demonstration** of a published advisory's PoC. It runs
untrusted code in a subprocess and observes the crash; it performs no real
host-side action beyond the minimal trigger. The crash is contained to the child
process (the harness survives). Do not run untrusted code against production
isolated-vm 7.0.0 — upgrade to 7.0.1 / 6.2.0.

---

## Demo 2 — Containment Degradation (NVIDIA NemoClaw/OpenShell)

Driven by NVIDIA's August 26 security bulletin on the containment layer
underneath NemoClaw:

| CVE | Type | CVSS | OpenShell |
|---|---|---|---|
| CVE-2026-65093 | Sandbox escape | 9.9 | affected 0–0.0.33 |
| CVE-2026-65083 | Sandbox provisioning incomplete disallowed-input list | 9.9 | affected 0–0.0.33 |
| CVE-2026-65092 | L7 REST path-traversal network-policy bypass | 8.5 | affected 0–0.0.33 |
| CVE-2026-65091 | Malicious-gateway OS command injection | 8.8 | affected |

Fixed in **v0.0.34**. No public PoC; no in-the-wild exploitation reported.

### The architectural failure

NVIDIA disclosed **four independent attack paths through the same trust layer**:
provisioning weakness → escape; search-path weakness → escape; REST path
traversal → network-policy bypass; malicious gateway → OS command injection.

This matters for increasingly **cyber-capable agents**. If the model can
actively search for weaknesses in the boundary, the assumption *"the agent might
be adversarial, but the sandbox constrains it"* holds only while every relevant
sandbox component remains trustworthy.

The control that failed is treating containment as a **binary property**:
`sandboxed = true`.

In reality, containment is a **conjunction** of independently attestable
properties:

```
Containment =
    provisioning integrity
  ∧ process isolation
  ∧ filesystem isolation
  ∧ network-policy integrity
  ∧ gateway integrity
  ∧ credential mediation
  ∧ runtime integrity
```

If **any one** term fails, `ContainmentProof = invalid`. This is especially
true for CVE-2026-65092 — an agent can still be technically "inside the sandbox"
while the **network effect boundary** has already failed.

### What the demo shows

The Visor Trust Plane distinguishes containment dimensions instead of carrying
one generic "sandbox = trusted" bit. It runs a cyber agent with an all-`VALID`
containment vector, then injects attestation events equivalent to the
disclosures and shows authority **degrading** (not blindly crashing):

* **Stage 0 — nominal:** process, filesystem, network, credential, gateway all
  `VALID`. Mandate (`process≥strong, network≥isolated, credentials≥brokered,
  gateway≥attested`) satisfied → mode `FULL`, all capabilities usable.
* **Stage 1 — inject CVE-2026-65092:** `network` containment → `REVOKED`. The
  Trust Plane revokes `network://lab-target` and `network://package-mirror`,
  preserves **local-only** exploitation and tool/credential authority, mode
  `DEGRADED`. A conventional platform would keep running because the process is
  still alive; Visor knows the network effect boundary is gone.
* **Stage 2 — inject CVE-2026-65093:** `process` containment → `REVOKED`. Every
  capability depends on the process boundary, so **all** execution authority is
  revoked → agent **TERMINATED**, mode `NONE`.

The receipt across Stage 2:

```
Agent mandate: VALID
Model identity: VALID

Process containment: REVOKED
Network containment: REVOKED
Filesystem containment: VALID
Credential containment: VALID
Gateway containment: VALID

Required containment vector satisfied: NO
Authority surviving degradation: NONE
Execution: REVOKED
```

No behavioral classifier had to notice the model attempting an escape. The
attestation event alone drives the denial.

### The principle (Proof-Carrying Autonomy)

> **Containment is not a property. It is a set of independently provable boundaries.**
> An autonomous action may rely only on containment properties for which a
> current proof exists.

If network isolation becomes untrusted but filesystem isolation stays sound, the
Trust Plane does **not** treat the whole environment identically. It **shrinks
authority** (revoke network capabilities, preserve local-only execution) rather
than either blindly continuing or killing everything indiscriminately.

### Quick start

```bash
npm run run:degrade   # run the degradation demo
npm run test:degrade  # self-test: asserts FULL → DEGRADED → NONE + receipt shape
```

No exploit, no untrusted code. A deterministic state machine over the
containment vector.

---

## Files

| Path | Purpose |
|---|---|
| `scripts/setup-envs.js` | Installs isolated-vm 7.0.0 + 7.0.1 into `envs/` (Demo 1) |
| `scripts/run-demo.js` | Demo 1 harness: escape repro + boundary manifest decision |
| `scripts/guest-payload.js` | Demo 1 TOCTOU trigger (official advisory PoC) |
| `scripts/containment-vector.js` | Demo 2 model: containment vector proofs + Trust Plane decision |
| `scripts/degrade-demo.js` | Demo 2 harness: inject CVE-65092 then CVE-65093, degrade + terminate |
| `envs/` | isolated-vm 7.0.0 (vulnerable) and 7.0.1 (fixed) installs |

## Related

- GHSA-864f-rcv7-6rh4 — https://github.com/laverdet/isolated-vm/security/advisories/GHSA-864f-rcv7-6rh4
- Endor Labs writeup — https://www.endorlabs.com/learn/ghsa-864f-rcv7-6rh4-critical-type-confusion-vulnerability-in-isolated-vm
- NVIDIA OpenShell / NemoClaw security bulletin — https://nvidia.custhelp.com/app/answers/detail/a_id/5872
