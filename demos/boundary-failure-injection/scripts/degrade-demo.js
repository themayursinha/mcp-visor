#!/usr/bin/env node
/**
 * degrade-demo.js — Containment Degradation Demo
 *
 * Driven by the NVIDIA Aug 26 bulletin on NemoClaw/OpenShell:
 *   CVE-2026-65093  sandbox escape,            CVSS 9.9
 *   CVE-2026-65083  provisioning incomplete list, CVSS 9.9
 *   CVE-2026-65092  L7 REST path-traversal network-policy bypass, CVSS 8.5
 *   CVE-2026-65091  malicious-gateway OS command injection, CVSS 8.8
 *   Affected OpenShell 0–0.0.33; fixed v0.0.34. No public PoC; no wild exploitation.
 *
 * A conventional agent platform treats containment as a binary:
 *       sandboxed = true  →  keep running
 * The Visor Trust Plane treats containment as a VECTOR of independently
 * attestable properties. This demo starts a cyber agent with an all-VALID
 * containment vector, then injects attestation events equivalent to two of the
 * disclosed failures and shows that Visor degrades (not crashes) and ultimately
 * revokes authority — without a behavioral classifier noticing an escape first.
 *
 * This is a DEMONSTRATION of a control-plane decision. It runs no exploit, no
 * untrusted code, and takes no real host-side action. It is a deterministic
 * state machine over the containment vector.
 */

const path = require("path");
const {
  nominalContainment,
  makeCapabilities,
  decide,
  receipt,
} = require(path.join(__dirname, "containment-vector.js"));

// A cyber-evaluation mandate. It requires STRONG process isolation, ISOLATED
// (restricted) network connectivity, and BROKERED credentials / separate creds.
const CYBER_MANDATE = {
  required: {
    process: "strong",
    network: "isolated",
    credentials: "brokered",
    gateway: "attested",
  },
};

// The capabilities the mandate granted the agent. EVERY capability is executed
// inside the process boundary, so each carries a process dependency in addition
// to its own dimension. Losing the process proof revokes all of them; losing
// only the network proof revokes just the network-dependent ones.
const CAPABILITIES = makeCapabilities([
  { id: "network://lab-target", requires: { network: "isolated", process: "strong" } },
  { id: "network://package-mirror", requires: { network: "isolated", process: "strong" } },
  { id: "local:/tmp/exploit-work", requires: { process: "strong", filesystem: "strong" } },
  { id: "tool:burp-suite", requires: { process: "strong", gateway: "attested" } },
  { id: "cred:api-signed", requires: { process: "strong", credentials: "brokered" } },
]);

function bind(cont, events) {
  const c = Object.assign({}, cont);
  for (const [dim, state] of events) c[dim] = state;
  return c;
}

let failures = 0;
function assert(cond, msg) {
  const ok = Boolean(cond);
  if (!ok) failures++;
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${msg}`);
  return ok;
}

console.log("Containment Degradation Demo — NVIDIA NemoClaw/OpenShell bulletin");
console.log("================================================================");
console.log("Mandate: process>=strong, network>=isolated, credentials>=brokered, gateway>=attested");
console.log();

// ---- Stage 0: nominal all-VALID -------------------------------------------
let containment = nominalContainment();
let d0 = decide(CYBER_MANDATE, containment, CAPABILITIES);
console.log("--- Stage 0: agent starts, containment vector all VALID ---");
console.log("  " + Object.entries(containment).map(([k, v]) => `${k}: ${v}`).join(", "));
console.log("  execution: " + d0.execution);
console.log("  surviving authority: " + d0.survivingAuthority.join(", "));
console.log();

// ---- Stage 1: inject CVE-2026-65092 (network-policy bypass) ----------------
containment = bind(containment, [["network", "REVOKED"]]);
let d1 = decide(CYBER_MANDATE, containment, CAPABILITIES);
console.log("--- Stage 1: attestation event = CVE-2026-65092 (L7 REST network-policy untrusted) ---");
console.log("  network containment: REVOKED");
console.log("  mandate requires network>=isolated → required vector satisfied: " + (d1.requiredVector.satisfied ? "YES" : "NO"));
console.log("  revoking network capabilities: " + d1.capabilities.filter((c) => !c.usable && c.id.startsWith("network:")).map((c) => c.id).join(", "));
console.log("  surviving authority: " + (d1.survivingAuthority.length ? d1.survivingAuthority.join(", ") : "NONE"));
console.log("  execution: " + d1.execution + " (local-only execution continues)");
console.log();

// ---- Stage 2: inject CVE-2026-65093 (process-isolation escape) ------------
containment = bind(containment, [["process", "REVOKED"]]);
let d2 = decide(CYBER_MANDATE, containment, CAPABILITIES);
console.log("--- Stage 2: attestation event = CVE-2026-65093 (process-isolation untrusted) ---");
console.log("  process containment: REVOKED");
console.log("  mandate requires process>=strong → required vector satisfied: " + (d2.requiredVector.satisfied ? "YES" : "NO"));
console.log("  surviving authority: " + (d2.survivingAuthority.length ? d2.survivingAuthority.join(", ") : "NONE"));
console.log("  execution: " + d2.execution + " → agent TERMINATED");
console.log();

// ---- Receipt --------------------------------------------------------------
console.log("=== Receipt ===");
console.log(receipt(d2));
console.log();

// SELF-TEST
if (process.argv.includes("--self-test")) {
  console.log("=== SELF-TEST ===");
  assert(d0.execution === "ALLOW", "Stage 0: all-VALID vector authorizes execution");
  assert(d0.mode === "FULL", "Stage 0: mode is FULL");
  assert(d0.survivingAuthority.length === CAPABILITIES.length, "Stage 0: all capabilities usable");
  assert(d1.execution === "ALLOW", "Stage 1: network revocation does NOT kill the agent (local-only continues)");
  assert(d1.mode === "DEGRADED", "Stage 1: mode is DEGRADED (partial authority)");
  assert(!d1.requiredVector.satisfied, "Stage 1: required vector becomes unsatisfied");
  assert(
    d1.survivingAuthority.every((id) => !id.startsWith("network:")),
    "Stage 1: all network capabilities revoked"
  );
  assert(
    d1.survivingAuthority.includes("local:/tmp/exploit-work") &&
      d1.survivingAuthority.includes("tool:burp-suite") &&
      d1.survivingAuthority.includes("cred:api-signed"),
    "Stage 1: local exploitation + tool + credential authority survive"
  );
  assert(d2.execution === "REVOKED", "Stage 2: process revocation terminates execution");
  assert(d2.mode === "NONE", "Stage 2: mode is NONE");
  assert(!d2.requiredVector.satisfied, "Stage 2: required vector unsatisfied");
  assert(d2.survivingAuthority.length === 0, "Stage 2: no authority survives degradation");
  assert(
    d2.containment.process === "REVOKED" && d2.containment.network === "REVOKED",
    "Stage 2: process + network containment both REVOKED in receipt"
  );
  console.log(failures === 0 ? "\nSELF-TEST PASS" : `\nSELF-TEST FAIL (${failures})`);
  process.exit(failures === 0 ? 0 : 1);
}
