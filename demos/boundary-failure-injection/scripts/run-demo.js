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

function runGuest(envDir) {
  // The child requires the payload module (avoids string-in-string quoting hell).
  const payloadPath = JSON.stringify(path.join(__dirname, "guest-payload.js"));
  const script = `
    const ivm = require('isolated-vm');
    const payload = require(${payloadPath});
    const isolate = new ivm.Isolate({ memoryLimit: 64 });
    const ctx = isolate.createContextSync();
    // give the guest exactly one constrained host reference (the tool proxy).
    // guest-payload.js documents the contract "ivm.Reference to { x: 1 }":
    // x must be present so ref.getSync('x', { externalCopy: true }) resolves
    // to the real ExternalCopy constructor instead of an undefined-property
    // fallback (Codex P1, PR #75).
    const toolProxy = new ivm.Reference({ x: 1, name: 'mcp-tool-proxy', call: () => ({ ok: true }) });
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
  for (const [name] of Object.entries(envs)) {
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

  // Self-test: version classification, documented host-reference contract, and
  // actual runGuest outcomes (vulnerable must crash; fixed must refuse cleanly).
  if (selfTest) {
    const vulnerableAffected = isAffected(versions.vulnerable);
    const fixedAffected = isAffected(versions.fixed);
    const vulnerable = results.vulnerable;
    const fixed = results.fixed;
    console.log("\n=== SELF-TEST ===");
    console.log(`vulnerable affected: ${vulnerableAffected} (expect true)`);
    console.log(`fixed affected: ${fixedAffected} (expect false)`);
    console.log(`vulnerable crash: ${Boolean(vulnerable && vulnerable.crash)} (expect SIGSEGV/139)`);
    console.log(`fixed crash: ${Boolean(fixed && fixed.crash)} (expect false)`);
    console.log(`fixed ok: ${Boolean(fixed && fixed.ok)} (expect true, clean refusal)`);
    const fail = (msg) => {
      console.error(`SELF-TEST FAIL: ${msg}`);
      process.exit(1);
    };
    if (!vulnerableAffected || fixedAffected) {
      fail("version classification: vulnerable must be affected, fixed must not");
    }
    if (!vulnerable || !vulnerable.ok || !vulnerable.crash) {
      fail("vulnerable env must crash (SIGSEGV / status 139); got: " + JSON.stringify(vulnerable));
    }
    if (!fixed || !fixed.ok || fixed.crash) {
      fail("fixed env must not crash and must yield a clean refusal; got: " + JSON.stringify(fixed));
    }
    if (!/exception/i.test((fixed && fixed.output) || "")) {
      fail("fixed env must yield a clean refusal/exception; got: " + ((fixed && fixed.output) || ""));
    }
    console.log("SELF-TEST PASS");
    process.exit(0);
  }
}

main();
