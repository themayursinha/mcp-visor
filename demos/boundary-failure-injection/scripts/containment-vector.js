"use strict";
/**
 * containment-vector.js — Containment Vector Proofs
 *
 * The Visor Trust Plane primitive. "sandboxed = true" is a binary that does not
 * hold. Containment is a CONJUNCTION of independently attestable properties, and
 * an autonomous action may rely only on containment properties for which a
 * current proof exists.
 *
 *   Containment =
 *       provisioning integrity
 *     ∧ process isolation
 *     ∧ filesystem isolation
 *     ∧ network-policy integrity
 *     ∧ gateway integrity
 *     ∧ credential mediation
 *     ∧ runtime integrity
 *
 * If ANY one term fails, ContainmentProof = invalid.
 *
 * This module is a deterministic model, not a product. It exists to prove the
 * semantics before any enforcement lands in the mcp-visor Go proxy. No LLM, no
 * I/O, no lifecycle. Injectable, so the degradation demo can script events.
 *
 * Correctness notes (Codex PR #80 review):
 *  - Each dimension carries an attested STRENGTH, not just a VALID bit. A
 *    requirement is met only if the dimension is VALID and its attested
 *    strength is >= the required strength. Strength is compared, not ignored.
 *  - Execution is authorized only when a MANDATE-APPROVED mode (full or an
 *    explicitly declared degraded mode) has its required vector satisfied.
 *    Degradation is never silently auto-derived; the mandate must declare it.
 *  - A capability is usable only while every dimension it depends on is VALID
 *    and meets its requirement, independent of how the agent is viewed.
 */

const DIMENSIONS = [
  "provisioning",
  "process",
  "filesystem",
  "network",
  "credentials",
  "gateway",
  "runtime",
];

// Attestation state of a single dimension.
//   VALID   — a current, trusted proof exists for this property (with a strength).
//   REVOKED — a proof existed but was invalidated (advisory, untrusted event).
//   UNPROVEN— no current proof (never proven, or cannot be established).
const STATES = ["VALID", "REVOKED", "UNPROVEN"];

// Strength levels a mandate can require of a dimension, weakest to strongest.
// A VALID dimension is attested at one of these; a requirement is satisfied
// only when attested strength >= required strength.
const STRENGTH = ["none", "weak", "strong", "isolated", "brokered", "attested"];

const STATE = (state, strength) =>
  state === "VALID" ? { state, strength: strength || "strong" } : { state, strength: null };

/**
 * Create a containment vector with every dimension VALID at the given strength
 * (default "strong"). The network dimension defaults to "isolated", credentials
 * to "brokered", and gateway to "attested" so a cyber-evaluation mandate's full
 * vector is satisfiable at the nominal state.
 */
function nominalContainment() {
  const defaults = {
    network: "isolated",
    credentials: "brokered",
    gateway: "attested",
  };
  const vec = {};
  for (const d of DIMENSIONS) vec[d] = STATE("VALID", defaults[d] || "strong");
  return vec;
}

/**
 * A capability is an authority the agent may exercise. Each capability carries
 * the containment dimensions it depends on (with a required strength); it is
 * usable only while every one is VALID at or above the required strength.
 *
 *   { id: "network://lab-target", requires: { network: "isolated", process: "strong" } }
 *   { id: "local:/tmp/exploit",   requires: { process: "strong", filesystem: "strong" } }
 */
function makeCapabilities(defs) {
  return defs.map((d) => ({
    id: d.id,
    requires: d.requires || {},
  }));
}

function dimensionState(containment, dim) {
  return containment[dim] && containment[dim].state;
}

function dimensionStrength(containment, dim) {
  return containment[dim] && containment[dim].strength;
}

/**
 * Does a single dimension meet a required strength?
 *   state must be VALID (a current proof exists)
 *   the attested strength must be >= the required strength
 */
function satisfiesDimension(containment, dim, requiredStrength) {
  if (!DIMENSIONS.includes(dim)) return false;
  if (dimensionState(containment, dim) !== "VALID") return false;
  // Fail closed: a requirement with no recognizable strength is not satisfied,
  // even though a VALID dimension trivially meets "none". Requirements should
  // always be explicit; defaulting an absent one to "none" silently weakens the
  // check. Callers always pass explicit strengths (see CAPABILITIES / mandates).
  const reqIdx = STRENGTH.indexOf(requiredStrength);
  if (reqIdx < 0) return false;
  const attIdx = STRENGTH.indexOf(dimensionStrength(containment, dim) || "none");
  return attIdx >= reqIdx;
}

/**
 * Deep-clone a containment vector so that a decision holds an independent
 * snapshot of each dimension's {state, strength}. A shallow copy would share
 * the nested dimension objects with the caller, so a later in-place mutation
 * (e.g. containment.process.state = "REVOKED") would retroactively change an
 * earlier decision's receipt while its cached satisfied/execution stayed stale.
 */
function cloneContainment(containment) {
  const out = {};
  for (const d of DIMENSIONS) {
    const dim = containment[d];
    out[d] = dim && typeof dim === "object"
      ? { state: dim.state, strength: dim.strength }
      : dim;
  }
  return out;
}

/**
 * A required vector is only "declared" if the mandate actually provides a
 * non-empty mapping of dimensions for that mode. An empty/undefined full mode
 * is NOT a valid approval to run at FULL — otherwise a mandate that declares
 * only `degraded` would be treated as approving FULL (the explicit-mode
 * guarantee is bypassed).
 */
function hasDeclaredVector(required) {
  return required != null && Object.keys(required).length > 0;
}

/**
 * Evaluate a required vector (from a mandate mode) against a containment vector.
 * Returns { satisfied, failed: [{dim, required}] }.
 */
function requiredVectorSatisfied(containment, required) {
  const failed = [];
  for (const [dim, req] of Object.entries(required || {})) {
    if (!satisfiesDimension(containment, dim, req)) {
      failed.push({ dim, required: req });
    }
  }
  return { satisfied: failed.length === 0, failed };
}

/**
 * Classify a capability as usable or revoked under a containment vector.
 * A capability with any required dimension not VALID-at-required-strength is
 * revoked. Returns { id, usable, unmet: [{dim, required}] }.
 */
function capabilityState(cap, containment) {
  const unmet = Object.entries(cap.requires).filter(
    ([dim, req]) => !satisfiesDimension(containment, dim, req)
  );
  return { id: cap.id, usable: unmet.length === 0, unmet };
}

/**
 * The Trust Plane decision.
 *
 * Capability-level: each capability is usable only while every dimension it
 * requires is valid at the required strength. Losing a proof revokes the
 * capabilities that depend on it.
 *
 * Agent-level: execution is authorized only when a mandate-APPROVED mode has
 * its required vector satisfied. A mandate declares zero or more modes:
 *   - `full`:     the fully required vector (normal operation).
 *   - `degraded`: an EXPLICITLY approved fallback vector. Degradation is never
 *                 auto-derived; if the full vector is unsatisfied, the agent
 *                 may continue only at a mode the mandate has pre-approved.
 *
 * Modes are ranked; the strongest satisfiable mode is selected:
 *   FULL     — the full required vector is satisfied.
 *   DEGRADED — full is unsatisfied but an approved degraded vector is satisfied.
 *   NONE     — no approved mode is satisfied → execution revoked / terminated.
 */
function decide(mandate, containment, capabilities) {
  const caps = capabilities.map((c) => capabilityState(c, containment));
  const surviving = caps.filter((c) => c.usable).map((c) => c.id);

  // The full approved vector: mandate.full, or the legacy `required`. It is
  // only satisfiable if actually declared — an empty/undefined full mode is
  // NOT an approval to run, else a mandate declaring only `degraded` would be
  // treated as approving FULL (P1).
  const fullRequired = mandate.full || mandate.required;
  const fullDeclared = hasDeclaredVector(fullRequired);
  const full = fullDeclared ? requiredVectorSatisfied(containment, fullRequired) : null;
  // Same non-empty declaration guard for both modes. An empty/undefined
  // degraded vector is NOT an approved fallback — otherwise `degraded: {}`
  // would authorize DEGRADED with zero containment requirements (this was the
  // same P1 class fixed for `full`, now applied consistently to `degraded`).
  const degraded = hasDeclaredVector(mandate.degraded)
    ? requiredVectorSatisfied(containment, mandate.degraded)
    : null;

  let mode, execution, activeRequired;
  if (full && full.satisfied) {
    mode = "FULL";
    execution = "ALLOW";
    activeRequired = fullRequired;
  } else if (degraded && degraded.satisfied) {
    mode = "DEGRADED";
    execution = "ALLOW";
    activeRequired = mandate.degraded;
  } else {
    mode = "NONE";
    execution = "REVOKED";
    activeRequired = fullDeclared ? fullRequired : mandate.degraded;
  }

  return {
    mandate: "VALID",
    containment: cloneContainment(containment), // deep snapshot (P2)
    mode,
    fullVector: full,
    degradedVector: degraded,
    activeRequired,
    capabilities: caps,
    survivingAuthority: surviving,
    execution,
  };
}

/**
 * Emit the trust-plane receipt in the shape used by the demo output.
 */
function receipt(decision) {
  const dims = DIMENSIONS.map(
    (d) => {
      const st = dimensionState(decision.containment, d);
      const str = dimensionStrength(decision.containment, d);
      return `${d}: ${st || "UNPROVEN"}${str ? ` (${str})` : ""}`;
    }
  ).join("\n");
  return [
    "Agent mandate: VALID",
    "Model identity: VALID",
    "",
    dims,
    "",
    "Operating mode: " + decision.mode,
    "Full mandate vector satisfied: " +
      (decision.fullVector ? (decision.fullVector.satisfied ? "YES" : "NO") : "N/A (not declared)"),
    "Authority surviving degradation: " +
      (decision.survivingAuthority.length ? decision.survivingAuthority.join(", ") : "NONE"),
    "Execution: " + decision.execution,
  ].join("\n");
}

module.exports = {
  DIMENSIONS,
  STATES,
  STRENGTH,
  STATE,
  nominalContainment,
  makeCapabilities,
  dimensionState,
  dimensionStrength,
  satisfiesDimension,
  requiredVectorSatisfied,
  capabilityState,
  hasDeclaredVector,
  cloneContainment,
  decide,
  receipt,
};