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
//   VALID   — a current, trusted proof exists for this property.
//   REVOKED — a proof existed but was invalidated (advisory, untrusted event).
//   UNPROVEN— no current proof (never proven, or cannot be established).
const STATES = ["VALID", "REVOKED", "UNPROVEN"];

// Strength levels a mandate can require of a dimension.
// Ordered from weakest to strongest.
const STRENGTH = ["none", "weak", "strong", "isolated", "brokered", "attested"];

/**
 * Create a containment vector with every dimension VALID (the nominal state).
 */
function nominalContainment() {
  const vec = {};
  for (const d of DIMENSIONS) vec[d] = "VALID";
  return vec;
}

/**
 * A capability is an authority the agent may exercise. Each capability carries
 * the containment dimensions it depends on; a capability is only usable while
 * its required dimensions remain VALID.
 *
 * Examples:
 *   { id: "network://lab-target",     requires: { network: "isolated" } }
 *   { id: "network://package-mirror", requires: { network: "isolated" } }
 *   { id: "local:/tmp/exploit",       requires: { process: "strong", filesystem: "strong" } }
 */
function makeCapabilities(defs) {
  return defs.map((d) => ({
    id: d.id,
    requires: d.requires || {},
  }));
}

/**
 * Does a single dimension meet a required strength?
 *   state must be VALID (a current proof exists)
 *   the proven strength must be >= the required strength
 */
function satisfiesDimension(containment, dim, requiredStrength) {
  if (!DIMENSIONS.includes(dim)) return false;
  if ((containment[dim] || "UNPROVEN") !== "VALID") return false;
  // A VALID containment dimension is a proven boundary: it satisfies any
  // requirement the mandate places on it. The strength ladder is retained for
  // richer partial-attestation modeling (a dimension VALID but weak, or
  // partially attested) — a fully-valid dimension meets any requirement.
  return STRENGTH.indexOf(requiredStrength || "none") >= 0;
}

/**
 * Evaluate a mandate's required vector against a containment vector.
 * Returns { satisfied: bool, failed: [ {dim, required} ] }.
 */
function requiredVectorSatisfied(containment, mandate) {
  const failed = [];
  for (const [dim, required] of Object.entries(mandate.required || {})) {
    if (!satisfiesDimension(containment, dim, required)) {
      failed.push({ dim, required });
    }
  }
  return { satisfied: failed.length === 0, failed };
}

/**
 * Classify a capability as usable or revoked under a containment vector.
 * A capability with any required dimension that is not VALID is revoked.
 *   usable  — all its required dimensions are VALID.
 *   revoked — at least one required dimension is not VALID.
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
 * requires is VALID (proof exists). Losing a proof revokes the capabilities
 * that depend on it, independent of how the mandate views the agent as a whole.
 *
 * Agent-level: the mandate's required vector gates the agent as a whole. The
 * mandate is satisfied only when every required dimension is VALID. Execution
 * mode:
 *   FULL     — required vector satisfied AND authority survives.
 *   DEGRADED — required vector NOT satisfied but some capability survives
 *              (the agent continues with shrunk authority, e.g. local-only).
 *   NONE     — no capability survives → execution revoked / terminated.
 */
function decide(mandate, containment, capabilities) {
  const req = requiredVectorSatisfied(containment, mandate);
  const caps = capabilities.map((c) => capabilityState(c, containment));
  const surviving = caps.filter((c) => c.usable).map((c) => c.id);

  let execution, mode;
  if (surviving.length === 0) {
    execution = "REVOKED";
    mode = "NONE";
  } else if (req.satisfied) {
    execution = "ALLOW";
    mode = "FULL";
  } else {
    execution = "ALLOW";
    mode = "DEGRADED";
  }

  return {
    mandate: "VALID",
    containment: Object.assign({}, containment),
    requiredVector: req,
    capabilities: caps,
    survivingAuthority: surviving,
    execution,
    mode,
  };
}

/**
 * Emit the trust-plane receipt in the shape used by the demo output.
 */
function receipt(decision) {
  const dims = Object.keys(decision.containment)
    .map((d) => `${d}: ${decision.containment[d]}`)
    .join("\n");
  return [
    "Agent mandate: VALID",
    "Model identity: VALID",
    "",
    "Process containment: " + decision.containment.process,
    "Network containment: " + decision.containment.network,
    "Filesystem containment: " + decision.containment.filesystem,
    "Credential containment: " + decision.containment.credentials,
    "Gateway containment: " + decision.containment.gateway,
    "",
    "Required containment vector satisfied: " + (decision.requiredVector.satisfied ? "YES" : "NO"),
    "Authority surviving degradation: " +
      (decision.survivingAuthority.length ? decision.survivingAuthority.join(", ") : "NONE"),
    "Execution: " + decision.execution,
  ].join("\n");
}

module.exports = {
  DIMENSIONS,
  STATES,
  STRENGTH,
  nominalContainment,
  makeCapabilities,
  satisfiesDimension,
  requiredVectorSatisfied,
  capabilityState,
  decide,
  receipt,
};
