// Package capability: narrow capability-accumulation accounting.
// Default NoopEvaluator; opt-in via config flag. Deterministic, stdlib-only.
//
// evaluator.go — Evaluator interface, NoopEvaluator default, the stateful
// ChainEvaluator, authorization decisions, evidence/effect/signal/capability
// constants, and the fixed capability lattice. This is the production split
// of the design-contract probe (Rev 15): the probe reference lives in the
// planner scratch workspace and is byte-identical in semantics.
package capability

import (
	"context"
	"errors"
	"fmt"
)

const (
	DecisionAllow             = "ALLOW"
	DecisionPauseRequireProof = "PAUSE_REQUIRE_NEW_PROOF"
)

// Reason values.
const (
	ReasonEffectOutsideEnvelope = "effect_outside_declared_envelope"
	ReasonEvaluatorError        = "evaluator_error"
)

// Receipt version; a future breaking change bumps it and consumers reject
// unknown versions.
const ReceiptVersion = 1

// GenesisPrevHash is the predecessor of the first receipt: SHA-256 of the
// empty payload (matches CDR CD-6). Every line carries a non-empty prev_hash.
const GenesisPrevHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e490166ae4ba7b5b37bcd8deac"

// Evidence levels.
const (
	EvidenceDeclaredOnly    = "declared_only"
	EvidenceArtifact        = "artifact"
	EvidenceRuntimeMarker   = "runtime_marker"
	EvidenceBoundaryRequest = "boundary_request"
)

// Effect kinds.
const (
	EffectHostExec     = "host_exec"
	EffectNetEgress    = "net_egress"
	EffectFileAccess   = "file_access"
	EffectCanaryAccess = "canary_access"
)

// Signal kinds (8-kind signal table, §4).
const (
	SignalDeclaredIntent          = "declared.intent"
	SignalArtifactPocCreated      = "artifact.poc_created"
	SignalArtifactBuildArtifact   = "artifact.build_artifact"
	SignalRuntimeMemoryCorruption = "runtime.memory_corruption_marker"
	SignalRuntimeSandboxEscape    = "runtime.sandbox_escape_marker"
	SignalBoundaryHostExec        = "boundary.request_host_exec"
	SignalBoundaryEgress          = "boundary.request_egress"
	SignalBoundaryFileOutside     = "boundary.request_file_outside_workspace"
)

// Capability lattice in fixed partial order (matches CDR model.go exactly).
// read_sandbox_mem is the baseline (held from the start, never a delta,
// never a pause trigger). Arrays on receipts are always emitted in this
// order (CD-6).
const (
	CapReadSandboxMem = "read_sandbox_mem"
	CapOOBRead        = "oob_read"
	CapOOBWrite       = "oob_write"
	CapHeapEscape     = "heap_escape"
	CapNativeExec     = "native_exec"
	CapHostExec       = "host_exec"
	CapNetEgress      = "net_egress"
)

// lattice is the deterministic emission order for capability arrays.
var lattice = []string{
	CapReadSandboxMem,
	CapOOBRead,
	CapOOBWrite,
	CapHeapEscape,
	CapNativeExec,
	CapHostExec,
	CapNetEgress,
}

// CapabilityConfirmation values (CDR D1/CD-3).
const (
	ConfirmationProvisional = "provisional"
	ConfirmationConfirmed   = "confirmed"
)

// ErrInvalidStep is returned for a step that cannot be canonically evaluated
// (missing/empty/malformed effect target on a boundary_request, missing
// declared authority, replay, prior-hash mismatch, unknown receipt version).
// The proxy maps any non-nil error to PAUSE_REQUIRE_NEW_PROOF with
// ReasonEvaluatorError (fail closed, never silent allow).
var ErrInvalidStep = errors.New("capability: invalid step")

// Evaluator reduces observed signals into capability deltas and an
// authorization decision for one step. It is an ACCOUNTING device:
// it never executes effects, never touches protected data, and its
// PAUSE decision routes to the existing approval gate.
//
// Implementations are per-session: one Evaluator instance per SessionID,
// and Eval is NOT safe for concurrent use on the same instance (the proxy
// serializes per-session calls).
type Evaluator interface {
	// Eval processes one tool-call step. prior is the hash of the last
	// receipt (GenesisPrevHash for the first step of a session). It returns
	// the sealed receipt, or (nil, err) on failure. A nil Receipt with a nil
	// error is the NoopEvaluator contract (zero behavioral delta).
	Eval(ctx context.Context, step Step, prior string) (*Receipt, error)
}

// NoopEvaluator is the default. It returns (nil, nil) — a session without
// explicit capability accounting behaves exactly as today.
type NoopEvaluator struct{}

func (NoopEvaluator) Eval(context.Context, Step, string) (*Receipt, error) { return nil, nil }

// ChainEvaluator is the stateful, deterministic production evaluator. It
// enforces the receipt-chain contract (§7.1): one session per instance,
// strictly increasing StepID, prior-hash equality, duplicate/replay
// rejection, cross-session rejection, per-session capability-accumulation
// state, and envelope-state threading. All failures return an error that
// the proxy maps to PAUSE_REQUIRE_NEW_PROOF (ReasonEvaluatorError).
type ChainEvaluator struct {
	sessionID string
	lastStep  int
	lastHash  string
	held      []string // accumulated lattice capabilities (baseline first)
	envelope  string   // running envelope state: HIGH → BOUNDARY_CROSSING
}

// NewChainEvaluator creates a per-session evaluator. A non-empty sessionID
// is required. The capability state starts at the baseline lattice level
// (read_sandbox_mem) and the envelope at HIGH.
func NewChainEvaluator(sessionID string) (*ChainEvaluator, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("%w: missing session", ErrInvalidStep)
	}
	return &ChainEvaluator{
		sessionID: sessionID,
		held:      []string{CapReadSandboxMem},
		envelope:  EnvelopeStateHigh,
	}, nil
}

// Eval validates and reduces one step, sealing a hash-linked receipt.
func (c *ChainEvaluator) Eval(ctx context.Context, step Step, prior string) (*Receipt, error) {
	_ = ctx
	if step.SessionID != c.sessionID {
		return nil, fmt.Errorf("%w: session %q != evaluator session %q", ErrInvalidStep, step.SessionID, c.sessionID)
	}
	if step.StepID <= 0 {
		return nil, fmt.Errorf("%w: non-positive step id", ErrInvalidStep)
	}
	if c.lastStep != 0 && step.StepID <= c.lastStep {
		return nil, fmt.Errorf("%w: step id %d not strictly increasing (last %d) — replay", ErrInvalidStep, step.StepID, c.lastStep)
	}
	if prior == "" {
		return nil, fmt.Errorf("%w: missing prior hash", ErrInvalidStep)
	}
	expected := GenesisPrevHash
	if c.lastStep != 0 {
		expected = c.lastHash
	}
	if prior != expected {
		return nil, fmt.Errorf("%w: prior hash mismatch (step %d)", ErrInvalidStep, step.StepID)
	}

	// Validate declared authority BEFORE any attribution logic.
	if err := ValidateAuthority(step.Declared); err != nil {
		return nil, err
	}

	// Normalize the declared authority so receipt identity (and the hash
	// chain) is deterministic regardless of the original spelling: host is
	// lowercased with the trailing dot stripped, executables are canonical
	// base names, CIDRs are masked. The normalized form is what attribution
	// and the sealed receipt use (reviewer run 179: normalized values, not
	// merely the original spelling, define identity).
	norm := normalizeDeclaredAuthority(step.Declared)
	step.Declared = norm

	// Signal extraction is part of the deterministic step reduction; the
	// signals are included in the sealed receipt so the chain records what
	// was observed (CD-6: receipts carry the observed signals). Extraction
	// runs BEFORE attribution so an args/tool-derived boundary signal can
	// bind to a derived effect kind (Rev 10, reviewer run 189).
	signals := ExtractSignals(step)
	// Rev 14 (Mayur operator decision, run 197): the empty-Effect
	// file-boundary derivation is REMOVED — there is no derived file scan,
	// so there is no path-resolution guard to run here. The parent
	// condition (derived file-outside scan) is eliminated entirely.
	// The untyped fail-closed rule lives in the derivation block below:
	// a file-boundary observation WITHOUT an explicit structured Effect is
	// UNTYPED → evaluator error → PAUSE (never ALLOW, never silent).
	// Non-file effects NEVER trigger file-boundary signals.
	//
	// Rev 10 (reviewer run 189): an args/tool-derived boundary signal with an
	// EMPTY structured Effect must never fall through to the "non-boundary →
	// ALLOW" branch. Bind the signal to a derived effect kind so attribution
	// and capability accounting see the boundary request. When the observed
	// surface provides no attributable target, Eval FAILS CLOSED (evaluator
	// error → PAUSE), never ALLOW. Rev 14: the derived-kind set is host_exec
	// (host-exec tool name only) and net_egress (DestIP/DestHost/args-URL);
	// file_outside has NO derived kind — a file-boundary observation with
	// empty Effect is untyped and fails closed below.
	effectKind := step.Effect
	attribStep := step
	if effectKind == "" {
		effectKind = deriveEffectKind(step, signals)
		if effectKind != "" {
			attribStep = bindDerivedTarget(step, effectKind)
		} else {
			// Rev 14 (Mayur operator decision, run 197): a boundary_request
			// observation with EMPTY structured Effect and NO attributable
			// derived kind is UNTYPED → evaluator error → PAUSE. This covers
			// a pre-populated SignalBoundaryFileOutside (which now has NO
			// derived kind — the file-boundary derivation was removed
			// entirely), and any boundary signal that could not be bound to
			// host_exec/net_egress (e.g. an args-only egress surface with no
			// destination). Untyped boundary observations NEVER reach the
			// empty-effect ALLOW branch.
			if hasBoundarySignal(signals) {
				return nil, fmt.Errorf("%w: untyped boundary request (empty effect, no attributable derived kind)", ErrInvalidStep)
			}
			// No boundary signal on the empty-Effect surface: the step is a
			// pure observation step UNLESS its mediated file surface is
			// outside the workspace (or unresolvable). A file-boundary
			// observation without an explicit Effect is UNTYPED → FAIL
			// CLOSED (evaluator error → PAUSE) — the reviewer's original
			// run-194 repro (Step{Path:"/etc/passwd", Effect:""} → ALLOW)
			// stays closed WITHOUT the removed derivation: no row-8 signal
			// is emitted and no file_access kind is derived; the step simply
			// fails closed. In-workspace paths with empty Effect remain pure
			// observation (ALLOW).
			if fp := fileSurfacePath(step); fp != "" {
				outside, perr := PathOutsideWorkspace(fp, step.Declared.WorkspaceRoot)
				if perr != nil {
					// Missing/nonexistent workspace root or unresolvable
					// path → evaluator error → PAUSE (never a silent
					// empty-signal ALLOW).
					return nil, perr
				}
				if outside {
					return nil, fmt.Errorf("%w: untyped file-boundary observation (empty effect, path outside workspace)", ErrInvalidStep)
				}
			}
		}
	}

	attrib, err := EffectAttributable(attribStep)
	if err != nil {
		return nil, err
	}

	// Rev 7 (reviewer run 183): defensive copy BEFORE receipt construction.
	// The sealed receipt must never alias caller-owned memory — mutating the
	// caller's Step.Signals after Eval must not change the receipt contents
	// or invalidate its hash. ExtractSignals may return step.Signals directly
	// (pre-populated by the proxy); copy before storing.
	signals = cloneSignals(signals)

	// Capability accumulation (CDR D1/D4 semantics): confirmed deltas
	// require a non-declared signal at matching evidence; declared intent
	// is provisional and never a delta. Accumulation is recorded regardless
	// of the authorization decision (a boundary request records the
	// requested capability even though the effect is paused).
	delta := confirmedDelta(step, signals, attrib, c.held)
	before := cloneCaps(c.held)
	after := unionLattice(before, delta)
	observed := highestCapability(delta)
	if !attrib && observed == "" {
		observed = requestedEffectCapability(step)
	}
	confirmation := ConfirmationProvisional
	if len(delta) > 0 {
		confirmation = ConfirmationConfirmed
	}
	var provisional *ProvisionalCapability
	if step.Primitive != "" && len(delta) == 0 {
		provisional = &ProvisionalCapability{
			Capability:    step.Primitive,
			Confirmation:  ConfirmationProvisional,
			EvidenceLevel: EvidenceDeclaredOnly,
		}
	}

	envBefore := EnvelopeState{State: c.envelope}
	envAfter := envBefore
	if !attrib {
		envAfter = EnvelopeState{State: EnvelopeStateBoundaryCrossing}
	}

	r := &Receipt{
		ReceiptVersion:            ReceiptVersion,
		SessionID:                 step.SessionID,
		StepID:                    step.StepID,
		DeclaredAuthority:         step.Declared,
		Signals:                   signals,
		CapabilityBefore:          before,
		CapabilityDelta:           delta,
		CapabilityAfter:           after,
		ObservedCapability:        observed,
		NominalPermissionsChanged: false,
		EffectiveAuthorityChanged: len(delta) > 0 || envAfter.State == EnvelopeStateBoundaryCrossing,
		EnvelopeBefore:            envBefore,
		EnvelopeAfter:             envAfter,
		EnvelopeTransition:        envBefore.State + " -> " + envAfter.State,
		ProvisionalCapability:     provisional,
		CapabilityConfirmation:    confirmation,
	}
	if attrib {
		r.Decision = DecisionAllow
	} else {
		r.Decision = DecisionPauseRequireProof
		r.Reason = ReasonEffectOutsideEnvelope
		r.RequiredProof = &RequiredProof{
			Type:        "fresh_authorization",
			Description: "human approval for effect outside declared envelope",
		}
	}
	if err := r.Seal(prior); err != nil {
		return nil, err
	}
	c.lastStep = step.StepID
	c.lastHash = r.Hash
	c.held = after
	c.envelope = envAfter.State
	return r, nil
}

// AdvanceAfterError records that the proxy sealed a pause receipt for a
// step Eval rejected, so the next Eval continues the same hash-linked
// chain instead of forking around the pause. stepID must be strictly
// greater than lastStep (the proxy's per-session counter); a rewind or
// empty hash is ignored and the live chain is left unchanged.
func (c *ChainEvaluator) AdvanceAfterError(stepID int, pauseHash string) {
	if stepID <= 0 || pauseHash == "" {
		return
	}
	if c.lastStep != 0 && stepID <= c.lastStep {
		return
	}
	c.lastStep = stepID
	c.lastHash = pauseHash
}

// EnvelopeState values (canonical, serialized).
const (
	EnvelopeStateHigh             = "HIGH"
	EnvelopeStateBoundaryCrossing = "BOUNDARY_CROSSING"
)
