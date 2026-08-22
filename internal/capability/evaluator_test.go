package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// evaluator_test.go — ChainEvaluator state machine, envelope attribution
// (E1–E5), derived-boundary binding, and the fail-closed adapter RED test.

func TestBoundaryRequestMissingTargetFailsClosed(t *testing.T) {
	e, err := NewChainEvaluator("sess-4")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-4",
		StepID:    1,
		Tool:      "file_write",
		Effect:    EffectFileAccess,
		// EffectTarget empty on a boundary_request
		Declared: DeclaredAuthority{
			Target:        "research-target",
			WorkspaceRoot: t.TempDir(),
		},
	}
	_, err = e.Eval(context.Background(), step, GenesisPrevHash)
	if err == nil {
		t.Fatalf("missing effect target on boundary_request must error (fail closed)")
	}
}

// Fail-closed: missing declared authority errors → PAUSE.

func TestBoundaryRequestRecordsRequestedCapability(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-26")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-26", StepID: 1, Tool: "host_exec",
		Effect: EffectHostExec, EffectTarget: "bash", Executable: "bash",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("undeclared host_exec must PAUSE, got %s", r.Decision)
	}
	if r.ObservedCapability != CapHostExec {
		t.Fatalf("observed capability = %s, want host_exec", r.ObservedCapability)
	}
	if !hasCap(r.CapabilityAfter, CapHostExec) {
		t.Fatalf("capability_after = %v, want host_exec recorded", r.CapabilityAfter)
	}
	if r.EnvelopeAfter.State != EnvelopeStateBoundaryCrossing {
		t.Fatalf("envelope_after = %s, want BOUNDARY_CROSSING", r.EnvelopeAfter.State)
	}
}

// 4. Signal classification: an IN-WORKSPACE path never emits
// boundary.request_file_outside_workspace; an outside path does.

func TestCapabilityAccumulationRuntimeMarker(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-24")
	if err != nil {
		t.Fatal(err)
	}
	decl := DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws}
	// Step 1: in-envelope observation with memory-corruption marker.
	r1, err := e.Eval(context.Background(), Step{
		SessionID: "sess-24", StepID: 1, Tool: "run",
		Result: "AddressSanitizer: heap-buffer-overflow", Declared: decl,
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("step 1: %v", err)
	}
	if r1.Decision != DecisionAllow {
		t.Fatalf("in-envelope observation must ALLOW, got %s", r1.Decision)
	}
	if !hasCap(r1.CapabilityDelta, CapOOBRead) || !hasCap(r1.CapabilityDelta, CapOOBWrite) {
		t.Fatalf("runtime marker must confirm oob_read/oob_write delta, got %v", r1.CapabilityDelta)
	}
	if r1.CapabilityConfirmation != ConfirmationConfirmed {
		t.Fatalf("confirmation = %s, want confirmed", r1.CapabilityConfirmation)
	}
	if r1.ObservedCapability != CapOOBWrite {
		t.Fatalf("observed capability = %s, want oob_write", r1.ObservedCapability)
	}
	if !hasCap(r1.CapabilityAfter, CapReadSandboxMem) || !hasCap(r1.CapabilityAfter, CapOOBRead) {
		t.Fatalf("step 1 after = %v, want baseline + oob", r1.CapabilityAfter)
	}
	// Step 2: sandbox-escape marker confirms heap_escape/native_exec and
	// accumulates on top of step 1 in lattice order.
	r2, err := e.Eval(context.Background(), Step{
		SessionID: "sess-24", StepID: 2, Tool: "run",
		Result: "container escape", Declared: decl,
	}, r1.Hash)
	if err != nil {
		t.Fatalf("step 2: %v", err)
	}
	if !hasCap(r2.CapabilityDelta, CapHeapEscape) || !hasCap(r2.CapabilityDelta, CapNativeExec) {
		t.Fatalf("escape marker must confirm heap_escape/native_exec delta, got %v", r2.CapabilityDelta)
	}
	// Lattice order: read_sandbox_mem, oob_read, oob_write, heap_escape, native_exec
	want := []string{CapReadSandboxMem, CapOOBRead, CapOOBWrite, CapHeapEscape, CapNativeExec}
	if !sameCaps(r2.CapabilityAfter, want) {
		t.Fatalf("step 2 after = %v, want %v (lattice order)", r2.CapabilityAfter, want)
	}
}

// 3b. Declared intent is provisional: a declared primitive with no confirmed
// delta yields a provisional_capability and provisional confirmation, never
// a pause and never a delta.

func TestCrossSessionRejected(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-A")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-B", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/a.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err == nil {
		t.Fatalf("cross-session step must be rejected")
	}
}

// Replay: duplicate StepID on the same evaluator is rejected.

func TestDeclaredNetworkEgressAllow(t *testing.T) {
	ws := t.TempDir()
	prefix, err := netip.ParsePrefix("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewChainEvaluator("sess-17")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-17", StepID: 1, Tool: "http_get",
		Effect: EffectNetEgress, DestIP: netip.MustParseAddr("10.0.0.7"),
		EffectTarget: "10.0.0.7",
		Declared: DeclaredAuthority{
			Target: "research-target", WorkspaceRoot: ws,
			Network: []netip.Prefix{prefix},
		},
	}
	r, err := e.Eval(context.Background(), step, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("in-envelope egress must ALLOW, got %s", r.Decision)
	}
}

// NoopEvaluator: zero behavioral delta.

func TestEvaluateDeterministic(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-1")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID:    "sess-1",
		StepID:       1,
		Tool:         "file_write",
		Effect:       EffectFileAccess,
		EffectTarget: ws + "/poc.js",
		Declared: DeclaredAuthority{
			Target:        "research-target",
			WorkspaceRoot: ws,
		},
	}
	r1, err := e.Eval(context.Background(), step, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	for i := 0; i < 5; i++ {
		e2, err := NewChainEvaluator("sess-1")
		if err != nil {
			t.Fatal(err)
		}
		r2, err := e2.Eval(context.Background(), step, GenesisPrevHash)
		if err != nil {
			t.Fatalf("Eval iter %d: %v", i, err)
		}
		if r1.Hash != r2.Hash || r1.Decision != r2.Decision {
			t.Fatalf("non-deterministic receipt: %v vs %v", r1.Hash, r2.Hash)
		}
	}
}

// E5-only pause: accumulating artifacts against the declared target is ALLOW.

func TestFileAccessStructuredPathAgreementAllow(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-34")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-34", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/poc.js",
		Path:     ws + "/poc.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}
	r, err := e.Eval(context.Background(), step, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("agreeing in-workspace file must ALLOW, got %s", r.Decision)
	}
	for _, sig := range r.Signals {
		if sig.Kind == SignalBoundaryFileOutside {
			t.Fatalf("agreeing in-workspace file must not emit file_outside signal")
		}
	}
}

// 3. Strict JSONL: Decode must reject trailing bytes (an appended second
// object), leading whitespace, and duplicate keys; a canonical line
// re-encodes byte-identically.

func TestFileAccessStructuredPathInsideRawOutsideFailsClosed(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	e, err := NewChainEvaluator("sess-33")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-33", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: outside + "/poc.js",
		Path:     ws + "/poc.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err == nil {
		t.Fatalf("raw/structured path containment disagreement must error (fail closed)")
	}
}

// 2c. File access with AGREEMENT (structured Path and raw EffectTarget both
// in-workspace) is ALLOW and its receipt carries no boundary signal.

func TestFileAccessStructuredPathOutsideRawInsideFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-32")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-32", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/poc.js",
		Path:     "/etc/passwd",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err == nil {
		t.Fatalf("raw/structured path containment disagreement must error (fail closed)")
	}
}

// 2b. File access with an inside Path but an outside raw EffectTarget
// (reverse disagreement) also fails closed.

func TestHostExecAlwaysPausesWithoutDeclaredSet(t *testing.T) {
	e, err := NewChainEvaluator("sess-3")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID:    "sess-3",
		StepID:       1,
		Tool:         "host_exec",
		Effect:       EffectHostExec,
		EffectTarget: "bash",
		Executable:   "bash",
		Declared: DeclaredAuthority{
			Target:        "research-target",
			WorkspaceRoot: t.TempDir(),
		},
	}
	r, err := e.Eval(context.Background(), step, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("undeclared host_exec must PAUSE (CD-2), got %s", r.Decision)
	}
	if r.Reason != ReasonEffectOutsideEnvelope {
		t.Fatalf("reason = %s, want %s", r.Reason, ReasonEffectOutsideEnvelope)
	}
}

// Fail-closed: a boundary_request with a missing effect target errors → PAUSE.

func TestHostExecDeclaredExecAndHostAllow(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-30")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-30", StepID: 1, Tool: "host_exec",
		Effect: EffectHostExec, EffectTarget: "bash", Executable: "bash",
		DestHost: "prod-host",
		Declared: DeclaredAuthority{
			Target: "research-target", WorkspaceRoot: ws,
			Host:                "Prod-Host.", // non-canonical spelling; normalized by Eval
			DeclaredExecutables: []string{"bash"},
		},
	}
	r, err := e.Eval(context.Background(), step, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("declared exec + matching host must ALLOW, got %s", r.Decision)
	}
	// The receipt carries the NORMALIZED host (lowercased, trailing dot
	// stripped) — canonical identity.
	if r.DeclaredAuthority.Host != "prod-host" {
		t.Fatalf("receipt declared host = %q, want canonical %q", r.DeclaredAuthority.Host, "prod-host")
	}
}

// 1c. Host-exec with no declared executables AND no declared host remains
// the shipped unconditional E5 (byte-identical CD-2).

func TestHostExecDeclaredExecNoHostFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-29")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-29", StepID: 1, Tool: "host_exec",
		Effect: EffectHostExec, EffectTarget: "bash", Executable: "bash",
		DestHost: "evil.example",
		Declared: DeclaredAuthority{
			Target: "research-target", WorkspaceRoot: ws,
			// NO declared host
			DeclaredExecutables: []string{"bash"},
		},
	}
	r, err := e.Eval(context.Background(), step, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("host_exec with no declared host must PAUSE (E5), got %s", r.Decision)
	}
}

// 1b. Host-exec partial authority: a declared host with a matching DestHost
// and a declared executable set is ALLOW only when the exec is declared AND
// the host matches (the full-authority case still works).

func TestHostExecDeclaredStructuredExecutableAllow(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-21")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-21", StepID: 1, Tool: "host_exec",
		Effect: EffectHostExec, EffectTarget: "bash", Executable: "bash",
		DestHost: "prod-host",
		Declared: DeclaredAuthority{
			Target: "research-target", WorkspaceRoot: ws,
			Host:                "prod-host",
			DeclaredExecutables: []string{"bash"},
		},
	}
	r, err := e.Eval(context.Background(), step, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("declared structured executable must ALLOW, got %s", r.Decision)
	}
}

// 2. Net-egress REQUIRES the raw EffectTarget: a valid DestIP with an empty
// raw target is an error even when the CIDR is declared (reviewer's
// adversarial case).

func TestHostExecMissingHostWithDeclaredHostFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-11")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-11", StepID: 1, Tool: "host_exec",
		Effect: EffectHostExec, EffectTarget: "bash", Executable: "bash",
		Declared: DeclaredAuthority{
			Target:              "research-target",
			WorkspaceRoot:       ws,
			Host:                "prod-host",
			DeclaredExecutables: []string{"bash"},
		},
	}
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err == nil {
		t.Fatalf("missing DestHost with declared host must error (fail closed)")
	}
}

// Declared authority validation: malformed declared CIDR fails closed.

func TestHostExecNoDeclaredSetAlwaysPauses(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-31")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-31", StepID: 1, Tool: "host_exec",
		Effect: EffectHostExec, EffectTarget: "bash", Executable: "bash",
		DestHost: "prod-host",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}
	r, err := e.Eval(context.Background(), step, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("host_exec with empty optional sets must PAUSE (shipped CD-2), got %s", r.Decision)
	}
}

// 2. File access: the STRUCTURED Path is canonical. An in-workspace
// EffectTarget with an outside structured Path (reviewer's adversarial case:
// Path="/etc/passwd", EffectTarget in-workspace) must fail closed — the raw
// and structured fields disagree → evaluator error → PAUSE.

func TestHostExecUndeclaredStructuredExecutableFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-20")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-20", StepID: 1, Tool: "host_exec",
		Effect: EffectHostExec, EffectTarget: "bash", Executable: "evil",
		DestHost: "prod-host",
		Declared: DeclaredAuthority{
			Target: "research-target", WorkspaceRoot: ws,
			Host:                "prod-host",
			DeclaredExecutables: []string{"bash"},
		},
	}
	// Mismatch between raw target and structured executable → error → PAUSE.
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err == nil {
		t.Fatalf("raw/structured executable mismatch must error (fail closed)")
	}
}

// 1b. The DECLARED executable set matches against the STRUCTURED executable:
// a declared "bash" with structured "bash" and matching host is ALLOW.

func TestInEnvelopeArtifactAllow(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-2")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID:    "sess-2",
		StepID:       1,
		Tool:         "file_write",
		Effect:       EffectFileAccess,
		EffectTarget: ws + "/poc.js",
		Declared: DeclaredAuthority{
			Target:        "research-target",
			WorkspaceRoot: ws,
		},
	}
	r, err := e.Eval(context.Background(), step, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("in-envelope artifact must ALLOW (CD-1), got %s", r.Decision)
	}
	if r.RequiredProof != nil {
		t.Fatalf("ALLOW must have nil RequiredProof")
	}
}

// CD-2: host_exec with an undeclared target is always PAUSE (shipped semantics).

func TestMalformedDeclaredCIDRFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-12")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-12", StepID: 1, Tool: "http_get",
		Effect: EffectNetEgress, EffectTarget: "10.0.0.7",
		DestIP: netip.MustParseAddr("10.0.0.7"),
		Declared: DeclaredAuthority{
			Target: "research-target", WorkspaceRoot: ws,
			Network: []netip.Prefix{netip.MustParsePrefix("10.0.0.5/24")}, // host bits
		},
	}
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err == nil {
		t.Fatalf("declared network with host bits must error (fail closed)")
	}
}

// Receipt JSON schema: canonical snake_case keys (CD-6) and the exact
// chain-critical fields; the hash covers the canonical JSON with Hash
// cleared.

func TestMissingDeclaredTargetFailsClosed(t *testing.T) {
	e, err := NewChainEvaluator("sess-5")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID:    "sess-5",
		StepID:       1,
		Tool:         "file_write",
		Effect:       EffectFileAccess,
		EffectTarget: t.TempDir() + "/poc.js",
		Declared: DeclaredAuthority{
			WorkspaceRoot: t.TempDir(),
			// Target missing
		},
	}
	_, err = e.Eval(context.Background(), step, GenesisPrevHash)
	if err == nil {
		t.Fatalf("missing declared target must error (fail closed)")
	}
}

// Prior-hash validation with a REAL workspace: a prior that is neither the
// genesis nor the previous receipt's hash must be rejected. This closes the
// reviewer's false-evidence note (the old test passed because /tmp/ws could
// not be resolved, not because the hash was compared).

func TestNetEgressEmptyRawTargetFailsClosed(t *testing.T) {
	ws := t.TempDir()
	prefix, err := netip.ParsePrefix("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewChainEvaluator("sess-22")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-22", StepID: 1, Tool: "http_get",
		Effect: EffectNetEgress, DestIP: netip.MustParseAddr("10.0.0.7"),
		// EffectTarget deliberately empty
		Declared: DeclaredAuthority{
			Target: "research-target", WorkspaceRoot: ws,
			Network: []netip.Prefix{prefix},
		},
	}
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err == nil {
		t.Fatalf("empty raw target with valid DestIP must error (fail closed)")
	}
}

// 2b. Hostname branch: the raw target must canonically equal DestHost.

func TestNetEgressMalformedTargetWithValidDestIPFailsClosed(t *testing.T) {
	ws := t.TempDir()
	prefix, err := netip.ParsePrefix("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewChainEvaluator("sess-10")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-10", StepID: 1, Tool: "http_get",
		Effect: EffectNetEgress, EffectTarget: "not-an-ip",
		DestIP: netip.MustParseAddr("10.0.0.7"),
		Declared: DeclaredAuthority{
			Target: "research-target", WorkspaceRoot: ws,
			Network: []netip.Prefix{prefix},
		},
	}
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err == nil {
		t.Fatalf("malformed EffectTarget with valid DestIP must error (fail closed)")
	}
}

// Fail-closed boundary gap: a missing DestHost is an error when a host is
// declared (not silently treated as in-envelope).

func TestNetEgressRawHostnameMustMatchDestHost(t *testing.T) {
	ws := t.TempDir()
	prefix, err := netip.ParsePrefix("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewChainEvaluator("sess-23")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-23", StepID: 1, Tool: "http_get",
		Effect: EffectNetEgress, EffectTarget: "api.evil.com",
		DestHost: "api.good.com",
		Declared: DeclaredAuthority{
			Target: "research-target", WorkspaceRoot: ws,
			Network: []netip.Prefix{prefix},
		},
	}
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err == nil {
		t.Fatalf("raw hostname != DestHost must error (fail closed)")
	}
}

// 3. Capability accumulation: runtime markers in an in-envelope observation
// step confirm bug A/B deltas (oob_read/oob_write) and accumulate across
// steps in lattice order; baseline read_sandbox_mem is always held.

func TestNoopEvaluatorZeroDelta(t *testing.T) {
	var ev Evaluator = NoopEvaluator{}
	r, err := ev.Eval(context.Background(), Step{}, "")
	if err != nil {
		t.Fatalf("noop must not error: %v", err)
	}
	if r != nil {
		t.Fatalf("noop must return nil receipt, got %+v", r)
	}
}

// Error-to-pause mapping: a PauseReceipt is sealed with ReasonEvaluatorError
// and a stable hash; the proxy uses it to pause (never silent allow).

func TestPriorHashMismatchRejectedValidWorkspace(t *testing.T) {
	ws := t.TempDir()
	decl := DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws}

	// Step 1 with a wrong (non-genesis) prior on the FIRST step.
	e1, err := NewChainEvaluator("sess-6")
	if err != nil {
		t.Fatal(err)
	}
	step1 := Step{
		SessionID: "sess-6", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/a.js", Declared: decl,
	}
	if _, err := e1.Eval(context.Background(), step1, "sha256:0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatalf("non-genesis prior on first step must be rejected")
	}

	// Step 2 with a prior that is NOT step 1's hash must be rejected.
	e2, err := NewChainEvaluator("sess-6")
	if err != nil {
		t.Fatal(err)
	}
	r1, err := e2.Eval(context.Background(), step1, GenesisPrevHash)
	if err != nil {
		t.Fatalf("step 1: %v", err)
	}
	step2 := Step{
		SessionID: "sess-6", StepID: 2, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/b.js", Declared: decl,
	}
	if _, err := e2.Eval(context.Background(), step2, "sha256:0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatalf("wrong prior on step 2 must be rejected")
	}
	// And the correct chained prior must succeed.
	r2, err := e2.Eval(context.Background(), step2, r1.Hash)
	if err != nil {
		t.Fatalf("chained step 2: %v", err)
	}
	if r2.PrevHash != r1.Hash {
		t.Fatalf("step 2 prev = %s, want step 1 hash %s", r2.PrevHash, r1.Hash)
	}
}

// Cross-session: an evaluator for session A rejects a step for session B.

func TestProvisionalDeclaredPrimitive(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-25")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-25", StepID: 1, Tool: "plan",
		Primitive: "heap_escape",
		Declared: DeclaredAuthority{
			Target: "research-target", WorkspaceRoot: ws,
			Intent: "study heap overflow against research target",
		},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("declared intent must never pause, got %s", r.Decision)
	}
	if len(r.CapabilityDelta) != 0 {
		t.Fatalf("declared intent must not confirm a delta, got %v", r.CapabilityDelta)
	}
	if r.ProvisionalCapability == nil || r.ProvisionalCapability.Capability != "heap_escape" {
		t.Fatalf("provisional capability missing/wrong: %+v", r.ProvisionalCapability)
	}
	if r.ProvisionalCapability.Confirmation != ConfirmationProvisional {
		t.Fatalf("provisional confirmation = %s, want provisional", r.ProvisionalCapability.Confirmation)
	}
	if r.CapabilityConfirmation != ConfirmationProvisional {
		t.Fatalf("receipt confirmation = %s, want provisional", r.CapabilityConfirmation)
	}
}

// 3c. A boundary request records the requested capability even though the
// effect pauses (CDR semantics): host_exec PAUSE carries CapHostExec.

func TestRedOptedInEvaluatorErrorNeverSilentAllow(t *testing.T) {
	// An opted-in session with a malformed host_exec boundary step: missing
	// structured executable observation → evaluator error (ErrInvalidStep).
	// The decision path must PAUSE, never ALLOW.
	eval, err := NewChainEvaluator("session-red")
	if err != nil {
		t.Fatalf("NewChainEvaluator: %v", err)
	}

	step := Step{
		SessionID: "session-red",
		StepID:    1,
		Effect:    EffectHostExec,
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: t.TempDir(),
		},
		// Intentionally malformed: no Executable observation, no EffectTarget.
	}

	_, err = eval.Eval(context.Background(), step, GenesisPrevHash)
	if err == nil {
		t.Fatal("RED: expected evaluator error for malformed host_exec boundary step, got nil (silent allow)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("RED: expected ErrInvalidStep, got %v", err)
	}

	// The proxy's error-to-pause mapping: NewPauseReceipt must yield a
	// sealed PAUSE_REQUIRE_NEW_PROOF / evaluator_error receipt. It must
	// never look like an ALLOW and must not leak raw error text.
	receipt, err := NewPauseReceipt("session-red", 1, GenesisPrevHash, err)
	if err != nil {
		t.Fatalf("RED: NewPauseReceipt: %v", err)
	}
	if receipt.Decision != DecisionPauseRequireProof {
		t.Fatalf("RED: decision = %q, want PAUSE_REQUIRE_NEW_PROOF (never silent allow)", receipt.Decision)
	}
	if receipt.Reason != ReasonEvaluatorError {
		t.Fatalf("RED: reason = %q, want evaluator_error", receipt.Reason)
	}
	if receipt.ErrorCode != ErrorCodeInvalidStep {
		t.Fatalf("RED: error_code = %q, want evaluator_invalid_step", receipt.ErrorCode)
	}
	if receipt.Hash == "" || receipt.PrevHash == "" {
		t.Fatal("RED: pause receipt must be sealed with prev_hash and hash")
	}
	enc, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("RED: marshal pause receipt: %v", err)
	}
	if strings.Contains(string(enc), "host_exec missing") {
		t.Fatalf("RED: pause receipt leaks raw error detail: %s", enc)
	}
}

func TestReplayDuplicateStepIDRejected(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-7")
	if err != nil {
		t.Fatal(err)
	}
	decl := DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws}
	step := Step{
		SessionID: "sess-7", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/a.js", Declared: decl,
	}
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err != nil {
		t.Fatalf("step 1: %v", err)
	}
	// Replaying the SAME StepID must be rejected.
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err == nil {
		t.Fatalf("duplicate StepID must be rejected (replay)")
	}
}

// Non-increasing StepID (out of order after a prior step) is rejected.

func TestRev10ArgsDerivedEgressPausesAndRecordsDelta(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev10-egress")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-rev10-egress", StepID: 1,
		Tool: "exec",
		Args: map[string]string{"command": "curl http://evil.example/x"},
		Declared: DeclaredAuthority{
			Target: "target", WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("args-derived egress must PAUSE (E5), got %s", r.Decision)
	}
	if !hasCap(r.CapabilityDelta, CapNetEgress) {
		t.Fatalf("args-derived egress must record net_egress delta, got %v", r.CapabilityDelta)
	}
	if !hasSignalLevel(r.Signals, SignalBoundaryEgress, EvidenceBoundaryRequest) {
		t.Fatalf("receipt must carry boundary.request_egress, got %+v", r.Signals)
	}
}

// A derived boundary signal with NO attributable target anywhere fails
// closed: never ALLOW, never silent. (Effect empty, tool name not a
// host-exec surface, args carry the surface but no executable field.)

func TestRev10ArgsDerivedHostExecPausesAndRecordsDelta(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev10-host")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-rev10-host", StepID: 1,
		Tool: "bash",
		Args: map[string]string{"command": "bash -c id"},
		Declared: DeclaredAuthority{
			Target: "target", WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("args-derived host_exec must PAUSE (E5), got %s", r.Decision)
	}
	if !hasCap(r.CapabilityDelta, CapHostExec) {
		t.Fatalf("args-derived host_exec must record host_exec delta, got %v", r.CapabilityDelta)
	}
	if r.ObservedCapability != CapHostExec {
		t.Fatalf("observed capability = %s, want host_exec", r.ObservedCapability)
	}
	if !hasSignalLevel(r.Signals, SignalBoundaryHostExec, EvidenceBoundaryRequest) {
		t.Fatalf("receipt must carry boundary.request_host_exec, got %+v", r.Signals)
	}
}

// Args-derived egress with an empty structured Effect must also reach the
// decision path: bound to net_egress → E5 PAUSE with a net_egress delta.

func TestRev10DerivedBoundaryNoTargetFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev10-notarget")
	if err != nil {
		t.Fatal(err)
	}
	// Args carry a host-exec signature ("/bin/bash") but neither the tool
	// name nor Step.Executable/EffectTarget name an executable. bindDerived
	// sets EffectTarget to the empty exe → EffectAttributable errors
	// (missing target) → PAUSE via evaluator error, never ALLOW.
	_, err = e.Eval(context.Background(), Step{
		SessionID: "sess-rev10-notarget", StepID: 1,
		Tool: "exec",
		Args: map[string]string{"command": "/bin/bash -c id"},
		Declared: DeclaredAuthority{
			Target: "target", WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatalf("derived boundary signal with no target must fail closed (evaluator error), got nil")
	}
}

// Cross-source dedup (reviewer run 189 finding 2): a build signature AND an
// ELF magic fingerprint both produce artifact.build_artifact; the extractor
// must emit it exactly once.

func TestRev10EvalDerivedHostExecRequestedCapability(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev10-e2e")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-rev10-e2e", StepID: 1,
		Tool: "bash",
		Args: map[string]string{"command": "id"},
		Declared: DeclaredAuthority{
			Target: "target", WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("want PAUSE, got %s", r.Decision)
	}
	if r.Reason != ReasonEffectOutsideEnvelope {
		t.Fatalf("reason = %s, want effect_outside_declared_envelope", r.Reason)
	}
	if !strings.Contains(r.EnvelopeTransition, EnvelopeStateBoundaryCrossing) {
		t.Fatalf("envelope transition = %s, want BOUNDARY_CROSSING", r.EnvelopeTransition)
	}
}

func TestRev11ArgsOnlyHostExecPrepopulatedNoHostFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev11-args-only2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID: "sess-rev11-args-only2", StepID: 1,
		Tool:         "exec",
		Args:         map[string]string{"command": "/bin/bash -c id"},
		Executable:   "bash",
		EffectTarget: "bash",
		Declared: DeclaredAuthority{
			Target:              "target",
			WorkspaceRoot:       ws,
			DeclaredExecutables: []string{"bash"},
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatalf("args-only host-exec with generic tool must fail closed even with declared executables, got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// The REAL canonical host-exec tool name (bash) must still attribute and
// reach PAUSE (E5) under empty authority — not an error. The derived path
// must not regress the Rev 10 behavior.

func TestRev11ArgsOnlyHostExecWithPrepopulatedFieldsFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev11-args-only")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID: "sess-rev11-args-only", StepID: 1,
		Tool:         "exec",
		Args:         map[string]string{"command": "/bin/bash -c id"},
		Executable:   "bash",
		EffectTarget: "bash",
		DestHost:     "prod-host",
		Declared: DeclaredAuthority{
			Target:              "target",
			WorkspaceRoot:       ws,
			Host:                "prod-host",
			DeclaredExecutables: []string{"bash"},
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatalf("args-only host-exec with generic tool must fail closed (evaluator error → PAUSE), got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// Same finding, executable declared but NO declared host — the args-only
// surface still must not be attributed from caller-supplied fields.

func TestRev11DeclaredHostExecToolNameAttributable(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev11-attr")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-rev11-attr", StepID: 1,
		Tool:     "bash",
		DestHost: "prod-host",
		Args:     map[string]string{"command": "id"},
		Declared: DeclaredAuthority{
			Target:              "target",
			WorkspaceRoot:       ws,
			Host:                "prod-host",
			DeclaredExecutables: []string{"bash"},
		},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("declared bash tool + declared host must evaluate, got %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("declared bash tool + declared host must ALLOW (in-envelope), got %s", r.Decision)
	}
}

func TestRev11HostExecToolNameStillWorks(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev11-real")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-rev11-real", StepID: 1,
		Tool: "bash",
		Args: map[string]string{"command": "bash -c id"},
		Declared: DeclaredAuthority{
			Target: "target", WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("real bash tool must evaluate, got %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("real bash tool under empty authority must PAUSE (E5), got %s", r.Decision)
	}
}

// Reviewer's exact case (finding 2): benign content "crash" contains "sh".
// Must NOT produce any host_exec boundary signal, must NOT error, and under
// empty Effect must evaluate to ALLOW (E1–E3 non-boundary).

func TestRev12FileInsideEmptyEffectStillAllows(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev12-file-in")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-rev12-file-in",
		StepID:    1,
		Tool:      "read_file",
		Path:      ws + "/inside.txt",
		Effect:    "",
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("in-workspace path with empty Effect must evaluate, got %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("in-workspace path with empty Effect must ALLOW (pure observation), got %s", r.Decision)
	}
	if hasSignalLevel(r.Signals, SignalBoundaryFileOutside, EvidenceBoundaryRequest) {
		t.Fatalf("in-workspace path must not emit file-outside boundary, got %+v", r.Signals)
	}
}

// The structured EffectFileAccess path must be unchanged: outside path +
// explicit EffectFileAccess → PAUSE.

func TestRev12FileOutsideEmptyEffectFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev12-file-outside")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID:    "sess-rev12-file-outside",
		StepID:       1,
		Tool:         "read_file",
		Path:         "/etc/passwd",
		EffectTarget: "/etc/passwd",
		Effect:       "",
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatalf("file-outside with empty Effect is UNTYPED → evaluator error → PAUSE, got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// Same finding, raw EffectTarget only (no structured Path): untyped →
// evaluator error → PAUSE.

func TestRev12FileOutsideNoPathFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev12-file-nopath")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID: "sess-rev12-file-nopath",
		StepID:    1,
		Tool:      "file_write",
		Effect:    "",
		Signals: []Signal{
			{
				Kind:          SignalBoundaryFileOutside,
				Observation:   "file /etc/passwd",
				EvidenceLevel: EvidenceBoundaryRequest,
				SourceDigest:  digestOf("/etc/passwd"),
			},
		},
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatalf("file-outside signal with no file path must fail closed (evaluator error → PAUSE), got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// Reviewer's exact reproduction (finding 2): mediated `shell -c id` args
// invocation via a generic tool must emit a host-exec boundary signal and
// FAIL CLOSED (evaluator error → PAUSE) — never reach the empty-effect
// ALLOW branch. The generic `exec` tool name is NOT a host-exec surface
// (Rev 11), so the args-only shell surface has no attributable executable →
// evaluator error → PAUSE.

func TestRev12FileOutsidePrepopulatedSignalFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev12-file-pre")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID: "sess-rev12-file-pre",
		StepID:    1,
		Tool:      "read_file",
		Path:      "/etc/passwd",
		Effect:    "",
		Signals: []Signal{
			{
				Kind:          SignalBoundaryFileOutside,
				Observation:   "file /etc/passwd",
				EvidenceLevel: EvidenceBoundaryRequest,
				SourceDigest:  digestOf("/etc/passwd"),
			},
		},
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatalf("pre-populated file-outside signal with empty Effect is UNTYPED → evaluator error → PAUSE, got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// In-workspace path with empty Effect must still ALLOW (pure observation) —
// the file-boundary fix must not over-trigger on benign in-envelope paths.

func TestRev12FileOutsideRawTargetEmptyEffectFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev12-file-raw")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID:    "sess-rev12-file-raw",
		StepID:       1,
		Tool:         "file_write",
		EffectTarget: "/etc/passwd",
		Effect:       "",
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatalf("raw-target file-outside with empty Effect is UNTYPED → evaluator error → PAUSE, got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// Same finding, pre-populated authoritative signal: the proxy already
// extracted SignalBoundaryFileOutside; with empty Effect it is UNTYPED →
// evaluator error → PAUSE (Rev 14), never ALLOW.

func TestRev12FileOutsideStructuredEffectStillPauses(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev12-file-struct")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID:    "sess-rev12-file-struct",
		StepID:       1,
		Tool:         "read_file",
		Path:         "/etc/passwd",
		EffectTarget: "/etc/passwd",
		Effect:       EffectFileAccess,
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("structured file-access outside must evaluate (PAUSE), got error %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("structured file-access outside must PAUSE (E5), got %s", r.Decision)
	}
}

// A pre-populated file-outside signal with NO file path anywhere must fail
// closed (evaluator error → PAUSE), never ALLOW — the derived file step has
// no canonical target.

func TestRev13FileOutsideNonexistentWorkspaceRootFailsClosed(t *testing.T) {
	e, err := NewChainEvaluator("sess-rev13-root-missing")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID:    "sess-rev13-root-missing",
		StepID:       1,
		Tool:         "read_file",
		Path:         "/nonexistent-root-xyz/etc/passwd",
		EffectTarget: "/nonexistent-root-xyz/etc/passwd",
		Effect:       "",
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: "/nonexistent-root-xyz", // root does NOT exist
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatalf("file path with empty Effect under nonexistent workspace root is UNTYPED → evaluator error → PAUSE, got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// Pre-populated authoritative file-outside signal + empty Effect is UNTYPED
// → evaluator error → PAUSE (Rev 14), never ALLOW, regardless of whether
// the workspace root exists.

func TestRev13PrepopulatedFileOutsideMissingRootFailsClosed(t *testing.T) {
	e, err := NewChainEvaluator("sess-rev13-pre-missing-root")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID: "sess-rev13-pre-missing-root",
		StepID:    1,
		Tool:      "read_file",
		Path:      "/etc/passwd",
		Effect:    "",
		Signals: []Signal{
			{
				Kind:          SignalBoundaryFileOutside,
				Observation:   "file /etc/passwd",
				EvidenceLevel: EvidenceBoundaryRequest,
				SourceDigest:  digestOf("/etc/passwd"),
			},
		},
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: "/nonexistent-root-xyz",
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatalf("pre-populated file-outside signal with empty Effect is UNTYPED → evaluator error → PAUSE, got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// Negative control: an explicit NON-file effect (net_egress) must NEVER emit
// file_outside — Rev 14 removed the fallback scan entirely, so row 8 is
// emitted ONLY inside case EffectFileAccess. Reviewer reproduced
// EffectNetEgress + EffectTarget:"evil.example" emitting BOTH egress and
// file_outside under Rev 12; structurally impossible now.

func TestRev6DualNetworkDestinationsAgreeAllow(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-r6-2")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-r6-2", StepID: 1, Tool: "http_get",
		Effect: EffectNetEgress, EffectTarget: "10.0.0.7",
		DestIP:   netip.MustParseAddr("10.0.0.7"),
		DestHost: "10.0.0.7",
		Declared: DeclaredAuthority{
			Target: "research-target", WorkspaceRoot: ws,
			Network: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		},
	}
	r, err := e.Eval(context.Background(), step, GenesisPrevHash)
	if err != nil {
		t.Fatalf("agreeing structured destinations must ALLOW: %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("agreeing structured destinations must ALLOW, got %s", r.Decision)
	}
}

// 2. ExtractSignals MUST use the structured Step.Path for
// boundary.request_file_outside_workspace when Path is present. Rev 5 used
// only the raw EffectTarget, so a step with Path=/etc/passwd and an
// in-workspace raw EffectTarget produced NO boundary signal (reviewer run
// 181).

func TestRev6DualNetworkDestinationsDisagreeFailClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-r6-1")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-r6-1", StepID: 1, Tool: "http_get",
		Effect: EffectNetEgress, EffectTarget: "10.0.0.7",
		DestIP:   netip.MustParseAddr("10.0.0.7"),
		DestHost: "evil.example",
		Declared: DeclaredAuthority{
			Target: "research-target", WorkspaceRoot: ws,
			Network: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		},
	}
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err == nil {
		t.Fatalf("conflicting DestIP/DestHost must error (fail closed), got ALLOW")
	}
}

// 1b. The legal case: DestIP and DestHost AGREE (same destination) → ALLOW
// under the declared CIDR.

func TestRev7HostExecMalformedObservedHostIsEvaluatorError(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-r7-4")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-r7-4", StepID: 1, Tool: "host_exec",
		Executable: "bash", Effect: EffectHostExec, EffectTarget: "bash",
		DestHost: "bad host!",
		Declared: DeclaredAuthority{
			Target: "t", WorkspaceRoot: ws, Host: "prod-host",
			DeclaredExecutables: []string{"bash"},
		},
	}
	_, err = e.Eval(context.Background(), step, GenesisPrevHash)
	if err == nil {
		t.Fatalf("malformed observed DestHost must be evaluator error, got nil (classified as E5)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("malformed observed DestHost must map to ErrInvalidStep, got %v", err)
	}
}

// 4b. The same rule on net_egress: a malformed observed DestHost is an
// evaluator error even when the raw hostname target is valid — the malformed
// structured field must be rejected before any comparison.

func TestRev7NetEgressMalformedObservedHostIsEvaluatorError(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-r7-5")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-r7-5", StepID: 1, Tool: "http_get",
		Effect: EffectNetEgress, EffectTarget: "api.good.com",
		DestHost: "bad host!",
		Declared: DeclaredAuthority{
			Target: "t", WorkspaceRoot: ws,
			Network: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		},
	}
	_, err = e.Eval(context.Background(), step, GenesisPrevHash)
	if err == nil {
		t.Fatalf("malformed observed DestHost on net_egress must be evaluator error, got nil")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("malformed observed DestHost must map to ErrInvalidStep, got %v", err)
	}
}

// 5. The error code is a stable, safe category — the same class of failure
// always yields the same code, and a raw-value-shaped detail never appears.

func TestRev8HostExecMalformedObservedHostDeclaredHostStillError(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-r8-1d")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-r8-1d", StepID: 1, Tool: "host_exec",
		Executable: "bash", Effect: EffectHostExec, EffectTarget: "bash",
		DestHost: "bad host!",
		Declared: DeclaredAuthority{
			Target: "t", WorkspaceRoot: ws, Host: "prod-host",
			DeclaredExecutables: []string{"bash"},
		},
	}
	_, err = e.Eval(context.Background(), step, GenesisPrevHash)
	if err == nil {
		t.Fatalf("malformed observed DestHost with declared host must be evaluator error, got nil")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("malformed observed DestHost must map to ErrInvalidStep, got %v", err)
	}
}

func TestRev8HostExecMalformedObservedHostEmptyAuthorityIsEvaluatorError(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-r8-1a")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-r8-1a", StepID: 1, Tool: "host_exec",
		Executable: "bash", Effect: EffectHostExec, EffectTarget: "bash",
		DestHost: "bad host!",
		Declared: DeclaredAuthority{Target: "t", WorkspaceRoot: ws},
	}
	_, err = e.Eval(context.Background(), step, GenesisPrevHash)
	if err == nil {
		t.Fatalf("malformed observed DestHost with EMPTY optional authority must be evaluator error, got nil (classified as E5)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("malformed observed DestHost must map to ErrInvalidStep, got %v", err)
	}
	// The proxy's error-to-pause mapping: stable code, evaluator_error reason.
	pr, err := NewPauseReceipt(step.SessionID, step.StepID, GenesisPrevHash, err)
	if err != nil {
		t.Fatalf("NewPauseReceipt: %v", err)
	}
	if pr.Decision != DecisionPauseRequireProof || pr.Reason != ReasonEvaluatorError {
		t.Fatalf("error-to-pause must be PAUSE + evaluator_error, got %s/%s", pr.Decision, pr.Reason)
	}
	if pr.ErrorCode != ErrorCodeInvalidStep {
		t.Fatalf("malformed host must map to stable error_code %q, got %q", ErrorCodeInvalidStep, pr.ErrorCode)
	}
	// No raw detail leaks into the durable receipt.
	if bytes.Contains(mustEncodePause(t, pr), []byte("bad host!")) {
		t.Fatalf("pause receipt leaks raw malformed host: %s", mustEncodePause(t, pr))
	}
}

// 1b. Executable-only partial authority (declared exec set, NO declared host)
// + malformed observed DestHost → evaluator error → PAUSE, never E5.

func TestRev8HostExecMalformedObservedHostExecOnlyAuthorityIsEvaluatorError(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-r8-1b")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-r8-1b", StepID: 1, Tool: "host_exec",
		Executable: "bash", Effect: EffectHostExec, EffectTarget: "bash",
		DestHost: "bad host!",
		Declared: DeclaredAuthority{
			Target: "t", WorkspaceRoot: ws,
			DeclaredExecutables: []string{"bash"}, // exec-only partial authority
		},
	}
	_, err = e.Eval(context.Background(), step, GenesisPrevHash)
	if err == nil {
		t.Fatalf("malformed observed DestHost with EXEC-ONLY partial authority must be evaluator error, got nil (classified as E5)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("malformed observed DestHost must map to ErrInvalidStep, got %v", err)
	}
	pr, err := NewPauseReceipt(step.SessionID, step.StepID, GenesisPrevHash, err)
	if err != nil {
		t.Fatalf("NewPauseReceipt: %v", err)
	}
	if pr.Decision != DecisionPauseRequireProof || pr.Reason != ReasonEvaluatorError {
		t.Fatalf("error-to-pause must be PAUSE + evaluator_error, got %s/%s", pr.Decision, pr.Reason)
	}
	if pr.ErrorCode != ErrorCodeInvalidStep {
		t.Fatalf("malformed host must map to stable error_code %q, got %q", ErrorCodeInvalidStep, pr.ErrorCode)
	}
	if bytes.Contains(mustEncodePause(t, pr), []byte("bad host!")) {
		t.Fatalf("pause receipt leaks raw malformed host: %s", mustEncodePause(t, pr))
	}
}

// 1c. Control: a VALID observed DestHost with the same empty/partial authority
// shapes still pauses as ordinary E5 (decision PAUSE, no error) — the hoist
// must NOT change the E5 verdict for well-formed observations.

func TestRev8HostExecValidObservedHostEmptyAuthorityStillE5(t *testing.T) {
	ws := t.TempDir()
	for name, declared := range map[string]DeclaredAuthority{
		"empty":     {Target: "t", WorkspaceRoot: ws},
		"exec-only": {Target: "t", WorkspaceRoot: ws, DeclaredExecutables: []string{"bash"}},
	} {
		t.Run(name, func(t *testing.T) {
			e, err := NewChainEvaluator("sess-r8-1c-" + name)
			if err != nil {
				t.Fatal(err)
			}
			step := Step{
				SessionID: "sess-r8-1c-" + name, StepID: 1, Tool: "host_exec",
				Executable: "bash", Effect: EffectHostExec, EffectTarget: "bash",
				DestHost: "prod-host",
				Declared: declared,
			}
			r, err := e.Eval(context.Background(), step, GenesisPrevHash)
			if err != nil {
				t.Fatalf("valid observed host must NOT error: %v", err)
			}
			if r.Decision != DecisionPauseRequireProof {
				t.Fatalf("empty/exec-only authority with valid host must PAUSE (E5), got %s", r.Decision)
			}
			if r.Reason != ReasonEffectOutsideEnvelope {
				t.Fatalf("valid-host E5 must carry reason %q, got %q", ReasonEffectOutsideEnvelope, r.Reason)
			}
		})
	}
}

// 1d. Control: a malformed observed DestHost with a DECLARED host that would
// otherwise be out-of-envelope (right exec, wrong host) still errors (fail
// closed), preserving the Rev 7 rule in the full-authority branch.

func TestStepIDNonPositiveRejected(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-9")
	if err != nil {
		t.Fatal(err)
	}
	step := Step{
		SessionID: "sess-9", StepID: 0, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/a.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}
	if _, err := e.Eval(context.Background(), step, GenesisPrevHash); err == nil {
		t.Fatalf("StepID <= 0 must be rejected")
	}
}

// Canonicalization: path outside workspace fails closed; symlink escape
// fails closed when the target exists.

func TestStepIDNotStrictlyIncreasingRejected(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-8")
	if err != nil {
		t.Fatal(err)
	}
	decl := DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws}
	// Step 1 succeeds; replaying or going backwards on the same session fails.
	if _, err := e.Eval(context.Background(), Step{
		SessionID: "sess-8", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/a.js", Declared: decl,
	}, GenesisPrevHash); err != nil {
		t.Fatalf("step 1: %v", err)
	}
	// Same StepID again = replay.
	if _, err := e.Eval(context.Background(), Step{
		SessionID: "sess-8", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/a.js", Declared: decl,
	}, GenesisPrevHash); err == nil {
		t.Fatalf("non-increasing StepID must be rejected (replay)")
	}
	// Lower StepID = out of order.
	if _, err := e.Eval(context.Background(), Step{
		SessionID: "sess-8", StepID: 0, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/a.js", Declared: decl,
	}, GenesisPrevHash); err == nil {
		t.Fatalf("StepID <= 0 must be rejected")
	}
}

// StepID <= 0 is rejected.
