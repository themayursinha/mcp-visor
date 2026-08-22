package capability

import (
	"context"
	"testing"
)

// Codex P2 (PR #76): confirmedDelta used else-if between the two runtime
// marker kinds. ExtractSignals already emits both from one in-envelope
// observation (Result "SIGSEGV sandbox escape", or args payload containing
// both marker classes). The lattice must UNION both confirmed sets on that
// step: oob_read/oob_write AND heap_escape/native_exec. E3 still never
// pauses. This is accounting completeness, not a new post-relay Eval.

func TestP2BothRuntimeMarkerKindsUnionOnOneStep(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-p2-union")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-p2-union",
		StepID:    1,
		Tool:      "run",
		Result:    "SIGSEGV sandbox escape",
		Declared:  DeclaredAuthority{Target: "target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("in-envelope runtime markers must ALLOW (E3 never pauses), got %s", r.Decision)
	}
	wantDelta := []string{CapOOBRead, CapOOBWrite, CapHeapEscape, CapNativeExec}
	if !sameCaps(r.CapabilityDelta, wantDelta) {
		t.Fatalf("both marker kinds on one step must union deltas, got %v want %v", r.CapabilityDelta, wantDelta)
	}
	wantAfter := []string{CapReadSandboxMem, CapOOBRead, CapOOBWrite, CapHeapEscape, CapNativeExec}
	if !sameCaps(r.CapabilityAfter, wantAfter) {
		t.Fatalf("held after both markers = %v, want %v", r.CapabilityAfter, wantAfter)
	}
	if r.ObservedCapability != CapNativeExec {
		t.Fatalf("observed = %s, want native_exec (highest of the unioned delta)", r.ObservedCapability)
	}
}

// Production adapter does not populate Step.Result. Runtime markers still
// scan all args (Rev 15), so a payload containing both classes must union
// the same way on the pre-forward path.
func TestP2BothRuntimeMarkerKindsUnionFromArgsPayload(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-p2-args")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-p2-args",
		StepID:    1,
		Tool:      "write_file",
		Args:      map[string]string{"content": "SIGSEGV sandbox escape"},
		Declared:  DeclaredAuthority{Target: "target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("payload runtime markers must ALLOW, got %s", r.Decision)
	}
	if !hasCap(r.CapabilityDelta, CapOOBRead) || !hasCap(r.CapabilityDelta, CapHeapEscape) {
		t.Fatalf("args payload with both marker classes must union both sets, got %v", r.CapabilityDelta)
	}
}

func TestP2SingleRuntimeMarkerKindUnchanged(t *testing.T) {
	ws := t.TempDir()
	decl := DeclaredAuthority{Target: "target", WorkspaceRoot: ws}

	e1, err := NewChainEvaluator("sess-p2-mem")
	if err != nil {
		t.Fatal(err)
	}
	r1, err := e1.Eval(context.Background(), Step{
		SessionID: "sess-p2-mem", StepID: 1, Tool: "run",
		Result: "AddressSanitizer: heap-buffer-overflow", Declared: decl,
	}, GenesisPrevHash)
	if err != nil {
		t.Fatal(err)
	}
	if hasCap(r1.CapabilityDelta, CapHeapEscape) || hasCap(r1.CapabilityDelta, CapNativeExec) {
		t.Fatalf("memory-only marker must not confirm escape caps, got %v", r1.CapabilityDelta)
	}

	e2, err := NewChainEvaluator("sess-p2-esc")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := e2.Eval(context.Background(), Step{
		SessionID: "sess-p2-esc", StepID: 1, Tool: "run",
		Result: "container escape", Declared: decl,
	}, GenesisPrevHash)
	if err != nil {
		t.Fatal(err)
	}
	if hasCap(r2.CapabilityDelta, CapOOBRead) || hasCap(r2.CapabilityDelta, CapOOBWrite) {
		t.Fatalf("escape-only marker must not confirm oob caps, got %v", r2.CapabilityDelta)
	}
}
