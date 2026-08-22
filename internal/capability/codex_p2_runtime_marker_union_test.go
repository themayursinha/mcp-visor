package capability

import (
	"context"
	"strings"
	"testing"
)

// Parent class (PR #76 Codex P2s): confirmedDelta reduced independently
// observed signals through a single Effect (else-if on markers; host_exec
// precedence over egress). Deltas are a UNION over signals. Effect remains
// attribution-only (one kind for E5 vs ALLOW). E3 still never pauses.
// Runtime-marker confirmation stays on pure in-envelope observation only.

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

func TestP2BothBoundaryKindsUnionOnOneStep(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-p2-both-bound")
	if err != nil {
		t.Fatal(err)
	}
	// Attribution uses one derived Effect (host_exec from the tool name).
	// Accounting must still union the independently observed egress signal.
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-p2-both-bound",
		StepID:    1,
		Tool:      "bash",
		Args:      map[string]string{"command": "bash -c 'curl https://example.com'"},
		Declared:  DeclaredAuthority{Target: "target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("dual boundary request must PAUSE (E5), got %s", r.Decision)
	}
	if !hasCap(r.CapabilityDelta, CapHostExec) || !hasCap(r.CapabilityDelta, CapNetEgress) {
		t.Fatalf("host-exec + egress on one step must union both deltas, got %v", r.CapabilityDelta)
	}
	if !hasSignal(r.Signals, SignalBoundaryHostExec) || !hasSignal(r.Signals, SignalBoundaryEgress) {
		t.Fatalf("receipt must carry both boundary signals, got %+v", r.Signals)
	}
}

func TestP2EgressSignalObservationUsesStructuredDest(t *testing.T) {
	step := Step{
		Tool:     "web_fetch",
		Args:     map[string]string{"url": "https://api.example.com"},
		DestHost: "api.example.com",
	}
	var obs string
	for _, s := range ExtractSignals(step) {
		if s.Kind == SignalBoundaryEgress {
			obs = s.Observation
			if s.SourceDigest != digestOf("api.example.com") {
				t.Fatalf("egress digest must be of DestHost, got %s", s.SourceDigest)
			}
		}
	}
	if obs != "egress to api.example.com" {
		t.Fatalf("egress observation must use DestHost when EffectTarget is empty, got %q", obs)
	}
	if strings.TrimSpace(obs) == "egress to" {
		t.Fatal("egress observation must not be an empty target")
	}
}
