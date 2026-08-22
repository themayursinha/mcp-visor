package capability

import (
	"context"
	"errors"
	"testing"
)

// Rev 14 closure (Mayur operator decision, run 197 — STOP the design loop,
// eliminate the parent condition).
//
// Parent condition eliminated: the empty-Effect file-boundary DERIVATION
// (ExtractSignals emitting row 8 from an empty-Effect surface, and
// deriveEffectKind deriving file_access from SignalBoundaryFileOutside).
// Replacement rule:
//
//   - ExtractSignals emits boundary.request_file_outside_workspace ONLY
//     inside case EffectFileAccess (explicit structured effect).
//   - deriveEffectKind derives ONLY host_exec and net_egress.
//   - A file-boundary observation WITHOUT an explicit Effect is UNTYPED →
//     evaluator error → PAUSE (Eval's untyped guard). This covers a
//     pre-populated SignalBoundaryFileOutside with empty Effect, a mediated
//     file surface (Path/EffectTarget) outside the workspace on an
//     empty-Effect step, and an unresolvable path/workspace root.
//   - Non-file effects NEVER trigger file-boundary signals (no fallback
//     scan exists — structurally impossible).
//   - In-workspace paths with empty Effect remain pure observation (ALLOW).

// Untyped rule, structured form: empty-Effect + outside Path →
// evaluator error → PAUSE (never ALLOW, never E5 receipt).
func TestRev14UntypedFileOutsideStructuredFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev14-file-struct")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID:    "sess-rev14-file-struct",
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
		t.Fatalf("empty-Effect outside file surface is UNTYPED → evaluator error → PAUSE, got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// Untyped rule, raw-only form: empty-Effect + outside raw EffectTarget →
// evaluator error → PAUSE.
func TestRev14UntypedFileOutsideRawFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev14-file-raw")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID:    "sess-rev14-file-raw",
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
		t.Fatalf("empty-Effect outside raw file target is UNTYPED → evaluator error → PAUSE, got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// Untyped rule, pre-populated authoritative signal: SignalBoundaryFileOutside
// with empty Effect → evaluator error → PAUSE (the signal now has NO derived
// kind).
func TestRev14UntypedPrepopulatedFileOutsideFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev14-file-pre")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID: "sess-rev14-file-pre",
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

// Untyped rule, unresolvable root: empty-Effect + outside path under a
// NONEXISTENT workspace root → evaluator error → PAUSE (never ALLOW with
// zero signals; the removed derivation cannot fail open).
func TestRev14UntypedFileOutsideMissingRootFailsClosed(t *testing.T) {
	e, err := NewChainEvaluator("sess-rev14-root-missing")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID:    "sess-rev14-root-missing",
		StepID:       1,
		Tool:         "read_file",
		Path:         "/nonexistent-root-xyz/etc/passwd",
		EffectTarget: "/nonexistent-root-xyz/etc/passwd",
		Effect:       "",
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: "/nonexistent-root-xyz",
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatalf("empty-Effect file surface under nonexistent root is UNTYPED → evaluator error → PAUSE, got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// Untyped rule, no path anywhere: pre-populated file-outside signal with NO
// file surface → evaluator error → PAUSE (untyped; no target to probe).
func TestRev14UntypedFileOutsideNoPathFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev14-file-nopath")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID: "sess-rev14-file-nopath",
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
		t.Fatalf("file-outside signal with no file surface is UNTYPED → evaluator error → PAUSE, got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// Control: in-workspace path with empty Effect remains pure observation
// (ALLOW, no signal) — the untyped guard must not over-trigger.
func TestRev14InWorkspaceEmptyEffectStillAllows(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev14-file-in")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-rev14-file-in",
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

// Control: explicit EffectFileAccess outside still pauses (E5) — the
// explicit-effect path is unchanged by Rev 14.
func TestRev14ExplicitFileAccessOutsideStillPauses(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev14-file-explicit")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID:    "sess-rev14-file-explicit",
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
		t.Fatalf("explicit file-access outside must evaluate (PAUSE), got error %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("explicit file-access outside must PAUSE (E5), got %s", r.Decision)
	}
	if !hasSignalLevel(r.Signals, SignalBoundaryFileOutside, EvidenceBoundaryRequest) {
		t.Fatalf("explicit file-access outside must emit file_outside, got %+v", r.Signals)
	}
}

// Source-confusion closure: an explicit NON-file effect (net_egress) NEVER
// emits file_outside — the fallback scan is gone. Both at the signal level
// and at the Eval/receipt level.
func TestRev14ExplicitNonFileEffectNeverEmitsFileSignal(t *testing.T) {
	ws := t.TempDir()
	step := Step{
		SessionID:    "sess-rev14-net-egress",
		StepID:       1,
		Tool:         "curl",
		Effect:       EffectNetEgress,
		EffectTarget: "evil.example",
		DestHost:     "evil.example",
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: ws,
		},
	}
	sigs := ExtractSignals(step)
	for _, s := range sigs {
		if s.Kind == SignalBoundaryFileOutside {
			t.Fatalf("explicit net_egress step must NOT emit file_outside (source confusion), got %+v", sigs)
		}
	}
	e, err := NewChainEvaluator("sess-rev14-net-egress")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), step, GenesisPrevHash)
	if err != nil {
		t.Fatalf("explicit net_egress must evaluate, got %v", err)
	}
	for _, s := range r.Signals {
		if s.Kind == SignalBoundaryFileOutside {
			t.Fatalf("explicit net_egress receipt must NOT carry file_outside, got %+v", r.Signals)
		}
	}
}

// Derived host_exec/egress still bind (Rev 10/11/12 semantics kept): a
// host-exec TOOL NAME with empty Effect derives host_exec and pauses (E5
// under empty authority), never the untyped error.
func TestRev14DerivedHostExecToolNameStillBinds(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev14-host-exec")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-rev14-host-exec",
		StepID:    1,
		Tool:      "bash",
		Effect:    "",
		Declared:  DeclaredAuthority{Target: "target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("derived host_exec from tool name must evaluate (PAUSE), got error %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("derived host_exec must PAUSE (E5), got %s", r.Decision)
	}
}

// Derived net_egress still binds: a network TOOL NAME with a destination and
// empty Effect derives net_egress and pauses (E5 under empty authority).
func TestRev14DerivedEgressDestStillBinds(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev14-egress")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID:    "sess-rev14-egress",
		StepID:       1,
		Tool:         "curl",
		Effect:       "",
		EffectTarget: "evil.example",
		DestHost:     "evil.example",
		Declared:     DeclaredAuthority{Target: "target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("derived net_egress must evaluate (PAUSE), got error %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("derived net_egress must PAUSE (E5), got %s", r.Decision)
	}
}
