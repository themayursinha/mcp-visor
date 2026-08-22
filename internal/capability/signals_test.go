package capability

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// signals_test.go — signal-extraction fingerprint matchers (8-kind table,
// §4) and command-boundary/command-bearing-key matching regressions.

func TestBuildArtifactWithoutPathAndMagic(t *testing.T) {
	// Build tool without Path.
	sigs := ExtractSignals(Step{Tool: "gcc", Result: "compiled ok"})
	found := false
	for _, sig := range sigs {
		if sig.Kind == SignalArtifactBuildArtifact {
			found = true
		}
	}
	if !found {
		t.Fatalf("build tool without Path must emit artifact.build_artifact")
	}
	// ELF magic fingerprint.
	sigs = ExtractSignals(Step{ArtifactMagic: "ELF"})
	found = false
	for _, sig := range sigs {
		if sig.Kind == SignalArtifactBuildArtifact {
			found = true
		}
	}
	if !found {
		t.Fatalf("ELF magic must emit artifact.build_artifact")
	}
}

// 6. ValidateAuthority rejects malformed declared host and malformed
// declared executables (fail closed).

func TestExtractSignalsAllKinds(t *testing.T) {
	ws := t.TempDir()
	steps := []Step{
		{ // declared.intent + artifact.poc_created + artifact.build_artifact
			SessionID: "sess-19", StepID: 1, Tool: "gcc", Path: ws + "/poc.c",
			Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws,
				Intent: "study heap overflow against research target"},
		},
		{ // runtime.memory_corruption_marker + runtime.sandbox_escape_marker
			SessionID: "sess-19", StepID: 2, Tool: "run", Result: "SIGSEGV AddressSanitizer: heap-buffer-overflow sandbox escape",
		},
		{ // boundary.request_host_exec
			SessionID: "sess-19", StepID: 3, Tool: "host_exec", Executable: "bash",
			Effect: EffectHostExec, EffectTarget: "bash",
		},
		{ // boundary.request_egress
			SessionID: "sess-19", StepID: 4, Tool: "http_get",
			Effect: EffectNetEgress, DestIP: netip.MustParseAddr("203.0.113.9"),
			EffectTarget: "203.0.113.9",
		},
		{ // boundary.request_file_outside_workspace — an ACTUAL outside path
			SessionID: "sess-19", StepID: 5, Tool: "file_write",
			Effect: EffectFileAccess, EffectTarget: t.TempDir() + "/poc.js",
			Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
		},
	}
	all := map[string]bool{}
	for _, s := range steps {
		for _, sig := range ExtractSignals(s) {
			all[sig.Kind] = true
			if !strings.HasPrefix(sig.SourceDigest, "sha256:") {
				t.Fatalf("signal %s digest missing sha256 prefix", sig.Kind)
			}
		}
	}
	for _, k := range []string{
		SignalDeclaredIntent, SignalArtifactPocCreated, SignalArtifactBuildArtifact,
		SignalRuntimeMemoryCorruption, SignalRuntimeSandboxEscape,
		SignalBoundaryHostExec, SignalBoundaryEgress, SignalBoundaryFileOutside,
	} {
		if !all[k] {
			t.Fatalf("missing signal kind %s (got %v)", k, all)
		}
	}
}

// Signal extraction: an empty (non-boundary) step yields no boundary signal;
// declared intent alone is provisional (never a pause, never confirmed).

func TestExtractSignalsDeclaredIntentProvisional(t *testing.T) {
	sigs := ExtractSignals(Step{
		Declared: DeclaredAuthority{Intent: "study heap overflow"},
	})
	if len(sigs) != 1 || sigs[0].Kind != SignalDeclaredIntent {
		t.Fatalf("declared intent alone must yield exactly one provisional signal, got %+v", sigs)
	}
	if sigs[0].EvidenceLevel != EvidenceDeclaredOnly {
		t.Fatalf("declared intent evidence level = %s, want declared_only", sigs[0].EvidenceLevel)
	}
}

// ===== Rev 4 closures (independent review run 177) =====

// 1. Structured executable is the canonical host-exec attribution field:
// an undeclared structured executable must fail closed even when the raw
// EffectTarget names a declared executable (reviewer's adversarial case:
// EffectTarget="bash", Executable="evil", declared {bash} → PAUSE).

func TestFileOutsideSignalOnlyWhenProvenOutside(t *testing.T) {
	ws := t.TempDir()
	inside := ExtractSignals(Step{
		Effect: EffectFileAccess, EffectTarget: ws + "/poc.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	})
	for _, sig := range inside {
		if sig.Kind == SignalBoundaryFileOutside {
			t.Fatalf("in-workspace path must NOT emit file_outside signal")
		}
	}
	outside := t.TempDir()
	o := ExtractSignals(Step{
		Effect: EffectFileAccess, EffectTarget: outside + "/poc.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	})
	found := false
	for _, sig := range o {
		if sig.Kind == SignalBoundaryFileOutside {
			found = true
		}
	}
	if !found {
		t.Fatalf("outside path must emit file_outside signal")
	}
}

// 4b. In-workspace file access on an opted-in session is ALLOW and its
// receipt carries NO boundary signal.

func TestInWorkspaceFileAccessNoBoundarySignal(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-27")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-27", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/poc.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("in-workspace file must ALLOW, got %s", r.Decision)
	}
	for _, sig := range r.Signals {
		if sig.Kind == SignalBoundaryFileOutside {
			t.Fatalf("in-workspace receipt must not carry file_outside signal")
		}
	}
}

// 5. Build-artifact detection without a Path: a mediated build tool with no
// path still emits artifact.build_artifact; a typed ELF/PE magic fingerprint
// emits it too.

func TestRev10CrossSourceDedupBuildToolPlusMagic(t *testing.T) {
	sigs := ExtractSignals(Step{
		Tool:          "gcc",
		ArtifactMagic: "ELF",
	})
	count := 0
	for _, s := range sigs {
		if s.Kind == SignalArtifactBuildArtifact {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("Tool+ArtifactMagic must emit artifact.build_artifact exactly once, got %d (%+v)", count, sigs)
	}
}

// Path + args both carrying the same PoC extension must emit
// artifact.poc_created exactly once.

func TestRev10CrossSourceDedupEffectPlusToolArgs(t *testing.T) {
	sigs := ExtractSignals(Step{
		Tool:         "bash",
		Effect:       EffectHostExec,
		EffectTarget: "bash",
		Executable:   "bash",
		Args:         map[string]string{"command": "bash -c id"},
	})
	count := 0
	for _, s := range sigs {
		if s.Kind == SignalBoundaryHostExec {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("Effect+Tool+Args must emit boundary.request_host_exec exactly once, got %d (%+v)", count, sigs)
	}
}

// The dedup collapse is deterministic across map iteration orders.

func TestRev10CrossSourceDedupPathPlusArgs(t *testing.T) {
	sigs := ExtractSignals(Step{
		Tool: "write_file",
		Path: "/tmp/pwn.js",
		Args: map[string]string{"path": "/tmp/pwn.js"},
	})
	count := 0
	for _, s := range sigs {
		if s.Kind == SignalArtifactPocCreated {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("Path+Args must emit artifact.poc_created exactly once, got %d (%+v)", count, sigs)
	}
}

// Effect + tool/args both carrying the host-exec surface must emit
// boundary.request_host_exec exactly once.

func TestRev10DedupDeterministic(t *testing.T) {
	a := ExtractSignals(Step{
		Tool:          "gcc",
		ArtifactMagic: "ELF",
		Args:          map[string]string{"command": "gcc -o out x.c", "url": "http://e.com"},
	})
	b := ExtractSignals(Step{
		Tool:          "gcc",
		ArtifactMagic: "ELF",
		Args:          map[string]string{"url": "http://e.com", "command": "gcc -o out x.c"},
	})
	if len(a) != len(b) {
		t.Fatalf("dedup determinism violated: len(a)=%d len(b)=%d", len(a), len(b))
	}
	for i := range a {
		if a[i].Kind != b[i].Kind || a[i].Observation != b[i].Observation {
			t.Fatalf("signal sets differ: %+v vs %+v", a, b)
		}
	}
}

// End-to-end: an args-derived host_exec PAUSES and records host_exec as the
// requested capability even though the structured Effect was empty; the
// derived kind is what EffectAttributable and confirmedDelta see.

func TestRev11BenignContentCrashNoFalsePause(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev11-crash")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-rev11-crash", StepID: 1,
		Tool: "write_file",
		Args: map[string]string{"content": "crash"},
		Declared: DeclaredAuthority{
			Target: "target", WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("benign content must not fail closed (false PAUSE), got %v", err)
	}
	if r.Decision != DecisionAllow {
		t.Fatalf("benign content under empty Effect must ALLOW, got %s", r.Decision)
	}
	if hasSignalLevel(r.Signals, SignalBoundaryHostExec, EvidenceBoundaryRequest) {
		t.Fatalf("benign content must not emit boundary.request_host_exec, got %+v", r.Signals)
	}
}

// Negative control: more benign content that must not match host-exec.

func TestRev11BenignContentNegativeControls(t *testing.T) {
	benign := []string{"bashful", "success", "crash", "fishing", "washington", "shortcut"}
	for _, c := range benign {
		if hostExecFromArgs(Step{Tool: "write_file", Args: map[string]string{"content": c}}, c) {
			t.Fatalf("benign content %q must not be classified as host-exec", c)
		}
	}
}

// Positive controls: canonical host-exec command surfaces MUST still match.

func TestRev11HostExecPositiveControls(t *testing.T) {
	cases := []Step{
		{Tool: "exec", Args: map[string]string{"command": "/bin/bash -c id"}},
		{Tool: "exec", Args: map[string]string{"command": "/bin/sh -c 'ls'"}},
		{Tool: "exec", Args: map[string]string{"command": "bash -c id"}},
		{Tool: "exec", Args: map[string]string{"command": "sh -c 'ls'"}},
		{Tool: "bash"},
		{Tool: "sh"},
		{Tool: "host_exec"},
		{Tool: "/bin/bash"},
	}
	for _, step := range cases {
		if !hostExecFromArgs(step, "") {
			t.Fatalf("canonical host-exec surface %+v must be classified as host-exec", step)
		}
	}
}

// End-to-end: a REAL host-exec (bash tool) with a DECLARED host + executable
// that the caller does NOT supply — the derived executable comes from the
// tool name and is attributable → ALLOW (in-envelope). This proves the
// fail-closed change did not break legitimate in-envelope attribution.

func TestRev12ShellArgsNegativeControls(t *testing.T) {
	benign := []string{"shellac", "reshell", "shellfish", "in-shell", "shell_out"}
	for _, c := range benign {
		if argsContainShellToken(map[string]string{"content": c}) {
			t.Fatalf("benign content %q must not be classified as host-exec (shell token)", c)
		}
	}
}

// Positive controls for finding 2: canonical `shell` surfaces still match.

func TestRev12ShellArgsPositiveControls(t *testing.T) {
	cases := []Step{
		{Tool: "exec", Args: map[string]string{"command": "shell -c id"}},
		{Tool: "exec", Args: map[string]string{"command": "/bin/bash -c 'shell -x' "}},
		{Tool: "shell"},
		{Tool: "exec", Args: map[string]string{"command": "x; shell -c y"}},
	}
	for _, step := range cases {
		if !hostExecFromArgs(step, "") {
			t.Fatalf("canonical shell surface %+v must be classified as host-exec", step)
		}
	}
}

func TestRev12ShellArgsSurfaceRecognized(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev12-shell-args")
	if err != nil {
		t.Fatal(err)
	}
	// The extraction layer MUST recognize the shell args surface (signal
	// emitted) even though Eval fails closed on attribution.
	if !hostExecFromArgs(Step{Tool: "exec", Args: map[string]string{"command": "shell -c id"}}, "") {
		t.Fatalf("shell args surface must emit host-exec boundary signal")
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID: "sess-rev12-shell-args",
		StepID:    1,
		Tool:      "exec",
		Args:      map[string]string{"command": "shell -c id"},
		Effect:    "",
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatalf("shell args surface on generic tool must fail closed (evaluator error → PAUSE), got nil (ALLOW)")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("must wrap ErrInvalidStep, got %v", err)
	}
}

// The canonical `shell` TOOL NAME must still derive an executable and pause
// as ordinary E5 under empty authority (mirrors TestRev11HostExecToolNameStillWorks).

func TestRev12ShellToolNamePauses(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev12-shell-tool")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-rev12-shell-tool",
		StepID:    1,
		Tool:      "shell",
		Args:      map[string]string{"command": "id"},
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("shell tool name must evaluate, got %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("shell tool name under empty authority must PAUSE (E5), got %s", r.Decision)
	}
	if !hasSignalLevel(r.Signals, SignalBoundaryHostExec, EvidenceBoundaryRequest) {
		t.Fatalf("shell tool name must emit boundary.request_host_exec, got %+v", r.Signals)
	}
}

// Negative control for finding 2: `shell`-prefixed benign tokens must NOT be
// classified as host-exec (command-boundary-aware matching preserved).

func TestRev13EmptyEffectFileOutsideStillSignals(t *testing.T) {
	ws := t.TempDir()
	step := Step{
		Tool:         "file_write",
		Path:         "/etc/passwd",
		EffectTarget: "/etc/passwd",
		Effect:       "",
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: ws,
		},
	}
	sigs := ExtractSignals(step)
	if hasSignalLevel(sigs, SignalBoundaryFileOutside, EvidenceBoundaryRequest) {
		t.Fatalf("empty-Effect outside path must NOT emit file_outside (Rev 14 derivation removed), got %+v", sigs)
	}
	// And the Eval closure: untyped → evaluator error → PAUSE.
	e, err := NewChainEvaluator("sess-rev13-empty-file-outside")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID:    "sess-rev13-empty-file-outside",
		StepID:       1,
		Tool:         "file_write",
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

// End-to-end control: explicit non-file effect net_egress — Eval must not
// emit file_outside on the receipt.

func TestRev13ExplicitEgressReceiptNoFileSignal(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-rev13-egress-receipt")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID:    "sess-rev13-egress-receipt",
		StepID:       1,
		Tool:         "curl",
		Effect:       EffectNetEgress,
		EffectTarget: "evil.example",
		DestHost:     "evil.example",
		Declared: DeclaredAuthority{
			Target:        "target",
			WorkspaceRoot: ws,
		},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("explicit net_egress must evaluate, got %v", err)
	}
	for _, s := range r.Signals {
		if s.Kind == SignalBoundaryFileOutside {
			t.Fatalf("explicit net_egress receipt must NOT carry file_outside, got %+v", r.Signals)
		}
	}
}

func TestRev13ExplicitNetEgressNoFalseFileSignal(t *testing.T) {
	ws := t.TempDir()
	step := Step{
		SessionID:    "sess-rev13-net-egress",
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
	egress := false
	fileOutside := false
	for _, s := range sigs {
		switch s.Kind {
		case SignalBoundaryEgress:
			egress = true
		case SignalBoundaryFileOutside:
			fileOutside = true
		}
	}
	if !egress {
		t.Fatalf("net_egress step must emit boundary.request_egress, got %+v", sigs)
	}
	if fileOutside {
		t.Fatalf("explicit net_egress step must NOT emit file_outside (source confusion), got %+v", sigs)
	}
}

// Rev 14: an empty-Effect step with a canonical file surface OUTSIDE the
// workspace must NOT emit file_outside (the empty-Effect derivation was
// REMOVED). The step is untyped; Eval fails closed (evaluator error → PAUSE).

func TestRev6ExtractSignalsInWorkspacePathNoSignal(t *testing.T) {
	ws := t.TempDir()
	sigs := ExtractSignals(Step{
		Effect:       EffectFileAccess,
		Path:         ws + "/poc.js",
		EffectTarget: "/etc/passwd",
		Declared:     DeclaredAuthority{WorkspaceRoot: ws},
	})
	for _, sig := range sigs {
		if sig.Kind == SignalBoundaryFileOutside {
			t.Fatalf("in-workspace structured Path must not emit file_outside signal: %+v", sigs)
		}
	}
}

// 3. CanonicalHostIsValid must reject IP literals (reviewer run 181:
// "127.0.0.1" was accepted as a hostname). IP literals are not hostnames;
// they enter the declared-host identity and host-exec attribution only via
// the structured DestIP field.

func TestRev6ExtractSignalsUsesStructuredPath(t *testing.T) {
	ws := t.TempDir()
	sigs := ExtractSignals(Step{
		Effect:       EffectFileAccess,
		Path:         "/etc/passwd",
		EffectTarget: ws + "/poc.js",
		Declared:     DeclaredAuthority{WorkspaceRoot: ws},
	})
	for _, sig := range sigs {
		if sig.Kind == SignalBoundaryFileOutside {
			return // signal emitted — fix works
		}
	}
	t.Fatalf("structured outside Path must emit boundary.request_file_outside_workspace, got %+v", sigs)
}

// 2b. In-workspace structured Path must NOT emit the signal (no false
// positive) even when the raw EffectTarget is outside — disagreement is the
// evaluator's job, not the extractor's.

func TestRev9ArgsExtractionDeterministic(t *testing.T) {
	// Map iteration order must not affect the signal set.
	a := ExtractSignals(Step{
		Tool: "exec",
		Args: map[string]string{
			"command": "gcc -o /tmp/x poc.c",
			"url":     "https://example.com",
		},
	})
	b := ExtractSignals(Step{
		Tool: "exec",
		Args: map[string]string{
			"url":     "https://example.com",
			"command": "gcc -o /tmp/x poc.c",
		},
	})
	if len(a) != len(b) {
		t.Fatalf("deterministic args extraction violated: len(a)=%d len(b)=%d", len(a), len(b))
	}
	ak := make([]string, 0, len(a))
	for _, s := range a {
		ak = append(ak, s.Kind+"|"+s.Observation)
	}
	for _, s := range b {
		found := false
		for _, k := range ak {
			if k == s.Kind+"|"+s.Observation {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("signal set differs across map orders: %q not in %v", s.Kind+"|"+s.Observation, ak)
		}
	}
}

func TestRev9BashInArgsEmitsHostExec(t *testing.T) {
	sigs := ExtractSignals(Step{
		Tool: "exec",
		Args: map[string]string{"command": "/bin/bash -c 'id'"},
	})
	if !hasSignal(sigs, SignalBoundaryHostExec) {
		t.Fatalf("/bin/bash in Step.Args must emit boundary.request_host_exec, got %+v", sigs)
	}
}

func TestRev9BashToolNameEmitsHostExec(t *testing.T) {
	// Reviewer's exact case: Tool="bash" with no Effect populated.
	sigs := ExtractSignals(Step{
		Tool:         "bash",
		EffectTarget: "bash",
		Executable:   "bash",
	})
	if !hasSignal(sigs, SignalBoundaryHostExec) {
		t.Fatalf("bash tool call must emit boundary.request_host_exec, got %+v", sigs)
	}
}

func TestRev9BuildToolArgsWithoutPath(t *testing.T) {
	sigs := ExtractSignals(Step{
		Tool: "run",
		Args: map[string]string{"args": "clang -O2 -o out main.c"},
	})
	if !hasSignal(sigs, SignalArtifactBuildArtifact) {
		t.Fatalf("clang in Step.Args must emit artifact.build_artifact, got %+v", sigs)
	}
}

func TestRev9BuildToolInArgsEmitsBuildArtifact(t *testing.T) {
	sigs := ExtractSignals(Step{
		Tool: "exec",
		Args: map[string]string{"command": "gcc -o /tmp/x poc.c"},
	})
	if !hasSignal(sigs, SignalArtifactBuildArtifact) {
		t.Fatalf("build command in Step.Args must emit artifact.build_artifact, got %+v", sigs)
	}
}

func TestRev9EgressToolAndURLArg(t *testing.T) {
	// Network tool name.
	sigs := ExtractSignals(Step{Tool: "curl", Args: map[string]string{"url": "http://example.com"}})
	if !hasSignal(sigs, SignalBoundaryEgress) {
		t.Fatalf("curl tool must emit boundary.request_egress, got %+v", sigs)
	}
	// URL in args of a generic tool.
	sigs = ExtractSignals(Step{Tool: "exec", Args: map[string]string{"command": "wget https://example.com/x"}})
	if !hasSignal(sigs, SignalBoundaryEgress) {
		t.Fatalf("URL in Step.Args must emit boundary.request_egress, got %+v", sigs)
	}
}

func TestRev9EscapeMarkerInArgs(t *testing.T) {
	sigs := ExtractSignals(Step{
		Tool: "exec",
		Args: map[string]string{"command": "landlock violation"},
	})
	if !hasSignal(sigs, SignalRuntimeSandboxEscape) {
		t.Fatalf("escape marker in Step.Args must emit runtime.sandbox_escape_marker, got %+v", sigs)
	}
}

func TestRev9MemoryCorruptionMarkerInArgs(t *testing.T) {
	sigs := ExtractSignals(Step{
		Tool: "exec",
		Args: map[string]string{"output": "SIGSEGV heap-buffer-overflow"},
	})
	if !hasSignal(sigs, SignalRuntimeMemoryCorruption) {
		t.Fatalf("memory marker in Step.Args must emit runtime.memory_corruption_marker, got %+v", sigs)
	}
}

func TestRev9NoDoubleEmission(t *testing.T) {
	// A host_exec tool call with Effect populated must emit
	// boundary.request_host_exec exactly once (structured field + args
	// surface would both match without the dedup guard).
	sigs := ExtractSignals(Step{
		Tool:         "bash",
		Effect:       EffectHostExec,
		EffectTarget: "bash",
		Executable:   "bash",
	})
	count := 0
	for _, s := range sigs {
		if s.Kind == SignalBoundaryHostExec {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("boundary.request_host_exec must be emitted exactly once, got %d (%+v)", count, sigs)
	}

	// A gcc tool with a gcc arg must emit artifact.build_artifact once.
	sigs = ExtractSignals(Step{
		Tool: "gcc",
		Args: map[string]string{"command": "gcc -o out main.c"},
	})
	count = 0
	for _, s := range sigs {
		if s.Kind == SignalArtifactBuildArtifact {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("artifact.build_artifact must be emitted exactly once, got %d (%+v)", count, sigs)
	}
}

func TestRev9PocPathInArgs(t *testing.T) {
	sigs := ExtractSignals(Step{
		Tool: "write_file",
		Args: map[string]string{"path": "/tmp/pwn.js"},
	})
	if !hasSignal(sigs, SignalArtifactPocCreated) {
		t.Fatalf("PoC path in Step.Args must emit artifact.poc_created, got %+v", sigs)
	}
}

func TestRev9PrepopulatedSignalsWin(t *testing.T) {
	// The proxy's pre-populated Signals are authoritative; args extraction
	// must not add to them.
	sigs := ExtractSignals(Step{
		Tool:    "bash",
		Signals: []Signal{{Kind: SignalDeclaredIntent, EvidenceLevel: EvidenceDeclaredOnly, SourceDigest: digestOf("x")}},
	})
	if len(sigs) != 1 || sigs[0].Kind != SignalDeclaredIntent {
		t.Fatalf("pre-populated signals must be used as-is, got %+v", sigs)
	}
	if strings.Contains(sigs[0].Observation, "host exec") {
		t.Fatalf("pre-populated signal mutated: %+v", sigs[0])
	}
}

func TestRev9ShInArgsEmitsHostExec(t *testing.T) {
	sigs := ExtractSignals(Step{
		Tool: "exec",
		Args: map[string]string{"command": "sh -c 'curl http://example.com'"},
	})
	if !hasSignal(sigs, SignalBoundaryHostExec) {
		t.Fatalf("sh in Step.Args must emit boundary.request_host_exec, got %+v", sigs)
	}
}
