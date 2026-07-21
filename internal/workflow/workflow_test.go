package workflow_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/workflow"
)

func baseTask(mut func(*workflow.Task)) workflow.Task {
	tk := workflow.Task{
		TaskID: "T-TEST", InvariantIDs: []string{"H1"}, SecuritySensitive: true,
		SecurityProblem: "p", RequiredBehavior: "b", FailureBehavior: "f",
		AllowedPaths: []string{"allowed/"}, ApprovalGatedPaths: workflow.DefaultApprovalGated(),
		MaxAttempts: 2,
		RequiredCommands: []workflow.ReqCmd{
			{Name: "red_test", Expect: "fail", Argv: []string{"sh", "-c", "exit 1"}},
			{Name: "target_test", Expect: "pass", Argv: []string{"true"}},
			{Name: "harness", Expect: "pass", Argv: []string{"true"}},
		},
	}
	if mut != nil {
		mut(&tk)
	}
	return tk
}

func writeTask(t *testing.T, dir string, tk workflow.Task) string {
	t.Helper()
	b, err := json.Marshal(tk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "allowed"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "allowed", "task.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func gitInit(t *testing.T, root string) {
	t.Helper()
	run := func(args ...string) {
		c := exec.Command(args[0], args[1:]...)
		c.Dir = root
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	}
	run("git", "init")
	run("git", "config", "user.email", "t@t")
	run("git", "config", "user.name", "t")
	_ = os.WriteFile(filepath.Join(root, "README.md"), []byte("x\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(root, "allowed"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "allowed", "a.txt"), []byte("a\n"), 0o644)
	run("git", "add", "README.md", "allowed")
	run("git", "commit", "-m", "i")
}

func TestValidate_ArgvAndNames(t *testing.T) {
	dir := t.TempDir()
	tk := baseTask(func(tk *workflow.Task) {
		tk.RequiredCommands[0].Argv = nil
	})
	if _, err := workflow.LoadTask(writeTask(t, dir, tk)); err == nil {
		t.Fatal("empty argv")
	}
	tk = baseTask(func(tk *workflow.Task) {
		tk.RequiredCommands = append(tk.RequiredCommands, workflow.ReqCmd{Name: "red_test", Expect: "fail", Argv: []string{"false"}})
	})
	if _, err := workflow.LoadTask(writeTask(t, dir, tk)); err == nil {
		t.Fatal("duplicate name")
	}
	tk = baseTask(func(tk *workflow.Task) {
		tk.RequiredCommands = []workflow.ReqCmd{
			{Name: "red_test", Expect: "fail", Argv: []string{"false"}},
			{Name: "target_test", Expect: "pass", Argv: []string{"true"}},
		}
	})
	if _, err := workflow.LoadTask(writeTask(t, dir, tk)); err == nil {
		t.Fatal("missing harness")
	}
	tk = baseTask(func(tk *workflow.Task) {
		tk.SecuritySensitive = true
		tk.RequiredCommands = []workflow.ReqCmd{
			{Name: "target_test", Expect: "pass", Argv: []string{"true"}},
			{Name: "harness", Expect: "pass", Argv: []string{"true"}},
		}
	})
	if _, err := workflow.LoadTask(writeTask(t, dir, tk)); err == nil {
		t.Fatal("security needs red")
	}
}

func TestRun_UsesContractArgvOnly(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	p := writeTask(t, root, baseTask(nil))
	tk, err := workflow.LoadTask(p)
	if err != nil {
		t.Fatal(err)
	}
	// Running red uses contract argv exit 1, not caller true/false.
	rec, err := workflow.RunNamedCommand(root, tk, "red_test", "HEAD")
	if err != nil || rec.Exit != 1 || rec.Source != "executed" {
		t.Fatalf("%+v %v", rec, err)
	}
	if len(rec.Args) != 3 || rec.Args[0] != "sh" {
		t.Fatalf("argv not from contract: %v", rec.Args)
	}
	if rec.WorkspaceDigest == "" || rec.HeadSHA == "" {
		t.Fatal("missing snapshot metadata")
	}
	// Injected/substituted argv must block derivation.
	st, _ := workflow.DeriveStatus(tk, []workflow.CommandRecord{{
		Name: "target_test", Args: []string{"true"}, Exit: 0, Source: "executed",
		WorkspaceDigest: "fake", HeadSHA: "x", BaseSHA: "y",
	}, {
		Name: "harness", Args: []string{"false"}, Exit: 0, Source: "executed", // wrong argv vs contract true
		WorkspaceDigest: "fake", HeadSHA: "x", BaseSHA: "y",
	}}, workflow.ScopeResult{Pass: true}, nil, workflow.Snapshot{WorkspaceDigest: "fake", HeadSHA: "x", BaseSHA: "y"})
	if st != workflow.StatusBlocked {
		// harness argv mismatch vs contract
		t.Fatalf("expected blocked on argv mismatch, got %s", st)
	}
}

func TestSnapshot_InvalidateAfterChange(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	tk, err := workflow.LoadTask(writeTask(t, root, baseTask(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.RunNamedCommand(root, tk, "red_test", "HEAD"); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.RunNamedCommand(root, tk, "target_test", "HEAD"); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.RunNamedCommand(root, tk, "harness", "HEAD"); err != nil {
		t.Fatal(err)
	}
	rep, err := workflow.BuildReport(root, tk, "HEAD", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.DerivedStatus != workflow.StatusHarnessVerified && rep.DerivedStatus != workflow.StatusTargetVerified {
		// scope may fail if only allowed/ dirty - allowed/a exists tracked; no dirty oos
		// untracked nothing; should be harness verified if scope pass
	}
	// Ensure harness verified when scope clean
	if !rep.Scope.Pass {
		t.Fatalf("scope: %+v", rep.Scope)
	}
	if rep.DerivedStatus != workflow.StatusHarnessVerified {
		t.Fatalf("want HARNESS_VERIFIED got %s reasons=%v", rep.DerivedStatus, rep.Reasons)
	}
	// Change allowed file after harness
	if err := os.WriteFile(filepath.Join(root, "allowed", "a.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep2, err := workflow.BuildReport(root, tk, "HEAD", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.DerivedStatus == workflow.StatusHarnessVerified || rep2.DerivedStatus == workflow.StatusSecurityReviewed {
		t.Fatalf("stale harness still verified: %s %v", rep2.DerivedStatus, rep2.Reasons)
	}
}

func TestMaxAttempts(t *testing.T) {
	tk := baseTask(func(tk *workflow.Task) { tk.MaxAttempts = 2 })
	snap := workflow.Snapshot{WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"}
	mk := func(n int, exit int) workflow.CommandRecord {
		return workflow.CommandRecord{
			Name: "target_test", Args: []string{"true"}, Exit: exit, Source: "executed",
			WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b",
		}
	}
	// at limit (2) with final pass + red + harness still ok path-wise
	cmds := []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "b"},
		mk(1, 1),
		mk(2, 0),
		{Name: "harness", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
	}
	// need harness after target — order: red, target fail, target pass, harness
	st, reasons := workflow.DeriveStatus(&tk, cmds, workflow.ScopeResult{Pass: true}, nil, snap)
	if st != workflow.StatusHarnessVerified {
		t.Fatalf("at limit: %s %v", st, reasons)
	}
	// above limit
	cmds = append(cmds[:3], mk(3, 0), cmds[3])
	// recount: 3 targets
	cmds = []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "b"},
		mk(1, 1), mk(2, 1), mk(3, 0),
		{Name: "harness", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
	}
	st, reasons = workflow.DeriveStatus(&tk, cmds, workflow.ScopeResult{Pass: true}, nil, snap)
	if st != workflow.StatusBlocked {
		t.Fatalf("above limit: %s %v", st, reasons)
	}
}

func TestParseStatus_Unknown(t *testing.T) {
	if _, err := workflow.ParseStatus("NONSENSE"); err == nil {
		t.Fatal("expected error")
	}
	if s, err := workflow.ParseStatus("HARNESS_VERIFIED"); err != nil || s != workflow.StatusHarnessVerified {
		t.Fatalf("%v %v", s, err)
	}
}

func TestReviewIgnoredWithoutGates(t *testing.T) {
	tk := baseTask(nil)
	snap := workflow.Snapshot{WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"}
	st, rs := workflow.DeriveStatus(&tk, []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "b"},
	}, workflow.ScopeResult{Pass: true}, &workflow.ReviewArtifact{Passed: true}, snap)
	if st == workflow.StatusSecurityReviewed {
		t.Fatalf("review override %v", rs)
	}
}
