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

func TestWorkspaceDigest_TracksNewlineFilename(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	path := filepath.Join(root, "allowed", "line\nbreak.txt")
	if err := os.WriteFile(path, []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "add", "--", "allowed/line\nbreak.txt")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	cmd = exec.Command("git", "commit", "-m", "add newline path")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, out)
	}
	before, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("workspace digest ignored content change in newline-containing path")
	}
}

func TestCheckScope_FilenameWithSpacesCannotBeMangled(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	path := filepath.Join(root, "other file.txt")
	if err := os.WriteFile(path, []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "add", "other file.txt")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	cmd = exec.Command("git", "commit", "-m", "add spaced path")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, out)
	}
	base, err := workflow.ResolveBase(root, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tk := baseTask(func(tk *workflow.Task) {
		tk.AllowedPaths = []string{"file.txt"}
	})
	res, err := workflow.CheckScope(root, &tk, base)
	if err != nil {
		t.Fatal(err)
	}
	if res.Pass {
		t.Fatalf("mangled spaced path passed scope: %+v", res)
	}
	if len(res.Changed) != 1 || res.Changed[0] != "other file.txt" {
		t.Fatalf("spaced path parsed incorrectly: %v", res.Changed)
	}
}

func TestCheckScope_RenameTracksOldAndNewPaths(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	base, err := workflow.ResolveBase(root, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "mv", "allowed/a.txt", "allowed/b.txt")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git mv: %v: %s", err, out)
	}
	tk := baseTask(func(tk *workflow.Task) {
		tk.AllowedPaths = []string{"allowed/b.txt"}
	})
	res, err := workflow.CheckScope(root, &tk, base)
	if err != nil {
		t.Fatal(err)
	}
	if res.Pass {
		t.Fatalf("rename source outside allowed scope was ignored: %+v", res)
	}
	want := []string{"allowed/a.txt", "allowed/b.txt"}
	if len(res.Changed) != len(want) || res.Changed[0] != want[0] || res.Changed[1] != want[1] {
		t.Fatalf("rename paths parsed incorrectly: got=%v want=%v", res.Changed, want)
	}
}

func TestCheckScope_DanglingSymlinkFailsClosed(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	base, err := workflow.ResolveBase(root, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "allowed", "a.txt")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "..", "missing-outside"), path); err != nil {
		t.Fatal(err)
	}
	tk := baseTask(nil)
	res, err := workflow.CheckScope(root, &tk, base)
	if err != nil {
		t.Fatal(err)
	}
	if res.Pass {
		t.Fatalf("unresolved symlink target must fail closed: %+v", res)
	}
	if len(res.Dirty) != 1 || res.Dirty[0] != "allowed/a.txt" {
		t.Fatalf("dirty path parsed incorrectly: %v", res.Dirty)
	}
}

func TestResolveBase_RequiresExplicitBaseWithoutOriginMain(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	if _, err := workflow.ResolveBase(root, ""); err == nil {
		t.Fatal("missing origin/main must fail closed without an explicit base")
	}
	if got, err := workflow.ResolveBase(root, "HEAD"); err != nil || got == "" {
		t.Fatalf("explicit base should resolve: got=%q err=%v", got, err)
	}
}

func TestValidate_RejectsUnsafeTaskID(t *testing.T) {
	for _, taskID := range []string{".", "..", "../escape", "../../escape", `..\escape`, "/tmp/escape", "T safe"} {
		t.Run(taskID, func(t *testing.T) {
			dir := t.TempDir()
			tk := baseTask(func(tk *workflow.Task) {
				tk.TaskID = taskID
			})
			if _, err := workflow.LoadTask(writeTask(t, dir, tk)); err == nil {
				t.Fatalf("unsafe task_id %q accepted", taskID)
			}
		})
	}
}

func TestLoadTask_RejectsTrailingJSON(t *testing.T) {
	dir := t.TempDir()
	tk := baseTask(nil)
	b, err := json.Marshal(tk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "allowed"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "allowed", "task.json")
	if err := os.WriteFile(p, append(b, []byte("\n{}\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.LoadTask(p); err == nil {
		t.Fatal("trailing JSON document must be rejected")
	}
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
	mk := func(exit int) workflow.CommandRecord {
		return workflow.CommandRecord{
			Name: "target_test", Args: []string{"true"}, Exit: exit, Source: "executed",
			WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b",
		}
	}
	// at limit (2) with final pass + red + harness
	cmds := []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "b"},
		mk(1),
		mk(0),
		{Name: "harness", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
	}
	st, reasons := workflow.DeriveStatus(&tk, cmds, workflow.ScopeResult{Pass: true}, nil, snap)
	if st != workflow.StatusHarnessVerified {
		t.Fatalf("at limit: %s %v", st, reasons)
	}
	// above limit: 3 target executions
	cmds = []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "b"},
		mk(1), mk(1), mk(0),
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
	if _, err := workflow.ParseMinStatus("BLOCKED"); err == nil {
		t.Fatal("BLOCKED must not be valid -min")
	}
	if _, err := workflow.ParseMinStatus("UNSPECIFIED"); err == nil {
		t.Fatal("UNSPECIFIED must not be valid -min")
	}
	if _, err := workflow.ParseMinStatus("NONSENSE"); err == nil {
		t.Fatal("unknown must not be valid -min")
	}
	if s, err := workflow.ParseMinStatus("TARGET_VERIFIED"); err != nil || s != workflow.StatusTargetVerified {
		t.Fatalf("%v %v", s, err)
	}
}

func TestReviewIgnoredWithoutGates(t *testing.T) {
	tk := baseTask(nil)
	snap := workflow.Snapshot{WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"}
	st, rs := workflow.DeriveStatus(&tk, []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "b"},
	}, workflow.ScopeResult{Pass: true}, &workflow.ReviewArtifact{Passed: true, HeadSHA: "h", WorkspaceDigest: "d"}, snap)
	if st == workflow.StatusSecurityReviewed {
		t.Fatalf("review override %v", rs)
	}
}

func TestReviewSnapshotMismatch(t *testing.T) {
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
	// Review bound to version A
	snapA, err := workflow.CurrentSnapshot(root, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	revA := &workflow.ReviewArtifact{
		Passed: true, HeadSHA: snapA.HeadSHA, WorkspaceDigest: snapA.WorkspaceDigest, Reviewer: "r",
	}
	repA, err := workflow.BuildReport(root, tk, "HEAD", revA)
	if err != nil {
		t.Fatal(err)
	}
	if repA.DerivedStatus != workflow.StatusSecurityReviewed {
		t.Fatalf("version A should be SECURITY_REVIEWED: %s %v", repA.DerivedStatus, repA.Reasons)
	}
	// Change code (version B), rerun target+harness on new digest
	if err := os.WriteFile(filepath.Join(root, "allowed", "a.txt"), []byte("version-B\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.RunNamedCommand(root, tk, "target_test", "HEAD"); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.RunNamedCommand(root, tk, "harness", "HEAD"); err != nil {
		t.Fatal(err)
	}
	// Stale review for A must not review B
	repB, err := workflow.BuildReport(root, tk, "HEAD", revA)
	if err != nil {
		t.Fatal(err)
	}
	if repB.DerivedStatus != workflow.StatusHarnessVerified {
		t.Fatalf("stale review should leave HARNESS_VERIFIED, got %s %v", repB.DerivedStatus, repB.Reasons)
	}
	found := false
	for _, r := range repB.Reasons {
		if r == "review_snapshot_mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected review_snapshot_mismatch in %v", repB.Reasons)
	}
}
