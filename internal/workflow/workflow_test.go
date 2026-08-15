package workflow_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/workflow"
)

func baseTask(mut func(*workflow.Task)) workflow.Task {
	tk := workflow.Task{
		TaskID: "T-TEST", InvariantIDs: []string{"H1"}, SecuritySensitive: false,
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

func TestWorkspaceDigest_BindsNestedWorktrees(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	path := filepath.Join(root, ".worktrees", "other", "scratch.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
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
		t.Fatal(".worktrees must be bound into the workspace digest so commands can safely read it")
	}
}

func TestCurrentSnapshot_BindsTaskContract(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	tk := baseTask(nil)
	before, err := workflow.CurrentSnapshot(root, "HEAD", &tk)
	if err != nil {
		t.Fatal(err)
	}
	tk.MaxAttempts++
	after, err := workflow.CurrentSnapshot(root, "HEAD", &tk)
	if err != nil {
		t.Fatal(err)
	}
	if before.WorkspaceDigest == after.WorkspaceDigest {
		t.Fatal("snapshot digest ignored task contract change")
	}
}

func TestWorkspaceDigest_TracksIgnoredFile(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("ignored.sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "ignored.sh")
	if err := os.WriteFile(path, []byte("one\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("two\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	after, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("workspace digest ignored gitignored file content")
	}
}

func TestWorkspaceDigest_TracksExecutableBit(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	path := filepath.Join(root, "allowed", "a.txt")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	after, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("workspace digest ignored executable-bit change")
	}
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

func TestWorkspaceDigest_SymlinkEncodingCannotCollide(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	if err := os.Symlink("x\nL z2 y", filepath.Join(root, "z1")); err != nil {
		t.Fatal(err)
	}
	one, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "z1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("x", filepath.Join(root, "z1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("y", filepath.Join(root, "z2")); err != nil {
		t.Fatal(err)
	}
	two, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatal("ambiguous snapshot framing collided for distinct symlink states")
	}
}

func TestWorkspaceDigest_PreservesInvalidUTF8Bytes(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	path := filepath.Join(root, "z-link")
	if err := os.Symlink(string([]byte{'x', 0xff}), path); err != nil {
		t.Fatal(err)
	}
	one, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(string([]byte{'x', 0xfe}), path); err != nil {
		t.Fatal(err)
	}
	two, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatal("digest framing collapsed distinct invalid UTF-8 bytes")
	}
}

func TestWorkspaceDigest_RejectsEmbeddedRepository(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	nested := filepath.Join(root, "allowed", "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "init", "-q")
	cmd.Dir = nested
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nested git init: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(nested, "check.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.WorkspaceDigest(root); err == nil {
		t.Fatal("embedded repository must fail closed")
	}
}

func TestCheckScope_TracksIgnoredOutOfScopeFile(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("outside.sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "add", ".gitignore")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	cmd = exec.Command("git", "commit", "-m", "ignore outside input")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(root, "outside.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	tk := baseTask(nil)
	res, err := workflow.CheckScope(root, &tk, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if res.Pass {
		t.Fatalf("ignored out-of-scope command input passed scope: %+v", res)
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

func TestLoadTask_UnionsDefaultApprovalGates(t *testing.T) {
	dir := t.TempDir()
	tk := baseTask(func(tk *workflow.Task) {
		tk.ApprovalGatedPaths = []string{"custom/*"}
	})
	loaded, err := workflow.LoadTask(writeTask(t, dir, tk))
	if err != nil {
		t.Fatal(err)
	}
	has := func(want string) bool {
		for _, got := range loaded.ApprovalGatedPaths {
			if got == want {
				return true
			}
		}
		return false
	}
	if !has("custom/*") || !has("*_test.go") || !has("go.mod") || !has(".github/workflows/*") {
		t.Fatalf("custom gates must extend mandatory defaults: %v", loaded.ApprovalGatedPaths)
	}
}

func TestValidate_RequiresTargetPassCommand(t *testing.T) {
	dir := t.TempDir()
	tk := baseTask(func(tk *workflow.Task) {
		tk.RequiredCommands = []workflow.ReqCmd{
			{Name: "red_test", Expect: "fail", Argv: []string{"sh", "-c", "exit 1"}},
			{Name: "harness", Expect: "pass", Argv: []string{"true"}},
		}
	})
	if _, err := workflow.LoadTask(writeTask(t, dir, tk)); err == nil {
		t.Fatal("task without a non-harness pass command must be rejected")
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
	}}, workflow.ScopeResult{Pass: true}, nil, nil, workflow.Snapshot{WorkspaceDigest: "fake", HeadSHA: "x", BaseSHA: "y"})
	if st != workflow.StatusBlocked {
		// harness argv mismatch vs contract
		t.Fatalf("expected blocked on argv mismatch, got %s", st)
	}
}

func TestRunNamedCommand_UsesUniqueLogPaths(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	tk, err := workflow.LoadTask(writeTask(t, root, baseTask(nil)))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]struct{}{}
	for i := 0; i < 10; i++ {
		rec, err := workflow.RunNamedCommand(root, tk, "target_test", "HEAD")
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := seen[rec.LogPath]; exists {
			t.Fatalf("command log path reused: %s", rec.LogPath)
		}
		seen[rec.LogPath] = struct{}{}
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
	rep, err := workflow.BuildReport(root, tk, "HEAD")
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
	rep2, err := workflow.BuildReport(root, tk, "HEAD")
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
	st, reasons := workflow.DeriveStatus(&tk, cmds, workflow.ScopeResult{Pass: true}, nil, nil, snap)
	if st != workflow.StatusHarnessVerified {
		t.Fatalf("at limit: %s %v", st, reasons)
	}
	// above limit: 3 target executions
	cmds = []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "b"},
		mk(1), mk(1), mk(0),
		{Name: "harness", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
	}
	st, reasons = workflow.DeriveStatus(&tk, cmds, workflow.ScopeResult{Pass: true}, nil, nil, snap)
	if st != workflow.StatusBlocked {
		t.Fatalf("above limit: %s %v", st, reasons)
	}
}

func TestDeriveStatus_LatestTargetExecutionWins(t *testing.T) {
	tk := baseTask(nil)
	snap := workflow.Snapshot{WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"}
	cmds := []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "b"},
		{Name: "target_test", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
		{Name: "harness", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
		{Name: "target_test", Args: []string{"true"}, Exit: 1, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
	}

	st, reasons := workflow.DeriveStatus(&tk, cmds, workflow.ScopeResult{Pass: true}, nil, nil, snap)
	if st == workflow.StatusTargetVerified || st == workflow.StatusHarnessVerified || st == workflow.StatusSecurityReviewed {
		t.Fatalf("latest failed target must invalidate verification, got %s %v", st, reasons)
	}
}

func TestDeriveStatus_LatestHarnessExecutionWins(t *testing.T) {
	tk := baseTask(nil)
	snap := workflow.Snapshot{WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"}
	cmds := []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "b"},
		{Name: "target_test", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
		{Name: "harness", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
		{Name: "harness", Args: []string{"true"}, Exit: 1, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
	}

	st, reasons := workflow.DeriveStatus(&tk, cmds, workflow.ScopeResult{Pass: true}, nil, nil, snap)
	if st == workflow.StatusHarnessVerified || st == workflow.StatusSecurityReviewed {
		t.Fatalf("latest failed harness must invalidate harness verification, got %s %v", st, reasons)
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
	}, workflow.ScopeResult{Pass: true}, &workflow.ReviewArtifact{Passed: true, HeadSHA: "h", WorkspaceDigest: "d", BaseSHA: "b"}, nil, snap)
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
	snapA, err := workflow.CurrentSnapshot(root, "HEAD", tk)
	if err != nil {
		t.Fatal(err)
	}
	revA := &workflow.ReviewArtifact{
		Passed: true, HeadSHA: snapA.HeadSHA, WorkspaceDigest: snapA.WorkspaceDigest,
		BaseSHA: snapA.BaseSHA, Reviewer: "r",
	}
	revDir := filepath.Join(root, "evidence", "workflow", tk.TaskID, "reviews")
	if err := os.MkdirAll(revDir, 0o755); err != nil {
		t.Fatal(err)
	}
	revBytes, err := json.Marshal(revA)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(revDir, "1.json"), revBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	repA, err := workflow.BuildReport(root, tk, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if repA.DerivedStatus != workflow.StatusSecurityReviewed {
		t.Fatalf("version A should be SECURITY_REVIEWED: %s %v", repA.DerivedStatus, repA.Reasons)
	}
	// change code, rerun on new digest
	if err := os.WriteFile(filepath.Join(root, "allowed", "a.txt"), []byte("version-B\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.RunNamedCommand(root, tk, "target_test", "HEAD"); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.RunNamedCommand(root, tk, "harness", "HEAD"); err != nil {
		t.Fatal(err)
	}
	// stale review for A must not review B (digest mismatch)
	repB, err := workflow.BuildReport(root, tk, "HEAD")
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

func TestDeriveStatus_BaseMismatchRejectsTarget(t *testing.T) {
	tk := baseTask(nil)
	// Evidence recorded against base A must not verify under selected base B.
	cmds := []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "baseA"},
		{Name: "target_test", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "baseA"},
		{Name: "harness", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "baseA"},
	}
	snap := workflow.Snapshot{WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "baseB"}
	st, reasons := workflow.DeriveStatus(&tk, cmds, workflow.ScopeResult{Pass: true}, nil, nil, snap)
	if st == workflow.StatusTargetVerified || st == workflow.StatusHarnessVerified || st == workflow.StatusSecurityReviewed {
		t.Fatalf("base mismatch must reject verification, got %s %v", st, reasons)
	}
	found := false
	for _, r := range reasons {
		if r == "target_base_mismatch:target_test" || r == "harness_base_mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected base mismatch reason, got %v", reasons)
	}
}

func TestWorkspaceDigest_IncludesNonGeneratedEvidenceFile(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	path := filepath.Join(root, "evidence", "custom-check.sh")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	after, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("non-generated evidence/ files must be bound into the workspace digest")
	}
}

func TestWorkspaceDigest_StillSkipsGeneratedWorkflowEvidence(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	path := filepath.Join(root, "evidence", "workflow", "T-TEST", "commands.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{changed}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("generated evidence/workflow must remain excluded from digest")
	}
}

func TestValidate_RejectsArgvUnderGeneratedEvidence(t *testing.T) {
	tk := baseTask(func(tk *workflow.Task) {
		tk.RequiredCommands = []workflow.ReqCmd{
			{Name: "red_test", Expect: "fail", Argv: []string{"sh", "-c", "exit 1"}},
			{Name: "target_test", Expect: "pass", Argv: []string{"evidence/workflow/T-TEST/bin"}},
			{Name: "harness", Expect: "pass", Argv: []string{"true"}},
		}
	})
	if err := workflow.ValidateTask(&tk); err == nil {
		t.Fatal("argv under generated evidence/workflow must be rejected")
	}
}

func TestValidate_RejectsArgvUnderNestedWorktrees(t *testing.T) {
	tk := baseTask(func(tk *workflow.Task) {
		tk.RequiredCommands = []workflow.ReqCmd{
			{Name: "red_test", Expect: "fail", Argv: []string{"sh", "-c", "exit 1"}},
			{Name: "target_test", Expect: "pass", Argv: []string{".worktrees/other/result"}},
			{Name: "harness", Expect: "pass", Argv: []string{"true"}},
		}
	})
	if err := workflow.ValidateTask(&tk); err != nil {
		t.Fatalf(".worktrees is now bound into the digest, so argv referencing it is allowed: %v", err)
	}
}

func TestValidate_RejectsExcludedPathsInShellArgs(t *testing.T) {
	tk := baseTask(func(tk *workflow.Task) {
		tk.RequiredCommands = []workflow.ReqCmd{
			{Name: "red_test", Expect: "fail", Argv: []string{"sh", "-c", "exit 1"}},
			{Name: "target_test", Expect: "pass", Argv: []string{"sh", "-c", "cat evidence/workflow/T-TEST/commands.jsonl"}},
			{Name: "harness", Expect: "pass", Argv: []string{"true"}},
		}
	})
	if err := workflow.ValidateTask(&tk); err == nil {
		t.Fatal("excluded evidence/workflow path inside sh -c must be rejected")
	}
	tk2 := baseTask(func(tk *workflow.Task) {
		tk.RequiredCommands = []workflow.ReqCmd{
			{Name: "red_test", Expect: "fail", Argv: []string{"sh", "-c", "exit 1"}},
			{Name: "target_test", Expect: "pass", Argv: []string{"echo", "--input=evidence/workflow/x"}},
			{Name: "harness", Expect: "pass", Argv: []string{"true"}},
		}
	})
	if err := workflow.ValidateTask(&tk2); err == nil {
		t.Fatal("excluded evidence/workflow in --input= form must be rejected")
	}
}

func TestWorkspaceDigest_BindsEmptyDirectories(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	dir := filepath.Join(root, "allowed", "cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	after, err := workflow.WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("removing an empty untracked directory must change the workspace digest")
	}
}

func TestWriteReportJSON_HardLinkDoesNotTruncatePeer(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	peer := filepath.Join(root, "allowed", "peer.txt")
	if err := os.WriteFile(peer, []byte("peer-original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "evidence", "workflow", "report.json")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(peer, dest); err != nil {
		t.Fatal(err)
	}
	rep := &workflow.Report{TaskID: "T-TEST", DerivedStatus: workflow.StatusHarnessVerified}
	if err := workflow.WriteReportJSON(dest, rep); err != nil {
		t.Fatal(err)
	}
	peerBytes, err := os.ReadFile(peer)
	if err != nil {
		t.Fatal(err)
	}
	if string(peerBytes) != "peer-original\n" {
		t.Fatalf("hard-linked peer was truncated/overwritten: %q", peerBytes)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "HARNESS_VERIFIED") {
		t.Fatalf("report not written: %s", got)
	}
}

func TestMaxAttempts_PerTargetName(t *testing.T) {
	tk := baseTask(func(tk *workflow.Task) {
		tk.MaxAttempts = 1
		tk.RequiredCommands = []workflow.ReqCmd{
			{Name: "red_test", Expect: "fail", Argv: []string{"sh", "-c", "exit 1"}},
			{Name: "target_a", Expect: "pass", Argv: []string{"true"}},
			{Name: "target_b", Expect: "pass", Argv: []string{"true"}},
			{Name: "harness", Expect: "pass", Argv: []string{"true"}},
		}
	})
	snap := workflow.Snapshot{WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"}
	cmds := []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "b"},
		{Name: "target_a", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
		{Name: "target_b", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
		{Name: "harness", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
	}
	st, reasons := workflow.DeriveStatus(&tk, cmds, workflow.ScopeResult{Pass: true}, nil, nil, snap)
	if st != workflow.StatusHarnessVerified {
		t.Fatalf("one execution per target with max_attempts=1 must be allowed, got %s %v", st, reasons)
	}
}

func TestMaxAttempts_ExceededOnSingleTarget(t *testing.T) {
	tk := baseTask(func(tk *workflow.Task) { tk.MaxAttempts = 1 })
	snap := workflow.Snapshot{WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"}
	cmds := []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "b"},
		{Name: "target_test", Args: []string{"true"}, Exit: 1, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
		{Name: "target_test", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
	}
	st, reasons := workflow.DeriveStatus(&tk, cmds, workflow.ScopeResult{Pass: true}, nil, nil, snap)
	if st != workflow.StatusBlocked {
		t.Fatalf("two executions of one target with max_attempts=1 must block, got %s %v", st, reasons)
	}
}

// ---- Spec-adversarial gate + two-strike stop-loss (workflow hardening) ----

// specTask builds a security-sensitive task in the spec regime (spec_revision
// declared with the frozen contract fields).
func specTask(mut func(*workflow.Task)) workflow.Task {
	tk := baseTask(mut)
	tk.SecuritySensitive = true
	tk.SpecRevision = 1
	tk.MaxSameFailureClassStrikes = 2
	tk.NonGoals = []string{"no online rotation", "no automatic reopen"}
	tk.AttackClasses = []workflow.AttackClass{
		{ID: "X", FailureClass: "X", Expected: "deny"},
		{ID: "Y", FailureClass: "Y", Expected: "deny"},
	}
	return tk
}

func specReview(passed bool, revision int, digest string, mut func(*workflow.ReviewArtifact)) workflow.ReviewArtifact {
	r := workflow.ReviewArtifact{
		Phase: "spec", Passed: passed, SpecRevision: revision, ContractDigest: digest,
		CoveredAttackClasses: []string{"X", "Y"},
		Counterexamples:      []string{"symlink substitution in any component"},
		Sequence:             1,
	}
	if mut != nil {
		mut(&r)
	}
	return r
}

func implReview(passed bool, classes []string, mut func(*workflow.ReviewArtifact)) workflow.ReviewArtifact {
	r := workflow.ReviewArtifact{
		Passed: passed, HeadSHA: "h", WorkspaceDigest: "d", BaseSHA: "b",
		FailureClasses: classes,
	}
	if mut != nil {
		mut(&r)
	}
	return r
}

func specCmds() []workflow.CommandRecord {
	return []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b", SpecSequence: 1},
		{Name: "target_test", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
		{Name: "harness", Args: []string{"true"}, Exit: 0, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
	}
}

func specSnap() workflow.Snapshot {
	return workflow.Snapshot{WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"}
}

func hasReason(reasons []string, prefix string) bool {
	for _, r := range reasons {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

func TestSpecGate_NoSpecPassBlocksAboveSpecified(t *testing.T) {
	tk := specTask(nil)
	// Full green evidence (RED + target + harness) without a current spec pass
	// must not promote above SPECIFIED for a security task.
	st, reasons := workflow.DeriveStatus(&tk, specCmds(), workflow.ScopeResult{Pass: true}, nil, nil, specSnap())
	if st != workflow.StatusSpecified {
		t.Fatalf("no current spec pass must leave SPECIFIED, got %s %v", st, reasons)
	}
	if !hasReason(reasons, "spec_review_required") {
		t.Fatalf("expected spec_review_required reason, got %v", reasons)
	}
}

func TestSpecGate_CurrentSpecPassDerivesSpecReviewed(t *testing.T) {
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	reviews := []workflow.ReviewArtifact{specReview(true, 1, digest, nil)}
	// No RED yet: current spec pass alone derives SPEC_REVIEWED.
	st, reasons := workflow.DeriveStatus(&tk, nil, workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if st != workflow.StatusSpecReviewed {
		t.Fatalf("current spec pass without RED must derive SPEC_REVIEWED, got %s %v", st, reasons)
	}
	// A RED recorded against the current spec journal sequence promotes to FAILURE_REPRODUCED.
	red := []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b", SpecSequence: 1},
	}
	st, reasons = workflow.DeriveStatus(&tk, red, workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if st != workflow.StatusFailureReproduced {
		t.Fatalf("fresh RED after spec pass must derive FAILURE_REPRODUCED, got %s %v", st, reasons)
	}
}

func TestSpecGate_StaleSpecPass(t *testing.T) {
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	for name, reviews := range map[string][]workflow.ReviewArtifact{
		"wrong_digest":   {specReview(true, 1, "WRONG", nil)},
		"wrong_revision": {specReview(true, 2, digest, nil)},
	} {
		t.Run(name, func(t *testing.T) {
			st, reasons := workflow.DeriveStatus(&tk, specCmds(), workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
			if st != workflow.StatusSpecified {
				t.Fatalf("stale spec pass must not promote, got %s %v", st, reasons)
			}
		})
	}
}

func TestSpecGate_LatestSpecReviewWins(t *testing.T) {
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	// Latest review for the same digest+revision failed -> no current pass.
	reviews := []workflow.ReviewArtifact{
		specReview(true, 1, digest, nil),
		specReview(false, 1, digest, nil),
	}
	st, reasons := workflow.DeriveStatus(&tk, nil, workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if st != workflow.StatusSpecified {
		t.Fatalf("latest failed spec review must invalidate the pass, got %s %v", st, reasons)
	}
	// Latest review passed -> current pass.
	reviews = []workflow.ReviewArtifact{
		specReview(false, 1, digest, nil),
		specReview(true, 1, digest, nil),
	}
	st, _ = workflow.DeriveStatus(&tk, nil, workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if st != workflow.StatusSpecReviewed {
		t.Fatalf("latest passed spec review must derive SPEC_REVIEWED, got %s", st)
	}
}

func TestSpecGate_HistoricalSpecSurvivesTaxonomyExpansion(t *testing.T) {
	oldTK := specTask(nil)
	oldDigest, err := workflow.ContractDigest(&oldTK)
	if err != nil {
		t.Fatal(err)
	}
	newTK := specTask(nil)
	newTK.AttackClasses = append(newTK.AttackClasses, workflow.AttackClass{ID: "Z", FailureClass: "Z", Expected: "deny"})
	newDigest, err := workflow.ContractDigest(&newTK)
	if err != nil {
		t.Fatal(err)
	}
	oldSpec := specReview(true, 1, oldDigest, nil) // covers X,Y only — valid for the old contract
	st, reasons := workflow.DeriveStatus(&newTK, nil, workflow.ScopeResult{Pass: true}, nil, []workflow.ReviewArtifact{oldSpec}, specSnap())
	if st == workflow.StatusBlocked {
		t.Fatalf("historical spec must not block the journal after a class is added, got %s %v", st, reasons)
	}
	if st != workflow.StatusSpecified || !hasReason(reasons, "spec_review_required") {
		t.Fatalf("expanded taxonomy without a current spec must stay SPECIFIED, got %s %v", st, reasons)
	}
	newSpec := specReview(true, 1, newDigest, func(r *workflow.ReviewArtifact) {
		r.CoveredAttackClasses = []string{"X", "Y", "Z"}
		r.Sequence = 2
	})
	st, reasons = workflow.DeriveStatus(&newTK, nil, workflow.ScopeResult{Pass: true}, nil, []workflow.ReviewArtifact{oldSpec, newSpec}, specSnap())
	if st != workflow.StatusSpecReviewed {
		t.Fatalf("current spec covering the new taxonomy must derive SPEC_REVIEWED, got %s %v", st, reasons)
	}
}

func TestSpecGate_PassingSpecReviewRequiresCoverageAndCounterexamples(t *testing.T) {
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*workflow.ReviewArtifact){
		"missing_coverage": func(r *workflow.ReviewArtifact) {
			r.CoveredAttackClasses = []string{"X"}
		},
		"missing_counterexamples": func(r *workflow.ReviewArtifact) {
			r.Counterexamples = nil
		},
		"empty_counterexample": func(r *workflow.ReviewArtifact) {
			r.Counterexamples = []string{""}
		},
		"whitespace_counterexample": func(r *workflow.ReviewArtifact) {
			r.Counterexamples = []string{"  "}
		},
	} {
		t.Run(name, func(t *testing.T) {
			reviews := []workflow.ReviewArtifact{specReview(true, 1, digest, mut)}
			st, reasons := workflow.DeriveStatus(&tk, nil, workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
			if st != workflow.StatusBlocked {
				t.Fatalf("malformed passing spec review must block, got %s %v", st, reasons)
			}
			if !hasReason(reasons, "invalid_review_evidence") {
				t.Fatalf("expected invalid_review_evidence, got %v", reasons)
			}
		})
	}
}

func TestSpecGate_NonSecurityTaskNeedsNoSpecReview(t *testing.T) {
	tk := baseTask(nil) // non-security: no spec gate, no stop-loss
	st, reasons := workflow.DeriveStatus(&tk, specCmds(), workflow.ScopeResult{Pass: true}, nil, nil, specSnap())
	if st != workflow.StatusHarnessVerified {
		t.Fatalf("non-security task must not require a spec pass, got %s %v", st, reasons)
	}
}

func TestStopLoss_XXEvenIfSecondReviewPassed(t *testing.T) {
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	// Two consecutive implementation reviews with failure class X. The second
	// review passed; findings still count regardless of verdict.
	reviews := []workflow.ReviewArtifact{
		specReview(true, 1, digest, nil),
		implReview(true, []string{"X"}, nil),
		implReview(true, []string{"X"}, nil),
	}
	st, reasons := workflow.DeriveStatus(&tk, specCmds(), workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if st != workflow.StatusSpecified {
		t.Fatalf("2 consecutive X must return SPECIFIED, got %s %v", st, reasons)
	}
	if !hasReason(reasons, "same_failure_class_stop_loss:X:2/2") {
		t.Fatalf("expected same_failure_class_stop_loss:X:2/2, got %v", reasons)
	}
}

func TestStopLoss_LatchedUntilSpecClosure(t *testing.T) {
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	// After 2/2 (latched), a THIRD implementation review WITHOUT X must NOT
	// reset the streak: the stop-loss stays latched until a current passing
	// spec review lists X in closed_failure_classes.
	reviews := []workflow.ReviewArtifact{
		specReview(true, 1, digest, nil),
		implReview(false, []string{"X"}, nil),
		implReview(false, []string{"X"}, nil),
		implReview(false, nil, nil), // third review without X: must NOT unlatch
	}
	st, reasons := workflow.DeriveStatus(&tk, specCmds(), workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if st != workflow.StatusSpecified {
		t.Fatalf("latched stop-loss must stay SPECIFIED, got %s %v", st, reasons)
	}
	if !hasReason(reasons, "same_failure_class_stop_loss:X:2/2") {
		t.Fatalf("expected latched same_failure_class_stop_loss:X:2/2, got %v", reasons)
	}
	// A current passing spec review closing X unlatches and restarts the cycle.
	reviews = append(reviews, specReview(true, 1, digest, func(r *workflow.ReviewArtifact) {
		r.ClosedFailureClasses = []string{"X"}
	}))
	st, reasons = workflow.DeriveStatus(&tk, specCmds(), workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if st == workflow.StatusSpecified || hasReason(reasons, "same_failure_class_stop_loss") {
		t.Fatalf("spec closure must clear the stop-loss and advance, got %s %v", st, reasons)
	}
}

func TestStopLoss_DuplicateFindingCountsOnce(t *testing.T) {
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	// One review with two X findings counts once -> streak 1, no stop-loss.
	reviews := []workflow.ReviewArtifact{
		specReview(true, 1, digest, nil),
		implReview(false, []string{"X", "X"}, nil),
	}
	st, reasons := workflow.DeriveStatus(&tk, nil, workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if st != workflow.StatusSpecReviewed {
		t.Fatalf("duplicate X in one review must count once, got %s %v", st, reasons)
	}
	if hasReason(reasons, "same_failure_class_stop_loss") {
		t.Fatalf("unexpected stop-loss: %v", reasons)
	}
}

func TestStopLoss_InterruptedAndDifferentClassesDoNotTrigger(t *testing.T) {
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	for name, reviews := range map[string][]workflow.ReviewArtifact{
		"x_no_x_x": {
			specReview(true, 1, digest, nil),
			implReview(false, []string{"X"}, nil),
			implReview(false, nil, nil),
			implReview(false, []string{"X"}, nil),
		},
		"x_y": {
			specReview(true, 1, digest, nil),
			implReview(false, []string{"X"}, nil),
			implReview(false, []string{"Y"}, nil),
		},
	} {
		t.Run(name, func(t *testing.T) {
			st, reasons := workflow.DeriveStatus(&tk, nil, workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
			if st != workflow.StatusSpecReviewed {
				t.Fatalf("non-consecutive/different classes must not trigger, got %s %v", st, reasons)
			}
			if hasReason(reasons, "same_failure_class_stop_loss") {
				t.Fatalf("unexpected stop-loss: %v", reasons)
			}
		})
	}
}

func TestStopLoss_UnknownClassInvalid(t *testing.T) {
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	reviews := []workflow.ReviewArtifact{
		specReview(true, 1, digest, nil),
		implReview(false, []string{"bogus"}, nil),
	}
	st, reasons := workflow.DeriveStatus(&tk, nil, workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if st != workflow.StatusBlocked {
		t.Fatalf("unknown failure class must block, got %s %v", st, reasons)
	}
	if !hasReason(reasons, "invalid_review_evidence") {
		t.Fatalf("expected invalid_review_evidence, got %v", reasons)
	}
}

func TestStopLoss_RevisionBumpAloneDoesNotReset(t *testing.T) {
	oldTK := specTask(nil)
	oldDigest, err := workflow.ContractDigest(&oldTK)
	if err != nil {
		t.Fatal(err)
	}
	reviews := []workflow.ReviewArtifact{
		specReview(true, 1, oldDigest, nil),
		implReview(false, []string{"X"}, nil),
		implReview(false, []string{"X"}, nil),
	}
	st, reasons := workflow.DeriveStatus(&oldTK, specCmds(), workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if !hasReason(reasons, "same_failure_class_stop_loss:X:2/2") {
		t.Fatalf("expected stop-loss on revision 1, got %s %v", st, reasons)
	}
	// Bumping the revision changes the digest; without a new spec review that
	// closes X the stop-loss must persist.
	newTK := specTask(nil)
	newTK.SpecRevision = 2
	st, reasons = workflow.DeriveStatus(&newTK, specCmds(), workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if st != workflow.StatusSpecified || !hasReason(reasons, "same_failure_class_stop_loss:X:2/2") {
		t.Fatalf("revision bump alone must not reset the stop-loss, got %s %v", st, reasons)
	}
}

func TestStopLoss_ReviewedClosureDerivesSpecReviewedAndInvalidatesOldRed(t *testing.T) {
	oldTK := specTask(nil)
	oldDigest, err := workflow.ContractDigest(&oldTK)
	if err != nil {
		t.Fatal(err)
	}
	newTK := specTask(nil)
	newTK.SpecRevision = 2
	newDigest, err := workflow.ContractDigest(&newTK)
	if err != nil {
		t.Fatal(err)
	}
	closing := specReview(true, 2, newDigest, func(r *workflow.ReviewArtifact) {
		r.ClosedFailureClasses = []string{"X"}
		r.Sequence = 4
	})
	reviews := []workflow.ReviewArtifact{
		specReview(true, 1, oldDigest, nil),
		implReview(false, []string{"X"}, nil),
		implReview(false, []string{"X"}, nil),
		closing,
	}
	oldRed := []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "old", HeadSHA: "h", BaseSHA: "b", SpecSequence: 1},
	}
	st, reasons := workflow.DeriveStatus(&newTK, oldRed, workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if st != workflow.StatusSpecReviewed {
		t.Fatalf("reviewed closure must derive SPEC_REVIEWED, got %s %v", st, reasons)
	}
	if hasReason(reasons, "same_failure_class_stop_loss") {
		t.Fatalf("closing spec review must reset the stop-loss: %v", reasons)
	}
	if !hasReason(reasons, "red_failure_stale_or_missing") {
		t.Fatalf("old RED must be invalidated after the closure, got %v", reasons)
	}
}

func TestStopLoss_StaleSpecReviewDoesNotReset(t *testing.T) {
	oldTK := specTask(nil)
	oldDigest, err := workflow.ContractDigest(&oldTK)
	if err != nil {
		t.Fatal(err)
	}
	// Two X strikes, then a passing spec review bound to a stale digest / wrong
	// revision that lists X in closed_failure_classes must NOT clear the streak.
	base := []workflow.ReviewArtifact{
		specReview(true, 1, oldDigest, nil),
		implReview(false, []string{"X"}, nil),
		implReview(false, []string{"X"}, nil),
	}
	for name, stale := range map[string]workflow.ReviewArtifact{
		"wrong_digest": specReview(true, 1, "STALE-DIGEST-0000", func(r *workflow.ReviewArtifact) {
			r.ClosedFailureClasses = []string{"X"}
		}),
		"wrong_revision": specReview(true, 2, oldDigest, func(r *workflow.ReviewArtifact) {
			r.ClosedFailureClasses = []string{"X"}
		}),
	} {
		t.Run(name, func(t *testing.T) {
			reviews := append(append([]workflow.ReviewArtifact{}, base...), stale)
			st, reasons := workflow.DeriveStatus(&oldTK, specCmds(), workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
			if st != workflow.StatusSpecified {
				t.Fatalf("stale spec review must not clear stop-loss, got %s %v", st, reasons)
			}
			if !hasReason(reasons, "same_failure_class_stop_loss:X:2/2") {
				t.Fatalf("expected same_failure_class_stop_loss:X:2/2, got %v", reasons)
			}
		})
	}
}

func TestStopLoss_MultiClassReasonDeterministic(t *testing.T) {
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	// X and Y both reach 2/2 (each review contains both classes, so neither
	// streak is ended); the selected stop-loss class must be deterministic
	// (sorted canonical order -> X) across repeated derivations.
	reviews := []workflow.ReviewArtifact{
		specReview(true, 1, digest, nil),
		implReview(false, []string{"X", "Y"}, nil),
		implReview(false, []string{"X", "Y"}, nil),
	}
	for i := 0; i < 200; i++ {
		st, reasons := workflow.DeriveStatus(&tk, nil, workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
		if st != workflow.StatusSpecified {
			t.Fatalf("iteration %d: expected SPECIFIED, got %s %v", i, st, reasons)
		}
		if !hasReason(reasons, "same_failure_class_stop_loss:X:2/2") {
			t.Fatalf("iteration %d: expected deterministic same_failure_class_stop_loss:X:2/2, got %v", i, reasons)
		}
	}
}

func TestValidate_NonSecurityTaskSpecRevisionWithoutSpecFields(t *testing.T) {
	// A non-security task authored from template.json keeps spec_revision:1 but
	// empties attack_classes/non_goals; spec-field validation must not apply
	// unless the task is security-sensitive (specRegime).
	tk := baseTask(func(tk *workflow.Task) {
		tk.SecuritySensitive = false
		tk.SpecRevision = 1
		tk.MaxSameFailureClassStrikes = 2
		tk.AttackClasses = nil
		tk.NonGoals = nil
	})
	if err := workflow.ValidateTask(&tk); err != nil {
		t.Fatalf("non-security task with spec_revision:1 and empty spec fields must validate: %v", err)
	}
}

func TestValidate_SecurityTaskRequiresSpecRegime(t *testing.T) {
	// A security-sensitive task that omits spec_revision must be REJECTED:
	// the spec-adversarial gate and two-strike stop-loss are mandatory for
	// security tasks, not opt-in (Codex P1 3787245168).
	tk := baseTask(func(tk *workflow.Task) {
		tk.SecuritySensitive = true
		tk.SpecRevision = 0
		tk.MaxSameFailureClassStrikes = 0
		tk.AttackClasses = nil
		tk.NonGoals = nil
	})
	if err := workflow.ValidateTask(&tk); err == nil {
		t.Fatal("security-sensitive task without spec_revision must be rejected")
	}
}

func TestValidateReviewArtifact_RejectsFindingsWithoutClasses(t *testing.T) {
	tk := specTask(nil)
	r := workflow.ReviewArtifact{
		Phase: "implementation", Passed: false,
		HeadSHA: "h", WorkspaceDigest: "d", BaseSHA: "b",
		Findings: []string{"something is wrong"},
		// FailureClasses intentionally omitted.
	}
	if err := workflow.ValidateReviewArtifact(&r, &tk); err == nil {
		t.Fatal("findings without failure_class must be rejected")
	}
}

func TestValidateReviewArtifact_NonSecurityFindingsNeedNoClasses(t *testing.T) {
	tk := baseTask(nil) // non-security: no taxonomy, no stop-loss
	r := workflow.ReviewArtifact{
		Phase: "implementation", Passed: false,
		HeadSHA: "h", WorkspaceDigest: "d", BaseSHA: "b",
		Findings: []string{"please rename this helper"},
	}
	if err := workflow.ValidateReviewArtifact(&r, &tk); err != nil {
		t.Fatalf("non-security implementation review with findings and no failure_classes must be accepted: %v", err)
	}
}

func TestValidateReviewArtifact_UnboundReviewRejected(t *testing.T) {
	tk := specTask(nil)
	// Any implementation review (classed or classless, passed or failed)
	// without snapshot binding must be rejected — it could advance OR
	// interrupt a failure-class streak for an unrelated tip.
	for name, r := range map[string]workflow.ReviewArtifact{
		"failed_classed": {
			Phase: "implementation", Passed: false,
			FailureClasses: []string{"X"},
		},
		"failed_classless": {
			Phase: "implementation", Passed: false,
		},
		"passed_classed": {
			Phase: "implementation", Passed: true,
			FailureClasses: []string{"X"},
		},
	} {
		if err := workflow.ValidateReviewArtifact(&r, &tk); err == nil {
			t.Fatalf("%s: implementation review without snapshot binding must be rejected", name)
		}
	}
}

func TestBuildReport_MalformedReviewEvidenceBlocked(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	tk := specTask(nil)
	dir := filepath.Join(root, "evidence", "workflow", tk.TaskID, "reviews")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Gap: 1.json and 3.json (missing 2.json).
	if err := os.WriteFile(filepath.Join(dir, "1.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "3.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := workflow.BuildReport(root, &tk, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if rep.DerivedStatus != workflow.StatusBlocked {
		t.Fatalf("gapped review evidence must block, got %s %v", rep.DerivedStatus, rep.Reasons)
	}
	if !hasReason(rep.Reasons, "invalid_review_evidence") {
		t.Fatalf("expected invalid_review_evidence, got %v", rep.Reasons)
	}
}

func TestLoadReviewSequence_RejectsUnknownJSONFields(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "evidence", "workflow", tk.TaskID, "reviews")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(specReview(true, 1, digest, func(r *workflow.ReviewArtifact) { r.Sequence = 0 }))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1.json"), spec, 0o644); err != nil {
		t.Fatal(err)
	}
	// Singular failure_class is a schema mistake: it must not decode as a
	// classless review that resets an unlatched streak.
	bad := []byte(`{"passed":false,"head_sha":"h","workspace_digest":"d","base_sha":"b","failure_class":"X","notes":"typo"}`)
	if err := os.WriteFile(filepath.Join(dir, "2.json"), bad, 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := workflow.BuildReport(root, &tk, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if rep.DerivedStatus != workflow.StatusBlocked {
		t.Fatalf("unknown journal fields must block, got %s %v", rep.DerivedStatus, rep.Reasons)
	}
	if !hasReason(rep.Reasons, "invalid_review_evidence") {
		t.Fatalf("expected invalid_review_evidence, got %v", rep.Reasons)
	}
}

func TestValidate_SpecThresholdMustEqualTwo(t *testing.T) {
	tk := specTask(nil)
	tk.MaxSameFailureClassStrikes = 3
	if err := workflow.ValidateTask(&tk); err == nil {
		t.Fatal("security threshold must equal 2")
	}
}

func TestRunNamedCommand_RequiresCurrentSpecPass(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	tk := specTask(nil)
	if _, err := workflow.RunNamedCommand(root, &tk, "red_test", "HEAD"); err == nil {
		t.Fatal("task command must be rejected without a current spec pass")
	}
}

func TestRunNamedCommand_StopLossRejectsCommands(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "evidence", "workflow", tk.TaskID, "reviews")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(n int, r workflow.ReviewArtifact) {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.json", n)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(1, specReview(true, 1, digest, nil))
	write(2, implReview(false, []string{"X"}, nil))
	write(3, implReview(false, []string{"X"}, nil))
	_, err = workflow.RunNamedCommand(root, &tk, "red_test", "HEAD")
	if err == nil {
		t.Fatal("task command must be rejected during same-failure-class stop-loss")
	}
	if !strings.Contains(err.Error(), "same_failure_class_stop_loss:X:2/2") {
		t.Fatalf("expected stop-loss rejection, got %v", err)
	}
}

func TestParseStatus_SpecReviewed(t *testing.T) {
	if s, err := workflow.ParseStatus("SPEC_REVIEWED"); err != nil || s != workflow.StatusSpecReviewed {
		t.Fatalf("ParseStatus(SPEC_REVIEWED) = %v, %v", s, err)
	}
	if s, err := workflow.ParseMinStatus("SPEC_REVIEWED"); err != nil || s != workflow.StatusSpecReviewed {
		t.Fatalf("ParseMinStatus(SPEC_REVIEWED) = %v, %v", s, err)
	}
}

func TestSpecGate_RedFreshnessUsesJournalSequenceNotMtime(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "evidence", "workflow", tk.TaskID, "reviews")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(n int, r workflow.ReviewArtifact) {
		t.Helper()
		r.Sequence = 0 // journal identity is the filename; loader assigns Sequence
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.json", n)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(1, specReview(true, 1, digest, nil))
	if _, err := workflow.RunNamedCommand(root, &tk, "red_test", "HEAD"); err != nil {
		t.Fatal(err)
	}

	t.Run("same_spec_future_mtime_still_fresh", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		if err := os.Chtimes(filepath.Join(dir, "1.json"), future, future); err != nil {
			t.Fatal(err)
		}
		rep, err := workflow.BuildReport(root, &tk, "HEAD")
		if err != nil {
			t.Fatal(err)
		}
		if rep.DerivedStatus != workflow.StatusFailureReproduced {
			t.Fatalf("RED stamped for spec sequence 1 must stay fresh when only mtime changes, got %s %v", rep.DerivedStatus, rep.Reasons)
		}
	})

	t.Run("later_spec_backdated_mtime_still_stale", func(t *testing.T) {
		write(2, specReview(true, 1, digest, nil))
		past := time.Now().Add(-time.Hour)
		if err := os.Chtimes(filepath.Join(dir, "2.json"), past, past); err != nil {
			t.Fatal(err)
		}
		rep, err := workflow.BuildReport(root, &tk, "HEAD")
		if err != nil {
			t.Fatal(err)
		}
		if rep.DerivedStatus != workflow.StatusSpecReviewed {
			t.Fatalf("new spec journal entry must invalidate prior RED even when mtime is backdated, got %s %v", rep.DerivedStatus, rep.Reasons)
		}
		if !hasReason(rep.Reasons, "red_failure_stale_or_missing") {
			t.Fatalf("expected red_failure_stale_or_missing, got %v", rep.Reasons)
		}
	})
}

func TestSpecGate_UnstampedRedIsStaleAgainstJournaledSpec(t *testing.T) {
	tk := specTask(nil)
	digest, err := workflow.ContractDigest(&tk)
	if err != nil {
		t.Fatal(err)
	}
	reviews := []workflow.ReviewArtifact{specReview(true, 1, digest, func(r *workflow.ReviewArtifact) {
		r.Sequence = 1
	})}
	red := []workflow.CommandRecord{
		{Name: "red_test", Args: []string{"sh", "-c", "exit 1"}, Exit: 1, Source: "executed", WorkspaceDigest: "d", HeadSHA: "h", BaseSHA: "b"},
	}
	st, reasons := workflow.DeriveStatus(&tk, red, workflow.ScopeResult{Pass: true}, nil, reviews, specSnap())
	if st != workflow.StatusSpecReviewed {
		t.Fatalf("unstamped RED against journaled spec sequence 1 must be stale, got %s %v", st, reasons)
	}
	if !hasReason(reasons, "red_failure_stale_or_missing") {
		t.Fatalf("expected red_failure_stale_or_missing, got %v", reasons)
	}
}

func TestBuildReport_NonSecurityFindingsWithoutClassesNotBlocked(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	tk := baseTask(nil)
	dir := filepath.Join(root, "evidence", "workflow", tk.TaskID, "reviews")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r := workflow.ReviewArtifact{
		Phase: "implementation", Passed: false,
		HeadSHA: "h", WorkspaceDigest: "d", BaseSHA: "b",
		Findings: []string{"please rename this helper"},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := workflow.BuildReport(root, &tk, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if rep.DerivedStatus == workflow.StatusBlocked {
		t.Fatalf("non-security findings without failure_classes must not block, got %s %v", rep.DerivedStatus, rep.Reasons)
	}
}
