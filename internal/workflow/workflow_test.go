package workflow_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/workflow"
)

func taskFile(t *testing.T, dir string, mut func(*workflow.Task)) string {
	t.Helper()
	tk := workflow.Task{
		TaskID: "T-TEST", InvariantIDs: []string{"H1"}, SecuritySensitive: true,
		SecurityProblem: "p", RequiredBehavior: "b", FailureBehavior: "f",
		AllowedPaths: []string{"allowed/"}, ApprovalGatedPaths: workflow.DefaultApprovalGated(),
		MaxAttempts: 2,
		RequiredCommands: []workflow.ReqCmd{
			{Name: "red_test", Expect: "fail"},
			{Name: "target_test", Expect: "pass"},
			{Name: "harness", Expect: "pass"},
		},
	}
	if mut != nil {
		mut(&tk)
	}
	b, _ := json.Marshal(tk)
	p := filepath.Join(dir, "task.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidate_MissingFields(t *testing.T) {
	dir := t.TempDir()
	if _, err := workflow.LoadTask(taskFile(t, dir, func(tk *workflow.Task) { tk.InvariantIDs = nil })); err == nil {
		t.Fatal("expected invariant error")
	}
	if _, err := workflow.LoadTask(taskFile(t, dir, func(tk *workflow.Task) { tk.AllowedPaths = nil })); err == nil {
		t.Fatal("expected allowed_paths error")
	}
}

func TestRun_RealExitNoInject(t *testing.T) {
	root := t.TempDir()
	tk, _ := workflow.LoadTask(taskFile(t, root, nil))
	rec, err := workflow.RunCommand(root, tk.TaskID, "red_test", []string{"sh", "-c", "exit 7"})
	if err != nil || rec.Exit != 7 || rec.Source != "executed" {
		t.Fatalf("%+v %v", rec, err)
	}
	st, _ := workflow.DeriveStatus(tk, []workflow.CommandRecord{{Name: "harness", Exit: 0, Source: "injected"}}, workflow.ScopeResult{Pass: true}, nil)
	if st != workflow.StatusBlocked {
		t.Fatalf("injected source not blocked: %s", st)
	}
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
	run("git", "add", "README.md")
	run("git", "commit", "-m", "i")
}

func TestScope_ChangesAndGated(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	_ = os.MkdirAll(filepath.Join(root, "allowed"), 0o755)
	tk, _ := workflow.LoadTask(taskFile(t, root, func(tk *workflow.Task) {
		tk.AllowedPaths = []string{"allowed/", "foo_test.go"}
	}))
	base, _ := workflow.ResolveBase(root, "HEAD")
	_ = os.WriteFile(filepath.Join(root, "secret.go"), []byte("package s\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "README.md"), []byte("y\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "foo_test.go"), []byte("package f\n"), 0o644)
	sc, err := workflow.CheckScope(root, tk, base)
	if err != nil || sc.Pass || len(sc.ApprovalGated) == 0 {
		t.Fatalf("%+v %v", sc, err)
	}
	// delete tracked
	_ = os.Remove(filepath.Join(root, "README.md"))
	sc, _ = workflow.CheckScope(root, tk, base)
	if sc.Pass {
		t.Fatal("delete should fail scope")
	}
}

func TestDerive_Gates(t *testing.T) {
	tk, _ := workflow.LoadTask(taskFile(t, t.TempDir(), nil))
	scopeOK := workflow.ScopeResult{Pass: true}
	// missing RED
	st, _ := workflow.DeriveStatus(tk, []workflow.CommandRecord{
		{Name: "target_test", Exit: 0, Source: "executed"},
		{Name: "harness", Exit: 0, Source: "executed"},
	}, scopeOK, nil)
	if workflow.StatusRank(st) >= workflow.StatusRank(workflow.StatusTargetVerified) {
		t.Fatalf("missing red: %s", st)
	}
	// failed target
	st, _ = workflow.DeriveStatus(tk, []workflow.CommandRecord{
		{Name: "red_test", Exit: 1, Source: "executed"},
		{Name: "target_test", Exit: 1, Source: "executed"},
		{Name: "harness", Exit: 0, Source: "executed"},
	}, scopeOK, nil)
	if workflow.StatusRank(st) >= workflow.StatusRank(workflow.StatusTargetVerified) {
		t.Fatalf("failed target: %s", st)
	}
	// failed harness
	st, _ = workflow.DeriveStatus(tk, []workflow.CommandRecord{
		{Name: "red_test", Exit: 1, Source: "executed"},
		{Name: "target_test", Exit: 0, Source: "executed"},
		{Name: "harness", Exit: 2, Source: "executed"},
	}, scopeOK, nil)
	if st != workflow.StatusTargetVerified {
		t.Fatalf("failed harness: %s", st)
	}
	// review ignored
	st, rs := workflow.DeriveStatus(tk, []workflow.CommandRecord{
		{Name: "red_test", Exit: 1, Source: "executed"},
	}, scopeOK, &workflow.ReviewArtifact{Passed: true})
	if st == workflow.StatusSecurityReviewed {
		t.Fatalf("review override: %v", rs)
	}
	// happy
	st, _ = workflow.DeriveStatus(tk, []workflow.CommandRecord{
		{Name: "red_test", Exit: 1, Source: "executed"},
		{Name: "target_test", Exit: 0, Source: "executed"},
		{Name: "harness", Exit: 0, Source: "executed"},
	}, scopeOK, &workflow.ReviewArtifact{Passed: true})
	if st != workflow.StatusSecurityReviewed {
		t.Fatalf("happy: %s", st)
	}
}

func TestReport_Dirty(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	_ = os.MkdirAll(filepath.Join(root, "allowed"), 0o755)
	tk, _ := workflow.LoadTask(taskFile(t, root, nil))
	_ = os.WriteFile(filepath.Join(root, "allowed", "x.txt"), []byte("x\n"), 0o644)
	_, _ = workflow.RunCommand(root, tk.TaskID, "red_test", []string{"sh", "-c", "exit 1"})
	_, _ = workflow.RunCommand(root, tk.TaskID, "target_test", []string{"true"})
	_, _ = workflow.RunCommand(root, tk.TaskID, "harness", []string{"true"})
	rep, err := workflow.BuildReport(root, tk, "HEAD", nil)
	if err != nil || !rep.WorktreeDirty || !rep.EvidenceEditable {
		t.Fatalf("%+v %v", rep, err)
	}
}
