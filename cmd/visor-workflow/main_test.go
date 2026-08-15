package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/workflow"
)

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

func TestCLIRejectsReviewFlag(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	tk := workflow.Task{
		TaskID: "T-TEST", InvariantIDs: []string{"H1"}, SecuritySensitive: false,
		SecurityProblem: "p", RequiredBehavior: "b", FailureBehavior: "f",
		AllowedPaths: []string{"allowed/"},
		MaxAttempts:  1,
		RequiredCommands: []workflow.ReqCmd{
			{Name: "red_test", Expect: "fail", Argv: []string{"sh", "-c", "exit 1"}},
			{Name: "target_test", Expect: "pass", Argv: []string{"true"}},
			{Name: "harness", Expect: "pass", Argv: []string{"true"}},
		},
	}
	taskPath := writeTask(t, root, tk)
	reviewPath := filepath.Join(root, "evidence", "workflow", "T-TEST", "review-in.json")
	if err := os.MkdirAll(filepath.Dir(reviewPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reviewPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdVerify(root, []string{"-task", taskPath, "-base", "HEAD", "-review", reviewPath, "-min", "SPECIFIED"}); code != 2 {
		t.Fatalf("verify -review must be rejected, got exit %d", code)
	}
	if code := cmdReport(root, []string{"-task", taskPath, "-base", "HEAD", "-review", reviewPath}); code != 2 {
		t.Fatalf("report -review must be rejected, got exit %d", code)
	}
}
