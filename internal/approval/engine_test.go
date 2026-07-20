package approval_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/approval"
)

func TestApprovalGranted(t *testing.T) {
	dir := t.TempDir()
	eng, err := approval.NewEngine(dir, 5*time.Second)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if !eng.IsEnabled() {
		t.Fatal("engine should be enabled")
	}

	req := approval.Request{
		ID:        "test-001",
		Tool:      "slack_send_message",
		Server:    "slack",
		Reason:    "high-risk tool requires approval",
		RiskLevel: "high",
		SessionID: "sess-1",
	}

	go func() {
		time.Sleep(200 * time.Millisecond)
		okPath := filepath.Join(dir, "req-test-001.ok")
		_ = os.WriteFile(okPath, []byte{}, 0o600)
	}()

	start := time.Now()
	approved, err := eng.RequestApproval(req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if !approved {
		t.Error("expected approval to be granted")
	}
	if elapsed > 2*time.Second {
		t.Errorf("took too long: %v", elapsed)
	}
}

func TestApprovalDenied(t *testing.T) {
	dir := t.TempDir()
	eng, err := approval.NewEngine(dir, 5*time.Second)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	req := approval.Request{
		ID:        "test-002",
		Tool:      "shell_exec",
		Server:    "shell",
		Reason:    "dangerous command",
		RiskLevel: "critical",
		SessionID: "sess-1",
	}

	go func() {
		time.Sleep(200 * time.Millisecond)
		noPath := filepath.Join(dir, "req-test-002.no")
		_ = os.WriteFile(noPath, []byte{}, 0o600)
	}()

	approved, err := eng.RequestApproval(req)
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if approved {
		t.Error("expected approval to be denied")
	}
}

func TestApprovalTimeout(t *testing.T) {
	dir := t.TempDir()
	eng, err := approval.NewEngine(dir, 1*time.Second)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	req := approval.Request{
		ID:     "test-timeout",
		Tool:   "slow_tool",
		Server: "test",
	}

	approved, err := eng.RequestApproval(req)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if approved {
		t.Error("expected denied on timeout")
	}
	t.Logf("timeout error: %v", err)
}

func TestApprovalUsesExplicitPinnedTimeout(t *testing.T) {
	dir := t.TempDir()
	eng, err := approval.NewEngine(dir, 5*time.Second)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	start := time.Now()
	approved, err := eng.RequestApprovalWithTimeout(approval.Request{
		ID:     "pinned-timeout",
		Tool:   "slow_tool",
		Server: "test",
	}, 40*time.Millisecond)
	if err == nil || approved {
		t.Fatalf("expected explicit timeout denial, approved=%v err=%v", approved, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("explicit timeout was not honored promptly: %v", elapsed)
	}
}

func TestApprovalRequestFileCreated(t *testing.T) {
	dir := t.TempDir()
	eng, err := approval.NewEngine(dir, 2*time.Second)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	req := approval.Request{
		ID:        "test-file",
		Tool:      "file_write",
		Server:    "filesystem",
		Arguments: map[string]any{"path": "/tmp/out.txt", "content": "hello"},
		Reason:    "write operation",
		RiskLevel: "high",
		SessionID: "sess-test",
	}

	go func() {
		time.Sleep(300 * time.Millisecond)
		okPath := filepath.Join(dir, "req-test-file.ok")
		_ = os.WriteFile(okPath, []byte{}, 0o600)
	}()

	approved, err := eng.RequestApproval(req)
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if !approved {
		t.Error("expected approval granted")
	}

	reqPath := filepath.Join(dir, "req-test-file.json")
	if _, err := os.Stat(reqPath); !os.IsNotExist(err) {
		t.Error("request file should have been cleaned up")
	}
}

func TestApprovalFilesCleanedUp(t *testing.T) {
	dir := t.TempDir()
	eng, err := approval.NewEngine(dir, 5*time.Second)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	req := approval.Request{ID: "cleanup-test", Tool: "test", Server: "test"}

	go func() {
		time.Sleep(200 * time.Millisecond)
		okPath := filepath.Join(dir, "req-cleanup-test.ok")
		_ = os.WriteFile(okPath, []byte{}, 0o600)
	}()

	_, err = eng.RequestApproval(req)
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	reqPath := filepath.Join(dir, "req-cleanup-test.json")
	okPath := filepath.Join(dir, "req-cleanup-test.ok")
	noPath := filepath.Join(dir, "req-cleanup-test.no")

	if _, err := os.Stat(reqPath); !os.IsNotExist(err) {
		t.Error("request file should be cleaned up")
	}
	if _, err := os.Stat(okPath); !os.IsNotExist(err) {
		t.Error("ok file should be cleaned up")
	}
	if _, err := os.Stat(noPath); !os.IsNotExist(err) {
		t.Error("no file should be cleaned up")
	}
}

func TestApprovalEngineRejectsUnsafeRequestIDs(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "state")
	eng, err := approval.NewEngine(dir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(parent, "canary.txt")
	if err := os.WriteFile(canary, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"foo/../../bar", `foo\..\..\bar`, "foo\x00bar", "..", "."} {
		t.Run(fmt.Sprintf("%q", id), func(t *testing.T) {
			approved, err := eng.RequestApprovalWithTimeout(approval.Request{
				ID: id, Tool: "shell_exec", Server: "shell",
			}, 10*time.Millisecond)
			if err == nil || approved {
				t.Fatalf("unsafe request ID was accepted: approved=%v err=%v", approved, err)
			}
			if !strings.Contains(err.Error(), "unsafe request ID") {
				t.Fatalf("unsafe request ID reached file I/O: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("unsafe request ID created approval state: %v", entries)
			}
			data, err := os.ReadFile(canary)
			if err != nil || string(data) != "keep" {
				t.Fatalf("parent directory was affected: err=%v data=%q", err, data)
			}
		})
	}
}

func TestApprovalDisabledFailsClosed(t *testing.T) {
	eng := approval.MustEngine("", 1*time.Second)
	if eng.IsEnabled() {
		t.Error("engine should not be enabled with empty dir")
	}

	req := approval.Request{ID: "test", Tool: "test", Server: "test"}
	approved, err := eng.RequestApproval(req)
	if err == nil {
		t.Fatal("expected approval backend error")
	}
	if approved {
		t.Error("disabled approval backend must fail closed")
	}
}

func TestApprovalRequestFileContainsContext(t *testing.T) {
	dir := t.TempDir()
	eng, err := approval.NewEngine(dir, 2*time.Second)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	req := approval.Request{
		ID:        "ctx-001",
		Tool:      "database_export",
		Server:    "database",
		Arguments: map[string]any{"query": "SELECT * FROM users", "format": "csv"},
		Reason:    "large data export",
		RiskLevel: "high",
		SessionID: "sess-ctx",
		AgentID:   "agent-007",
	}

	done := make(chan struct{})
	go func() {
		time.Sleep(200 * time.Millisecond)
		okPath := filepath.Join(dir, "req-ctx-001.ok")
		_ = os.WriteFile(okPath, []byte{}, 0o600)
		time.Sleep(50 * time.Millisecond)
		close(done)
	}()

	go func() { _, _ = eng.RequestApproval(req) }()
	time.Sleep(100 * time.Millisecond)

	reqPath := filepath.Join(dir, "req-ctx-001.json")
	data, err := os.ReadFile(reqPath)
	<-done

	if err != nil {
		t.Fatalf("read request file: %v", err)
	}

	content := string(data)
	if len(content) == 0 {
		t.Error("request file should not be empty")
	}
	t.Logf("request file:\n%s", content)
}

func TestCLIApprovalEngineEnabled(t *testing.T) {
	eng := approval.NewCLIEngine(30 * time.Second)
	if !eng.IsEnabled() {
		t.Error("CLI engine should be enabled")
	}
}

func TestCLIApprovalEngineTimeout(t *testing.T) {
	eng := approval.NewCLIEngine(500 * time.Millisecond)

	req := approval.Request{
		ID:        "test-cli-timeout",
		Tool:      "shell_exec",
		Server:    "shell",
		Reason:    "dangerous command",
		RiskLevel: "critical",
		SessionID: "sess-1",
		AgentID:   "agent-1",
	}

	approved, err := eng.RequestApproval(req)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if approved {
		t.Error("expected denied on timeout")
	}
	t.Logf("timeout error: %v", err)
}
