package approval_test

import (
	"os"
	"path/filepath"
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
		os.WriteFile(okPath, []byte{}, 0o600)
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
		os.WriteFile(noPath, []byte{}, 0o600)
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
		ID:    "test-timeout",
		Tool:  "slow_tool",
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
		os.WriteFile(okPath, []byte{}, 0o600)
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
		os.WriteFile(okPath, []byte{}, 0o600)
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

func TestApprovalDisabled(t *testing.T) {
	eng := approval.MustEngine("", 1*time.Second)
	if eng.IsEnabled() {
		t.Error("engine should not be enabled with empty dir")
	}

	req := approval.Request{ID: "test", Tool: "test", Server: "test"}
	approved, err := eng.RequestApproval(req)
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if !approved {
		t.Error("should auto-approve when disabled")
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
		os.WriteFile(okPath, []byte{}, 0o600)
		time.Sleep(50 * time.Millisecond)
		close(done)
	}()

	go eng.RequestApproval(req)
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
