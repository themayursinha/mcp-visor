package audit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

func TestNewLoggerCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("audit log file should exist")
	}
}

func TestLogEvent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	event := audit.Event{
		EventType: audit.EventToolAllowed,
		SessionID: "sess-test",
		AgentID:   "agent-1",
		Server:    "filesystem",
		Tool:      "file_read",
		Arguments: map[string]any{
			"path": "/home/user/file.txt",
		},
		Decision:  "allow",
		Reason:    "allowed by policy",
		RiskLevel: "medium",
	}
	l.Log(event)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("audit log should not be empty")
	}

	var decoded audit.Event
	if err := json.Unmarshal(data[:len(data)-1], &decoded); err != nil {
		t.Fatalf("decode event: %v (raw: %s)", err, string(data))
	}
	if decoded.Tool != "file_read" {
		t.Errorf("expected file_read, got %s", decoded.Tool)
	}
	if decoded.Decision != "allow" {
		t.Errorf("expected allow, got %s", decoded.Decision)
	}
	if decoded.EventType != audit.EventToolAllowed {
		t.Errorf("expected tool_call_allowed, got %s", decoded.EventType)
	}
}

func TestLogMultipleEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	for i := 0; i < 5; i++ {
		l.Log(audit.Event{
			EventType: audit.EventToolDenied,
			SessionID: "sess-1",
			Server:    "shell",
			Tool:      "shell_exec",
			Decision:  "deny",
			Reason:    "dangerous command",
		})
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 5 {
		t.Errorf("expected 5 lines, got %d", lines)
	}
}

func TestRedactionInAuditLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	l.SetRedactionPatterns(policy.DefaultRedactionPatterns())

	l.Log(audit.Event{
		EventType: audit.EventToolAllowed,
		SessionID: "sess-1",
		Server:    "api",
		Tool:      "http_post",
		Arguments: map[string]any{
			"url": "https://example.com",
			"headers": map[string]any{
				"Authorization": "Bearer sk-proj-deadbeef1234567890abcdef123456",
			},
		},
		Decision: "allow",
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	content := string(data)
	if len(content) == 0 {
		t.Fatal("audit log should not be empty")
	}

	var decoded audit.Event
	if err := json.Unmarshal(data[:len(data)-1], &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}

	headers, ok := decoded.Arguments["headers"].(map[string]any)
	if !ok {
		t.Fatal("headers not found in decoded event")
	}
	auth, ok := headers["Authorization"].(string)
	if !ok {
		t.Fatal("Authorization header not found")
	}
	if auth == "Bearer sk-proj-deadbeef1234567890abcdef123456" {
		t.Error("secret should have been redacted")
	}
	if auth != "[REDACTED]" {
		t.Logf("authorization after redaction: %s", auth)
	}
}

func TestRedactionInResultPreview(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	l.SetRedactionPatterns(policy.DefaultRedactionPatterns())

	l.Log(audit.Event{
		EventType:     audit.EventToolAllowed,
		SessionID:     "sess-1",
		Server:        "database",
		Tool:          "database_query",
		Decision:      "allow",
		ResultPreview: "Connection string: mongodb://admin:SuperSecret123@db.internal:27017/prod",
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	var decoded audit.Event
	if err := json.Unmarshal(data[:len(data)-1], &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ResultPreview == "Connection string: mongodb://admin:SuperSecret123@db.internal:27017/prod" {
		t.Error("connection string should have been redacted")
	}
}

func TestSessionLifecycleEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	l.Log(audit.Event{EventType: audit.EventSessionStarted, SessionID: "sess-1", Server: "test"})
	l.Log(audit.Event{EventType: audit.EventToolAllowed, SessionID: "sess-1", Tool: "tool1", Decision: "allow"})
	l.Log(audit.Event{EventType: audit.EventSessionEnded, SessionID: "sess-1", Server: "test"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	content := string(data)
	if len(content) == 0 {
		t.Fatal("empty log")
	}

	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 3 {
		t.Errorf("expected 3 lines, got %d", lines)
	}
}

func TestMustLoggerWithInvalidPath(t *testing.T) {
	l := audit.MustLogger("/nonexistent/dir/should/fail/audit.jsonl")
	defer l.Close()

	l.Log(audit.Event{
		EventType: audit.EventToolAllowed,
		SessionID: "test",
		Decision:  "allow",
	})

	l.Close()
}

func TestMustLoggerWithEmptyPath(t *testing.T) {
	l := audit.MustLogger("")
	defer l.Close()

	l.Log(audit.Event{
		EventType: audit.EventToolAllowed,
		SessionID: "test",
		Decision:  "allow",
	})
}

func TestLoggerConcurrency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 50; j++ {
				l.Log(audit.Event{
					EventType: audit.EventToolAllowed,
					SessionID: "sess-concurrent",
					Tool:      "tool",
					Decision:  "allow",
				})
			}
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 500 {
		t.Errorf("expected 500 lines, got %d", lines)
	}
}
