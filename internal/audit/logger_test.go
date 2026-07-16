package audit_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	t.Cleanup(func() { _ = l.Close() })

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
	t.Cleanup(func() { _ = l.Close() })

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
	t.Cleanup(func() { _ = l.Close() })

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
	t.Cleanup(func() { _ = l.Close() })

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
	t.Cleanup(func() { _ = l.Close() })

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
	t.Cleanup(func() { _ = l.Close() })

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
	t.Cleanup(func() { _ = l.Close() })

	l.Log(audit.Event{
		EventType: audit.EventToolAllowed,
		SessionID: "test",
		Decision:  "allow",
	})

	l.Close()
}

func TestMustLoggerWithEmptyPath(t *testing.T) {
	l := audit.MustLogger("")
	t.Cleanup(func() { _ = l.Close() })

	l.Log(audit.Event{
		EventType: audit.EventToolAllowed,
		SessionID: "test",
		Decision:  "allow",
	})
}

func TestAuditLogHashChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	l.Log(audit.Event{EventType: audit.EventSessionStarted, SessionID: "sess-chain", Server: "demo"})
	l.Log(audit.Event{EventType: audit.EventToolAllowed, SessionID: "sess-chain", Server: "demo", Tool: "file_read", Decision: "allow"})

	lines := readAuditLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("expected 2 audit lines, got %d", len(lines))
	}

	var first, second audit.Event
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("decode second: %v", err)
	}

	if first.ChainIndex != 0 {
		t.Errorf("first chain_index: want 0, got %d", first.ChainIndex)
	}
	if first.PrevHash != "" {
		t.Errorf("first prev_hash: want empty, got %q", first.PrevHash)
	}
	if second.ChainIndex != 1 {
		t.Errorf("second chain_index: want 1, got %d", second.ChainIndex)
	}
	if second.PrevHash != first.Hash {
		t.Errorf("prev_hash linkage: second.PrevHash=%q first.Hash=%q", second.PrevHash, first.Hash)
	}
	if got := recomputeAuditHash(t, first); got != first.Hash {
		t.Errorf("first hash mismatch: recomputed %q stored %q", got, first.Hash)
	}
	if got := recomputeAuditHash(t, second); got != second.Hash {
		t.Errorf("second hash mismatch: recomputed %q stored %q", got, second.Hash)
	}
}

func TestNewLoggerRecoversHashChainAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	first, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	first.Log(audit.Event{EventType: audit.EventSessionStarted, SessionID: "sess-restart", Server: "demo"})
	first.Log(audit.Event{EventType: audit.EventToolAllowed, SessionID: "sess-restart", Server: "demo", Tool: "file_read", Decision: "allow"})
	if err := first.Close(); err != nil {
		t.Fatalf("close first logger: %v", err)
	}

	lines := readAuditLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines before reopen, got %d", len(lines))
	}
	var lastBefore audit.Event
	if err := json.Unmarshal([]byte(lines[1]), &lastBefore); err != nil {
		t.Fatalf("decode last before reopen: %v", err)
	}

	second, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("reopen NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	second.Log(audit.Event{EventType: audit.EventToolDenied, SessionID: "sess-restart", Server: "demo", Tool: "shell_exec", Decision: "deny"})

	after := readAuditLines(t, path)
	if len(after) != 3 {
		t.Fatalf("expected 3 lines after reopen write, got %d", len(after))
	}
	var continued audit.Event
	if err := json.Unmarshal([]byte(after[2]), &continued); err != nil {
		t.Fatalf("decode continued event: %v", err)
	}
	if continued.PrevHash != lastBefore.Hash {
		t.Fatalf("restart prev_hash: want %q, got %q", lastBefore.Hash, continued.PrevHash)
	}
	if continued.ChainIndex != lastBefore.ChainIndex+1 {
		t.Fatalf("restart chain_index: want %d, got %d", lastBefore.ChainIndex+1, continued.ChainIndex)
	}
	if got := recomputeAuditHash(t, continued); got != continued.Hash {
		t.Fatalf("continued hash mismatch: recomputed %q stored %q", got, continued.Hash)
	}
}

func TestNewLoggerRejectsIncompleteTrailingLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	l.Log(audit.Event{EventType: audit.EventSessionStarted, SessionID: "sess-partial", Server: "demo"})
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Simulate a torn write: strip the final newline and leave a partial suffix.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("fixture should end with newline")
	}
	partial := append(data[:len(data)-1], []byte(`,"torn":tru`)...)
	if err := os.WriteFile(path, partial, 0o600); err != nil {
		t.Fatalf("write partial: %v", err)
	}

	if _, err := audit.NewLogger(path); err == nil {
		t.Fatal("expected NewLogger to fail closed on incomplete trailing line")
	}
}

func TestNewLoggerRejectsMalformedLastRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte("{\"event_type\":\"session_started\"}\n{not-json\n"), 0o600); err != nil {
		t.Fatalf("write malformed: %v", err)
	}
	if _, err := audit.NewLogger(path); err == nil {
		t.Fatal("expected NewLogger to fail closed on malformed last record")
	}
}

func recomputeAuditHash(t *testing.T, e audit.Event) string {
	t.Helper()
	e.Hash = ""
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal audit event for hash: %v", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readAuditLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestLoggerConcurrency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

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
