package audit_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func TestRecoverChainStateReadsOnlyTailOfLargeLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.jsonl")

	// Build a multi-megabyte ledger with many prefix lines, then one real tip event.
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat(`{"event_type":"noise","session_id":"x","policy_decision":"allow","hash":"00"}`+"\n", 50_000)
	if _, err := f.WriteString(pad); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Append a valid tip via the real logger path by recovering then writing.
	// First recover from noise-only file would fail hash verify — rewrite tip cleanly:
	tipLogger, err := audit.NewLogger(filepath.Join(dir, "tip-only.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	tipLogger.Log(audit.Event{EventType: audit.EventToolAllowed, SessionID: "tip", Decision: "allow", Tool: "t"})
	if err := tipLogger.Close(); err != nil {
		t.Fatal(err)
	}
	tipLines := readAuditLines(t, filepath.Join(dir, "tip-only.jsonl"))
	if len(tipLines) != 1 {
		t.Fatalf("tip lines: %d", len(tipLines))
	}
	// Overwrite big file: padding + tip
	if err := os.WriteFile(path, append([]byte(pad), tipLines[0]+"\n"...), 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("recover large log: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reopened.Log(audit.Event{EventType: audit.EventToolDenied, SessionID: "tip", Decision: "deny", Tool: "u"})

	lines := readAuditLines(t, path)
	last := lines[len(lines)-1]
	var ev audit.Event
	if err := json.Unmarshal([]byte(last), &ev); err != nil {
		t.Fatal(err)
	}
	var tip audit.Event
	if err := json.Unmarshal([]byte(tipLines[0]), &tip); err != nil {
		t.Fatal(err)
	}
	if ev.PrevHash != tip.Hash {
		t.Fatalf("large-log recovery prev_hash want %q got %q", tip.Hash, ev.PrevHash)
	}
	if ev.ChainIndex != tip.ChainIndex+1 {
		t.Fatalf("large-log recovery chain_index want %d got %d", tip.ChainIndex+1, ev.ChainIndex)
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

func TestNewLoggerAcceptsLegacyRecordsWithoutHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	// Simulate a pre-hash-chain audit log: well-formed JSONL but missing hash/prev_hash/chain_index.
	legacy := `{"timestamp":"2026-01-01T00:00:00Z","event_type":"session_started","session_id":"old-session","decision":"allow"}
`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy: %v", err)
	}
	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger should accept legacy records without hash: %v", err)
	}
	defer l.Close()

	// Append a new event — must succeed and carry hash chain fields.
	l.Log(audit.Event{
		EventType: audit.EventToolAllowed,
		SessionID: "new-session",
		Tool:      "test_tool",
		Decision:  "allow",
	})

	lines := readAuditLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (legacy + new), got %d", len(lines))
	}

	var newEvent audit.Event
	if err := json.Unmarshal([]byte(lines[1]), &newEvent); err != nil {
		t.Fatalf("unmarshal new event: %v", err)
	}
	if newEvent.Hash == "" {
		t.Fatal("new event should have a hash")
	}
	if newEvent.PrevHash != "" {
		t.Fatalf("new event prev_hash should be empty (chain boundary), got %s", newEvent.PrevHash)
	}
	if newEvent.ChainIndex != 0 {
		t.Fatalf("new event chain_index should be 0 (chain boundary), got %d", newEvent.ChainIndex)
	}
}

func TestNewLoggerRejectsHashStrippedChainRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// First, write a valid hash-chain log with two events.
	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	l.Log(audit.Event{EventType: audit.EventSessionStarted, SessionID: "sess-strip", Server: "test"})
	l.Log(audit.Event{EventType: audit.EventToolAllowed, SessionID: "sess-strip", Server: "test", Tool: "read", Decision: "allow"})
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Read the last line (second event) and tamper by removing its hash.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d", len(lines))
	}

	var tampered audit.Event
	if err := json.Unmarshal(lines[1], &tampered); err != nil {
		t.Fatalf("unmarshal last event: %v", err)
	}
	// Strip the hash but leave PrevHash and ChainIndex intact.
	tampered.Hash = ""
	tamperedLine, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	lines[1] = tamperedLine
	tamperedData := append(bytes.Join(lines, []byte("\n")), '\n')
	if err := os.WriteFile(path, tamperedData, 0o600); err != nil {
		t.Fatal(err)
	}

	// Reopening should detect the stripped hash and fail.
	_, err = audit.NewLogger(path)
	if err == nil {
		t.Fatal("expected error for hash-stripped chained record, got nil")
	}
	if !errors.Is(err, audit.ErrCorruptAuditRecord) {
		t.Fatalf("expected ErrCorruptAuditRecord, got %v", err)
	}
}
