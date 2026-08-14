package audit_test

import (
	"path/filepath"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
)

func benchEvent() audit.Event {
	return audit.Event{
		EventType:     audit.EventToolDenied,
		SessionID:     "sess-12345",
		AgentID:       "agent-007",
		Server:        "/usr/local/bin/mock-server",
		Tool:          "file_read",
		Arguments:     map[string]any{"path": "/etc/passwd", "user": "admin"},
		Decision:      "deny",
		Reason:        "path matches deny pattern",
		RiskLevel:     "medium",
		ChainContext:  []string{"server:file_read"},
		ResultPreview: "",
		IsError:       false,
		Hash:          "",
		PrevHash:      "",
		ChainIndex:    1,
	}
}

func benchLogger(tb testing.TB) *audit.Logger {
	tb.Helper()
	dir := tb.TempDir()
	l, err := audit.NewLogger(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		tb.Fatalf("NewLogger: %v", err)
	}
	return l
}

func BenchmarkAuditLogEvent(b *testing.B) {
	logger := benchLogger(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = logger.Log(benchEvent())
	}
}

func BenchmarkAuditLogEventWithArguments(b *testing.B) {
	logger := benchLogger(b)
	evt := benchEvent()
	evt.Arguments = map[string]any{
		"path":      "/home/user/data.csv",
		"command":   "curl -X POST https://api.example.com/data -d @/tmp/payload",
		"api_key":   "«redacted:sk-…»",
		"recursive": map[string]any{"nested": "value"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = logger.Log(evt)
	}
}

func BenchmarkAuditLogEventSimple(b *testing.B) {
	logger := benchLogger(b)
	evt := audit.Event{
		EventType: audit.EventSessionStarted,
		SessionID: "sess-12345",
		AgentID:   "agent-007",
		Server:    "mock-server",
		Decision:  "",
		Message:   "session started",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = logger.Log(evt)
	}
}
