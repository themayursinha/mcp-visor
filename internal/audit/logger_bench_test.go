package audit_test

import (
	"os"
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

func BenchmarkAuditLogEvent(b *testing.B) {
	logger := audit.MustLogger(os.DevNull)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Log(benchEvent())
	}
}

func BenchmarkAuditLogEventWithArguments(b *testing.B) {
	logger := audit.MustLogger(os.DevNull)
	evt := benchEvent()
	evt.Arguments = map[string]any{
		"path":      "/home/user/data.csv",
		"command":   "curl -X POST https://api.example.com/data -d @/tmp/payload",
		"api_key":   "sk-test1234567890abcdefghijklmnopqrstuv",
		"recursive": map[string]any{"nested": "value"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Log(evt)
	}
}

func BenchmarkAuditLogEventSimple(b *testing.B) {
	logger := audit.MustLogger(os.DevNull)
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
		logger.Log(evt)
	}
}
