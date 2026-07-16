package proxy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func TestRedactionDoesNotEmitPrematureAllowAudit(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	secret := "sk-" + strings.Repeat("C", 48)
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-redact-audit",
		ClientID:     "agent-redact",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: low
`),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{
		"path":    "/workspace/public/readme.md",
		"api_key": secret,
	}), client)
	if action != "forward" {
		t.Fatalf("expected forward, got %s; response=%s", action, out.String())
	}
	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	lines := nonEmptyLines(string(data))
	if len(lines) != 1 {
		t.Fatalf("expected exactly one terminal audit event, got %d:\n%s", len(lines), string(data))
	}

	var ev audit.Event
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	if ev.EventType != audit.EventToolAllowed {
		t.Fatalf("expected tool_call_allowed, got %s", ev.EventType)
	}
	if ev.Decision != "allow" {
		t.Fatalf("expected terminal decision allow, got %q", ev.Decision)
	}
	if strings.Contains(lines[0], secret) {
		t.Fatalf("audit still contains secret")
	}
	if !strings.Contains(ev.Reason, "redacted") && !strings.Contains(lines[0], "REDACTED") {
		t.Fatalf("expected redaction evidence on terminal audit, got reason=%q event=%s", ev.Reason, lines[0])
	}
}

func TestDeniedAfterRedactionEmitsOnlyDenyAudit(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	secret := "ghp_" + strings.Repeat("D", 36)
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-redact-deny",
		ClientID:     "agent-redact",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "http_post"
        allowed: false
        risk: high
`),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "http_post", map[string]any{
		"url":   "https://example.com",
		"token": secret,
	}), client)
	if action != "denied" {
		t.Fatalf("expected denied, got %s; response=%s", action, out.String())
	}
	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	lines := nonEmptyLines(string(data))
	if len(lines) != 1 {
		t.Fatalf("expected exactly one deny audit event, got %d:\n%s", len(lines), string(data))
	}
	var ev audit.Event
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.EventType != audit.EventToolDenied {
		t.Fatalf("expected deny event, got %s", ev.EventType)
	}
	if strings.Contains(lines[0], secret) {
		t.Fatalf("deny audit leaked secret")
	}
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
