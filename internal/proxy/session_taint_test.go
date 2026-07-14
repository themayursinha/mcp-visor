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

func TestSessionTaintEgressDenyBlocksSinkAfterSensitiveSource(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-taint-test",
		ClientID:     "agent-taint-test",
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
        risk: medium
      - name: "http_post"
        allowed: true
        risk: high
taints:
  - name: "sensitive_file_accessed"
    description: "Session has read sensitive workspace data"
    source_tools: ["file_read"]
    source_patterns: ["**/secrets/**", "**/*.env"]
egress_controls:
  - name: "block_sensitive_egress"
    when_tainted: "sensitive_file_accessed"
    sink_tools: ["http_post"]
    action: deny
`),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{"path": "/workspace/secrets/customer-tokens.txt"}), client)
	if action != "forward" {
		t.Fatalf("expected sensitive source read to forward and taint session, got %s; response=%s", action, out.String())
	}
	if !p.session.HasTaint("sensitive_file_accessed") {
		t.Fatalf("expected session to be tainted after sensitive source read, taints=%+v", p.session.TaintsSnapshot())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(2, "http_post", map[string]any{"url": "https://example.com/upload", "body": "tokens"}), client)
	if action != "denied" {
		t.Fatalf("expected egress sink to be denied after taint, got %s", action)
	}
	if !strings.Contains(out.String(), "sensitive_file_accessed") || !strings.Contains(out.String(), "block_sensitive_egress") {
		t.Fatalf("expected denial to mention taint and rule, got %s", out.String())
	}

	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "http_post")
	if denied.SessionID != "sess-taint-test" {
		t.Fatalf("expected session id in audit, got %+v", denied)
	}
	if denied.Decision != "deny" {
		t.Fatalf("expected deny decision in audit, got %+v", denied)
	}
	if !containsString(denied.SessionTaints, "sensitive_file_accessed") {
		t.Fatalf("expected session taint in audit event, got %+v", denied)
	}
	if denied.TaintSource != "workspace:file_read" {
		t.Fatalf("expected source tool in audit event, got %+v", denied)
	}
	if denied.PolicyRule != "block_sensitive_egress" {
		t.Fatalf("expected policy rule in audit event, got %+v", denied)
	}
}

func TestSessionTaintEgressAllowsSinkBeforeTaint(t *testing.T) {
	p := New(Config{
		ServerName: "workspace",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
      - name: "http_post"
        allowed: true
taints:
  - name: "sensitive_file_accessed"
    source_tools: ["file_read"]
    source_patterns: ["**/secrets/**"]
egress_controls:
  - name: "block_sensitive_egress"
    when_tainted: "sensitive_file_accessed"
    sink_tools: ["http_post"]
    action: deny
`),
	})

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "http_post", map[string]any{"url": "https://example.com/upload", "body": "public"}), client)
	if action != "forward" {
		t.Fatalf("expected egress sink to forward before taint, got %s; response=%s", action, out.String())
	}
}

func findAuditEvent(t *testing.T, path string, eventType audit.EventType, tool string) audit.Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal audit event: %v\n%s", err, line)
		}
		if ev.EventType == eventType && ev.Tool == tool {
			return ev
		}
	}
	t.Fatalf("audit event not found: type=%s tool=%s log=%s", eventType, tool, string(data))
	return audit.Event{}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
