package proxy

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func TestAllowedToolsCallEmitsStandaloneJSONLAuditEvent(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-allow-audit",
		ClientID:     "agent-allow-audit",
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
	_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{"path": "/workspace/public/readme.md"}), client)
	if action != "forward" {
		t.Fatalf("expected allowed tools/call to forward, got %s; response=%s", action, out.String())
	}

	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}

	allowed := findAuditEvent(t, auditPath, audit.EventToolAllowed, "file_read")
	if allowed.SessionID != "sess-allow-audit" {
		t.Fatalf("expected session id in allow audit, got %+v", allowed)
	}
	if allowed.Decision != "allow" {
		t.Fatalf("expected allow decision, got %+v", allowed)
	}
	if allowed.Server != "workspace" {
		t.Fatalf("expected server workspace, got %+v", allowed)
	}
	if allowed.AgentID != "agent-allow-audit" {
		t.Fatalf("expected agent id in allow audit, got %+v", allowed)
	}
	if allowed.Hash == "" {
		t.Fatalf("expected hash-linked allow audit event, got %+v", allowed)
	}
}
