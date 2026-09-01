package proxy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func destructivePathYAML() string {
	return `
version: "1.0"
description: "Clean /tmp/agent-123; do not delete $HOME"
default_action: deny
servers:
  - name: "sandbox"
    allowed: true
    tools:
      - name: "cleanup_sandbox"
        allowed: true
        risk: high
        rules:
          - type: allow_path_slot
            patterns:
              - "/tmp/agent-123"
              - "/tmp/agent-123/**"
`
}

func TestDestructivePathProxyDeniesHomeBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "sandbox",
		SessionID:    "sess-destructive-path",
		ClientID:     "agent-fable",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, destructivePathYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	_, action := p.interceptAndModify(toolCallRaw(1, "cleanup_sandbox", map[string]any{
		"target": "/tmp/agent-123/expired.log",
	}), client)
	if action != "forward" {
		t.Fatalf("sandbox child must forward, got %s; response=%s", action, out.String())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(2, "cleanup_sandbox", map[string]any{
		"target": "/home/user",
	}), client)
	if action != "denied" {
		t.Fatalf("user home must deny before relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "destructive path outside mandate") {
		t.Fatalf("denial must name destructive path outside mandate, got %s", out.String())
	}

	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "cleanup_sandbox")
	if denied.Decision != "deny" {
		t.Fatalf("expected deny decision in audit, got %+v", denied)
	}
	for _, token := range []string{
		"argument class PATH",
		"effect class DESTRUCTIVE",
		"authority transition MANDATE->COLLATERAL",
	} {
		if !strings.Contains(denied.Reason, token) {
			t.Fatalf("audit reason missing evidence %q: %+v", token, denied)
		}
	}
}

func TestDestructivePathProxyDeniesShadowAliasBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "sandbox",
		SessionID:    "sess-destructive-alias",
		ClientID:     "agent-fable",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, destructivePathYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "cleanup_sandbox", map[string]any{
		"path":   "/tmp/agent-123",
		"target": "/home/user",
	}), client)
	if action != "denied" {
		t.Fatalf("shadow target alias must deny before relay, got %s; response=%s", action, out.String())
	}
}

func TestDestructivePathProxyHistoryDoesNotAuthorizeHome(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "sandbox",
		SessionID:    "sess-destructive-history",
		ClientID:     "agent-fable",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, destructivePathYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	for id := 1; id <= 2; id++ {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(id, "cleanup_sandbox", map[string]any{
			"target": "/home/user",
		}), client)
		if action != "denied" {
			t.Fatalf("call %d: repeated home delete must stay denied, got %s", id, action)
		}
	}
	out.Reset()
	_, action := p.interceptAndModify(toolCallRaw(3, "cleanup_sandbox", map[string]any{
		"target": "/tmp/agent-123",
	}), client)
	if action != "forward" {
		t.Fatalf("sandbox cleanup must still forward after denials, got %s; response=%s", action, out.String())
	}
}
