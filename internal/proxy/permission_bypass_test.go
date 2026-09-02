package proxy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func spawnPermissionBypassYAML() string {
	return `
version: "1.0"
description: "Spawn workers without skipping permissions"
default_action: deny
servers:
  - name: "orchestrator"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: low
      - name: "spawn_agent"
        allowed: true
        risk: high
        rules:
          - type: deny_permission_bypass
`
}

func TestPermissionBypassProxyDeniesSkipBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "orchestrator",
		SessionID:    "sess-spawn",
		ClientID:     "agent-parent",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, spawnPermissionBypassYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{
		"path": "/workspace/tickets.md",
	}), client)
	if action != "forward" {
		t.Fatalf("legitimate local read must forward, got %s; response=%s", action, out.String())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(2, "spawn_agent", map[string]any{
		"task": "deploy staging",
	}), client)
	if action != "forward" {
		t.Fatalf("spawn without a bypass flag must forward, got %s; response=%s", action, out.String())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(3, "spawn_agent", map[string]any{
		"task":             "deploy staging",
		"skip_permissions": true,
	}), client)
	if action != "denied" {
		t.Fatalf("skip_permissions must deny before relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "permission-bypass delegation") {
		t.Fatalf("denial must name permission-bypass delegation, got %s", out.String())
	}

	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "spawn_agent")
	if denied.Decision != "deny" {
		t.Fatalf("expected deny decision in audit, got %+v", denied)
	}
	for _, token := range []string{
		"argument class PERMISSION",
		"effect class DELEGATION",
		"authority transition PARENT->CHILD",
	} {
		if !strings.Contains(denied.Reason, token) {
			t.Fatalf("audit reason missing evidence %q: %+v", token, denied)
		}
	}
}

func TestPermissionBypassProxyDeniesShadowAliasBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "orchestrator",
		SessionID:    "sess-spawn-alias",
		ClientID:     "agent-parent",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, spawnPermissionBypassYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "spawn_agent", map[string]any{
		"task":                         "deploy staging",
		"skip_permissions":             false,
		"dangerously_skip_permissions": true,
	}), client)
	if action != "denied" {
		t.Fatalf("shadow dangerously_skip_permissions must deny before relay, got %s; response=%s", action, out.String())
	}
}

func TestPermissionBypassProxyHistoryDoesNotAuthorizeBypass(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "orchestrator",
		SessionID:    "sess-spawn-history",
		ClientID:     "agent-parent",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, spawnPermissionBypassYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	for id := 1; id <= 2; id++ {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(id, "spawn_agent", map[string]any{
			"skip_permissions": true,
		}), client)
		if action != "denied" {
			t.Fatalf("call %d: repeated skip_permissions must stay denied, got %s", id, action)
		}
	}
	out.Reset()
	_, action := p.interceptAndModify(toolCallRaw(3, "spawn_agent", map[string]any{
		"task": "deploy staging",
	}), client)
	if action != "forward" {
		t.Fatalf("spawn without a bypass flag must still forward after denials, got %s; response=%s", action, out.String())
	}
}
