package proxy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func argoApplicationYAML() string {
	return `
version: "1.0"
description: "Sync only staging-orders"
default_action: deny
servers:
  - name: "argocd"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: low
      - name: "argocd_sync"
        allowed: true
        risk: high
        rules:
          - type: allow_application
            patterns:
              - "staging-orders"
`
}

func TestApplicationProxyDeniesExpandingAppBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "argocd",
		SessionID:    "sess-argo-app",
		ClientID:     "agent-argocd",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, argoApplicationYAML()),
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
	_, action = p.interceptAndModify(toolCallRaw(2, "argocd_sync", map[string]any{
		"application": "staging-orders",
	}), client)
	if action != "forward" {
		t.Fatalf("mandated application must forward, got %s; response=%s", action, out.String())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(3, "argocd_sync", map[string]any{
		"application": "production-payments",
	}), client)
	if action != "denied" {
		t.Fatalf("production application must deny before relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "authority-expanding application") {
		t.Fatalf("denial must name authority-expanding application, got %s", out.String())
	}

	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "argocd_sync")
	if denied.Decision != "deny" {
		t.Fatalf("expected deny decision in audit, got %+v", denied)
	}
	for _, token := range []string{
		"argument class APPLICATION",
		"effect class CONTROL_PLANE",
		"authority transition MANDATE->CLUSTER",
	} {
		if !strings.Contains(denied.Reason, token) {
			t.Fatalf("audit reason missing evidence %q: %+v", token, denied)
		}
	}
}

func TestApplicationProxyDeniesShadowAliasBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "argocd",
		SessionID:    "sess-argo-alias",
		ClientID:     "agent-argocd",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, argoApplicationYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "argocd_sync", map[string]any{
		"application": "staging-orders",
		"name":        "production-payments",
	}), client)
	if action != "denied" {
		t.Fatalf("shadow name alias must deny before relay, got %s; response=%s", action, out.String())
	}
}

func TestApplicationProxyHistoryDoesNotAuthorizeApp(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "argocd",
		SessionID:    "sess-argo-history",
		ClientID:     "agent-argocd",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, argoApplicationYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	for id := 1; id <= 2; id++ {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(id, "argocd_sync", map[string]any{
			"application": "production-payments",
		}), client)
		if action != "denied" {
			t.Fatalf("call %d: repeated production app must stay denied, got %s", id, action)
		}
	}
	out.Reset()
	_, action := p.interceptAndModify(toolCallRaw(3, "argocd_sync", map[string]any{
		"application": "staging-orders",
	}), client)
	if action != "forward" {
		t.Fatalf("mandated application must still forward after denials, got %s; response=%s", action, out.String())
	}
}
