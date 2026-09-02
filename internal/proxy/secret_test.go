package proxy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func credentialRotationYAML() string {
	return `
version: "1.0"
description: "Do not forward replacement credentials"
default_action: deny
servers:
  - name: "gateway"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: low
      - name: "configure_secret"
        allowed: true
        risk: high
        rules:
          - type: deny_secret
`
}

func TestSecretProxyDeniesReplacementKeyBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "gateway",
		SessionID:    "sess-secret-rotate",
		ClientID:     "agent-ragflow",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, credentialRotationYAML()),
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
	_, action = p.interceptAndModify(toolCallRaw(2, "configure_secret", map[string]any{
		"name": "openai",
	}), client)
	if action != "forward" {
		t.Fatalf("configure_secret without a SECRET-class arg must forward, got %s; response=%s", action, out.String())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(3, "configure_secret", map[string]any{
		"name":    "openai",
		"api_key": "KEY_B",
	}), client)
	if action != "denied" {
		t.Fatalf("replacement api_key must deny before relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "untrusted credential custody") {
		t.Fatalf("denial must name untrusted credential custody, got %s", out.String())
	}

	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "configure_secret")
	if denied.Decision != "deny" {
		t.Fatalf("expected deny decision in audit, got %+v", denied)
	}
	for _, token := range []string{
		"argument class SECRET",
		"effect class CREDENTIAL",
		"authority transition MANDATE->CUSTODY",
	} {
		if !strings.Contains(denied.Reason, token) {
			t.Fatalf("audit reason missing evidence %q: %+v", token, denied)
		}
	}
}

func TestSecretProxyDeniesShadowAliasBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "gateway",
		SessionID:    "sess-secret-alias",
		ClientID:     "agent-ragflow",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, credentialRotationYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "configure_secret", map[string]any{
		"name":    "openai",
		"new_key": "KEY_B",
	}), client)
	if action != "denied" {
		t.Fatalf("shadow new_key alias must deny before relay, got %s; response=%s", action, out.String())
	}
}

func TestSecretProxyHistoryDoesNotAuthorizeCredential(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "gateway",
		SessionID:    "sess-secret-history",
		ClientID:     "agent-ragflow",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, credentialRotationYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	for id := 1; id <= 2; id++ {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(id, "configure_secret", map[string]any{
			"api_key": "KEY_B",
		}), client)
		if action != "denied" {
			t.Fatalf("call %d: repeated replacement key must stay denied, got %s", id, action)
		}
	}
	out.Reset()
	_, action := p.interceptAndModify(toolCallRaw(3, "configure_secret", map[string]any{
		"name": "openai",
	}), client)
	if action != "forward" {
		t.Fatalf("configure_secret without a secret must still forward after denials, got %s; response=%s", action, out.String())
	}
}
