package proxy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func mcpRegistrationYAML() string {
	return `
version: "1.0"
description: "Register only /usr/bin/node or mcp.internal"
default_action: deny
servers:
  - name: "mcphub"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: low
      - name: "register_mcp"
        allowed: true
        risk: high
        rules:
          - type: allow_activation
            patterns:
              - "/usr/bin/node"
            domains:
              - "mcp.internal"
`
}

func TestActivationProxyDeniesSpawnBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "mcphub",
		SessionID:    "sess-register",
		ClientID:     "agent-tenant",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, mcpRegistrationYAML()),
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
	_, action = p.interceptAndModify(toolCallRaw(2, "register_mcp", map[string]any{
		"command": "/usr/bin/node",
	}), client)
	if action != "forward" {
		t.Fatalf("mandated binary must forward, got %s; response=%s", action, out.String())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(3, "register_mcp", map[string]any{
		"command": "/bin/sh",
	}), client)
	if action != "denied" {
		t.Fatalf("/bin/sh must deny before relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "unauthorized configuration activation") {
		t.Fatalf("denial must name unauthorized configuration activation, got %s", out.String())
	}

	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "register_mcp")
	if denied.Decision != "deny" {
		t.Fatalf("expected deny decision in audit, got %+v", denied)
	}
	for _, token := range []string{
		"argument class EXECUTABLE",
		"effect class PROCESS",
		"authority transition CONFIG->SPAWN",
	} {
		if !strings.Contains(denied.Reason, token) {
			t.Fatalf("audit reason missing evidence %q: %+v", token, denied)
		}
	}
}

func TestActivationProxyDeniesNetworkBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "mcphub",
		SessionID:    "sess-register-ssrf",
		ClientID:     "agent-tenant",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, mcpRegistrationYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	_, action := p.interceptAndModify(toolCallRaw(1, "register_mcp", map[string]any{
		"url": "https://mcp.internal/sse",
	}), client)
	if action != "forward" {
		t.Fatalf("mandated host must forward, got %s; response=%s", action, out.String())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(2, "register_mcp", map[string]any{
		"url": "http://169.254.169.254/",
	}), client)
	if action != "denied" {
		t.Fatalf("link-local metadata must deny before relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "effect class NETWORK") {
		t.Fatalf("denial must name NETWORK effect, got %s", out.String())
	}
}

func TestActivationProxyDeniesShadowAliasBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "mcphub",
		SessionID:    "sess-register-alias",
		ClientID:     "agent-tenant",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, mcpRegistrationYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "register_mcp", map[string]any{
		"command": "/usr/bin/node",
		"url":     "http://169.254.169.254/",
	}), client)
	if action != "denied" {
		t.Fatalf("shadow metadata url must deny before relay, got %s; response=%s", action, out.String())
	}
}

func TestActivationProxyHistoryDoesNotAuthorizeActivation(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "mcphub",
		SessionID:    "sess-register-history",
		ClientID:     "agent-tenant",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, mcpRegistrationYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	for id := 1; id <= 2; id++ {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(id, "register_mcp", map[string]any{
			"command": "/bin/sh",
		}), client)
		if action != "denied" {
			t.Fatalf("call %d: repeated /bin/sh must stay denied, got %s", id, action)
		}
	}
	out.Reset()
	_, action := p.interceptAndModify(toolCallRaw(3, "register_mcp", map[string]any{
		"command": "/usr/bin/node",
	}), client)
	if action != "forward" {
		t.Fatalf("mandated binary must still forward after denials, got %s; response=%s", action, out.String())
	}
}
