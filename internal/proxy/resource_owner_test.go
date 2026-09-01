package proxy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func thirdPartyEffectYAML() string {
	return `
version: "1.0"
description: "Book a class for alice; do not cancel anyone else's reservation"
default_action: deny
servers:
  - name: "booking"
    allowed: true
    tools:
      - name: "create_reservation"
        allowed: true
        risk: high
        rules:
          - type: allow_resource_owner
            patterns:
              - "alice"
      - name: "cancel_reservation"
        allowed: true
        risk: high
        rules:
          - type: allow_resource_owner
            patterns:
              - "alice"
`
}

func TestResourceOwnerProxyDeniesCrossPrincipalBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "booking",
		SessionID:    "sess-third-party",
		ClientID:     "agent-booking",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, thirdPartyEffectYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	_, action := p.interceptAndModify(toolCallRaw(1, "create_reservation", map[string]any{
		"owner":    "alice",
		"class_id": "spin-0700",
	}), client)
	if action != "forward" {
		t.Fatalf("alice booking herself must forward, got %s; response=%s", action, out.String())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(2, "cancel_reservation", map[string]any{
		"owner":          "bob",
		"reservation_id": "res-918",
	}), client)
	if action != "denied" {
		t.Fatalf("cancelling bob must deny before relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "cross-principal effect") {
		t.Fatalf("denial must name cross-principal effect, got %s", out.String())
	}

	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "cancel_reservation")
	if denied.Decision != "deny" {
		t.Fatalf("expected deny decision in audit, got %+v", denied)
	}
	for _, token := range []string{
		"argument class PRINCIPAL",
		"effect class THIRD_PARTY",
		"authority transition USER->OTHER",
	} {
		if !strings.Contains(denied.Reason, token) {
			t.Fatalf("audit reason missing evidence %q: %+v", token, denied)
		}
	}
}

func TestResourceOwnerProxyDeniesShadowAliasBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "booking",
		SessionID:    "sess-third-party-alias",
		ClientID:     "agent-booking",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, thirdPartyEffectYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "cancel_reservation", map[string]any{
		"owner":   "alice",
		"user_id": "bob",
	}), client)
	if action != "denied" {
		t.Fatalf("shadow principal alias must deny before relay, got %s; response=%s", action, out.String())
	}
}

func TestResourceOwnerProxyHistoryDoesNotAuthorizeOtherPrincipal(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "booking",
		SessionID:    "sess-third-party-history",
		ClientID:     "agent-booking",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, thirdPartyEffectYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	for id := 1; id <= 2; id++ {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(id, "cancel_reservation", map[string]any{
			"owner":          "bob",
			"reservation_id": "res-918",
		}), client)
		if action != "denied" {
			t.Fatalf("call %d: repeated cross-principal cancel must stay denied, got %s", id, action)
		}
	}
	out.Reset()
	_, action := p.interceptAndModify(toolCallRaw(3, "cancel_reservation", map[string]any{
		"owner":          "alice",
		"reservation_id": "res-alice-1",
	}), client)
	if action != "forward" {
		t.Fatalf("alice cancelling herself must still forward after denials, got %s; response=%s", action, out.String())
	}
}
