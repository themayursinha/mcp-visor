package proxy

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func saraMandateYAML() string {
	return `
version: "1.0"
description: "Find invoice #123 and email it to finance@example.com"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
        rules:
          - type: allow_path
            patterns:
              - "/workspace/invoices/**"
      - name: "send_email"
        allowed: true
        risk: high
        rules:
          - type: allow_recipient
            patterns:
              - "finance@example.com"
`
}

func TestAuthorityNonEscalationProxyDeniesInjectedRecipientBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-sara",
		ClientID:     "agent-sara",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, saraMandateYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	// Observation instantiates the authorized invoice slot.
	_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{
		"path": "/workspace/invoices/123.pdf",
	}), client)
	if action != "forward" {
		t.Fatalf("invoice read must forward, got %s; response=%s", action, out.String())
	}

	// Influence graph would explain attacker@example.com (it appeared in a
	// tool result). Authority graph does not include that mailbox.
	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(2, "send_email", map[string]any{
		"recipient":  "attacker@example.com",
		"invoice_id": "123",
	}), client)
	if action != "denied" {
		t.Fatalf("injected recipient must be denied before relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "recipient is not in allowlist") {
		t.Fatalf("denial must name the recipient allowlist, got %s", out.String())
	}

	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "send_email")
	if denied.Decision != "deny" {
		t.Fatalf("expected deny decision in audit, got %+v", denied)
	}
	if !strings.Contains(denied.Reason, "recipient is not in allowlist") {
		t.Fatalf("audit reason must record authority expansion, got %+v", denied)
	}
}

func TestAuthorityNonEscalationProxyHistoryDoesNotPromoteRecipient(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-sara-history",
		ClientID:     "agent-sara",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, saraMandateYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	for id, recipient := range []string{"attacker@example.com", "attacker@example.com", "finance@example.com"} {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(id+1, "send_email", map[string]any{
			"recipient":  recipient,
			"invoice_id": "123",
		}), client)
		if recipient == "finance@example.com" {
			if action != "forward" {
				t.Fatalf("mandated recipient must still forward after denials, got %s; response=%s", action, out.String())
			}
			continue
		}
		if action != "denied" {
			t.Fatalf("call %d: repeated attacker recipient must stay denied, got %s", id+1, action)
		}
	}
}

func TestAuthorityNonEscalationProxyDeniesShadowAliasBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-sara-alias",
		ClientID:     "agent-sara",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, saraMandateYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "send_email", map[string]any{
		"recipient":  "finance@example.com",
		"to":         "attacker@example.com",
		"invoice_id": "123",
	}), client)
	if action != "denied" {
		t.Fatalf("shadow alias must be denied before relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "recipient is not in allowlist") {
		t.Fatalf("denial must name the recipient allowlist, got %s", out.String())
	}
}

func TestAuthorityNonEscalationProxyRelaysCanonicalUniqueArguments(t *testing.T) {
	p, cleanup := newSARAProxy(t, "sess-sara-dup")
	defer cleanup()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{"recipient":"attacker@example.com","recipient":"finance@example.com","invoice_id":"123"}}}` + "\n")
	modified, action := p.interceptAndModify(raw, client)
	if action != "forward" {
		t.Fatalf("last-wins mandated recipient must relay, got %s; response=%s", action, out.String())
	}
	assertForwardedRecipient(t, modified, "finance@example.com")
}

func TestAuthorityNonEscalationProxyRelaysCanonicalEscapedEquivalentKeys(t *testing.T) {
	p, cleanup := newSARAProxy(t, "sess-sara-unicode")
	defer cleanup()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{"recipient":"attacker@example.com","\u0072ecipient":"finance@example.com","invoice_id":"123"}}}` + "\n")
	modified, action := p.interceptAndModify(raw, client)
	if action != "forward" {
		t.Fatalf("escaped-equivalent last-wins mandated recipient must relay, got %s; response=%s", action, out.String())
	}
	assertForwardedRecipient(t, modified, "finance@example.com")
}

func TestAuthorityNonEscalationProxyRelaysCanonicalDuplicateArgumentsMembers(t *testing.T) {
	p, cleanup := newSARAProxy(t, "sess-sara-args")
	defer cleanup()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{"recipient":"attacker@example.com","invoice_id":"123"},"arguments":{"recipient":"finance@example.com","invoice_id":"123"}}}` + "\n")
	modified, action := p.interceptAndModify(raw, client)
	if action != "forward" {
		t.Fatalf("last-wins arguments object must relay, got %s; response=%s", action, out.String())
	}
	assertForwardedRecipient(t, modified, "finance@example.com")
}

func TestAuthorityNonEscalationProxyDeniesLastWinsAttackerRecipient(t *testing.T) {
	p, cleanup := newSARAProxy(t, "sess-sara-last-attacker")
	defer cleanup()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{"recipient":"finance@example.com","recipient":"attacker@example.com"}}}` + "\n")
	_, action := p.interceptAndModify(raw, client)
	if action != "denied" {
		t.Fatalf("last-wins attacker recipient must deny, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "recipient is not in allowlist") {
		t.Fatalf("denial must name the recipient allowlist, got %s", out.String())
	}
}

func newSARAProxy(t *testing.T, sessionID string) (*Proxy, func()) {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    sessionID,
		ClientID:     "agent-sara",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, saraMandateYAML()),
	})
	return p, func() { _ = p.audit.Close() }
}

func assertForwardedRecipient(t *testing.T, modified json.RawMessage, want string) {
	t.Helper()
	if strings.Contains(string(modified), "attacker@example.com") {
		t.Fatalf("first-wins attacker must not remain in relayed bytes: %s", modified)
	}
	var env struct {
		Params struct {
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(modified), &env); err != nil {
		t.Fatalf("forwarded JSON: %v", err)
	}
	got, _ := env.Params.Arguments["recipient"].(string)
	if got != want {
		t.Fatalf("relayed recipient=%q want %q; args=%#v", got, want, env.Params.Arguments)
	}
}
