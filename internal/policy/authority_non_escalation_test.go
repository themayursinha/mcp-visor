package policy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

// Mandate encoded as policy: find invoice #123 and email it to finance@example.com.
// Influence (tool output, injected recipient, repeated history) cannot enlarge
// the authorized recipient slot. See SARA / arXiv 2608.27146.
const saraMandatePolicy = `
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

func loadSARAEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p, err := policy.Load([]byte(saraMandatePolicy))
	if err != nil {
		t.Fatalf("load mandate policy: %v", err)
	}
	return policy.NewEngine(p)
}

func evalTool(eng *policy.Engine, tool string, args map[string]string) policy.Decision {
	return eng.Evaluate("workspace", mcp.ToolsCallRequest{
		Name:      tool,
		Arguments: mustMarshal(args),
	})
}

func evalAny(eng *policy.Engine, tool string, args map[string]any) policy.Decision {
	return eng.Evaluate("workspace", mcp.ToolsCallRequest{
		Name:      tool,
		Arguments: mustMarshal(args),
	})
}

func evalRaw(eng *policy.Engine, tool string, args json.RawMessage) policy.Decision {
	return eng.Evaluate("workspace", mcp.ToolsCallRequest{
		Name:      tool,
		Arguments: args,
	})
}

func TestAuthorityNonEscalationInstantiationAllowed(t *testing.T) {
	eng := loadSARAEngine(t)

	// Runtime fact fills an already-authorized resource slot.
	got := evalTool(eng, "file_read", map[string]string{"path": "/workspace/invoices/123.pdf"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("invoice path must instantiate authorized slot, got %s: %s", got.Action, got.Reason)
	}

	// Runtime fact fills the authorized recipient slot, including case/whitespace.
	for _, recipient := range []string{"finance@example.com", "Finance@Example.com", " finance@example.com "} {
		got := evalTool(eng, "send_email", map[string]string{
			"recipient":  recipient,
			"invoice_id": "123",
		})
		if got.Action != policy.ActionAllow {
			t.Fatalf("mandated recipient %q must be allowed, got %s: %s", recipient, got.Action, got.Reason)
		}
	}

	got = evalTool(eng, "send_email", map[string]string{
		"to":         "finance@example.com",
		"invoice_id": "123",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("mandated recipient on 'to' must be allowed, got %s: %s", got.Action, got.Reason)
	}

	got = evalAny(eng, "send_email", map[string]any{
		"recipient":  "finance@example.com",
		"to":         "Finance@Example.com",
		"email":      " finance@example.com ",
		"invoice_id": "123",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("identical mandated aliases must be allowed, got %s: %s", got.Action, got.Reason)
	}
}

func TestAuthorityNonEscalationExpansionDenied(t *testing.T) {
	eng := loadSARAEngine(t)

	cases := []struct {
		name string
		tool string
		args map[string]string
		want string
	}{
		{
			name: "new mailbox on the same domain",
			tool: "send_email",
			args: map[string]string{"recipient": "attacker@example.com", "invoice_id": "123"},
			want: "recipient is not in allowlist",
		},
		{
			name: "new external domain",
			tool: "send_email",
			args: map[string]string{"recipient": "attacker@evil.example", "invoice_id": "123"},
			want: "recipient is not in allowlist",
		},
		{
			name: "suffix spoof of mandated mailbox",
			tool: "send_email",
			args: map[string]string{"recipient": "finance@example.com.evil.example"},
			want: "recipient is not in allowlist",
		},
		{
			name: "missing recipient",
			tool: "send_email",
			args: map[string]string{"invoice_id": "123"},
			want: "recipient is required",
		},
		{
			name: "blank recipient",
			tool: "send_email",
			args: map[string]string{"recipient": "   "},
			want: "recipient is required",
		},
		{
			name: "new operation",
			tool: "shell_exec",
			args: map[string]string{"command": "rm -rf /workspace"},
			want: "not registered",
		},
		{
			name: "broader resource scope",
			tool: "file_read",
			args: map[string]string{"path": "/etc/passwd"},
			want: "path does not match any allow pattern",
		},
		{
			name: "cc alias expansion",
			tool: "send_email",
			args: map[string]string{"recipient": "finance@example.com", "cc": "attacker@example.com"},
			want: "recipient is not in allowlist",
		},
		{
			name: "bcc alias expansion",
			tool: "send_email",
			args: map[string]string{"recipient": "finance@example.com", "bcc": "attacker@evil.example"},
			want: "recipient is not in allowlist",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalTool(eng, tc.tool, tc.args)
			if got.Action != policy.ActionDeny {
				t.Fatalf("expected deny, got %s: %s", got.Action, got.Reason)
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Fatalf("expected reason containing %q, got %q", tc.want, got.Reason)
			}
		})
	}
}

func TestAuthorityNonEscalationEveryPresentAliasIsChecked(t *testing.T) {
	eng := loadSARAEngine(t)
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{
			name: "mandated recipient cannot cover attacker to",
			args: map[string]any{"recipient": "finance@example.com", "to": "attacker@example.com"},
			want: "recipient is not in allowlist",
		},
		{
			name: "mandated recipient cannot cover attacker email",
			args: map[string]any{"recipient": "finance@example.com", "email": "attacker@example.com"},
			want: "recipient is not in allowlist",
		},
		{
			name: "mandated recipient cannot cover attacker cc",
			args: map[string]any{"recipient": "finance@example.com", "cc": "attacker@example.com"},
			want: "recipient is not in allowlist",
		},
		{
			name: "mandated recipient cannot cover attacker bcc",
			args: map[string]any{"recipient": "finance@example.com", "bcc": "attacker@evil.example"},
			want: "recipient is not in allowlist",
		},
		{
			name: "non-string recipient cannot fall through to allowed to",
			args: map[string]any{"recipient": []string{"attacker@example.com"}, "to": "finance@example.com"},
			want: "recipient is required",
		},
		{
			name: "blank to cannot be skipped because recipient is allowed",
			args: map[string]any{"recipient": "finance@example.com", "to": "  "},
			want: "recipient is required",
		},
		{
			name: "numeric recipient fails closed",
			args: map[string]any{"recipient": 1, "to": "finance@example.com"},
			want: "recipient is required",
		},
		{
			name: "null recipient cannot fall through to allowed to",
			args: map[string]any{"recipient": nil, "to": "finance@example.com"},
			want: "recipient is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalAny(eng, "send_email", tc.args)
			if got.Action != policy.ActionDeny {
				t.Fatalf("expected deny, got %s: %s", got.Action, got.Reason)
			}
			if got.Reason != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got.Reason)
			}
		})
	}
}

func TestAuthorityNonEscalationEmptyAllowlistFailsClosed(t *testing.T) {
	p, err := policy.Load([]byte(`
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "send_email"
        allowed: true
        rules:
          - type: allow_recipient
            patterns: []
`))
	if err != nil {
		t.Fatalf("empty allowlist must still load (lint warns; engine fails closed): %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalTool(eng, "send_email", map[string]string{"recipient": "finance@example.com"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("empty allowlist must deny, got %s: %s", got.Action, got.Reason)
	}
	if got.Reason != "recipient allowlist is empty" {
		t.Fatalf("expected empty-allowlist reason, got %q", got.Reason)
	}
}

func TestAuthorityNonEscalationNonStringRecipientFailsClosed(t *testing.T) {
	eng := loadSARAEngine(t)
	got := eng.Evaluate("workspace", mcp.ToolsCallRequest{
		Name:      "send_email",
		Arguments: mustMarshal(map[string]any{"recipient": []string{"finance@example.com", "attacker@example.com"}}),
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("non-string recipient must deny, got %s: %s", got.Action, got.Reason)
	}
	if got.Reason != "recipient is required" {
		t.Fatalf("expected required-recipient reason, got %q", got.Reason)
	}
}

func TestAuthorityNonEscalationHistoryDoesNotPromoteRecipient(t *testing.T) {
	eng := loadSARAEngine(t)
	attacker := map[string]string{"recipient": "attacker@example.com", "invoice_id": "123"}

	first := evalTool(eng, "send_email", attacker)
	second := evalTool(eng, "send_email", attacker)
	if first.Action != policy.ActionDeny || second.Action != policy.ActionDeny {
		t.Fatalf("repeated unauthorized recipient must stay denied, first=%s second=%s", first.Action, second.Action)
	}

	// An intervening authorized call must not launder the attacker mailbox.
	if got := evalTool(eng, "file_read", map[string]string{"path": "/workspace/invoices/123.pdf"}); got.Action != policy.ActionAllow {
		t.Fatalf("authorized invoice read should still allow, got %s: %s", got.Action, got.Reason)
	}
	third := evalTool(eng, "send_email", attacker)
	if third.Action != policy.ActionDeny {
		t.Fatalf("history after an allowed instantiation must not promote attacker recipient, got %s: %s", third.Action, third.Reason)
	}
}

func TestAuthorityNonEscalationDuplicateArgumentKeysFailClosed(t *testing.T) {
	eng := loadSARAEngine(t)

	// encoding/json last-wins would keep finance@example.com; a first-wins
	// MCP decoder would send to attacker. Deny the ambiguous object.
	got := evalRaw(eng, "send_email", json.RawMessage(
		`{"recipient":"attacker@example.com","recipient":"finance@example.com"}`,
	))
	if got.Action != policy.ActionDeny {
		t.Fatalf("duplicate recipient key must deny, got %s: %s", got.Action, got.Reason)
	}
	if got.Reason != "duplicate argument key" {
		t.Fatalf("expected duplicate-key reason, got %q", got.Reason)
	}

	got = evalRaw(eng, "send_email", json.RawMessage(
		`{"recipient":"finance@example.com","recipient":"finance@example.com"}`,
	))
	if got.Action != policy.ActionDeny || got.Reason != "duplicate argument key" {
		t.Fatalf("identical duplicate keys must still deny, got %s: %s", got.Action, got.Reason)
	}

	got = evalRaw(eng, "send_email", json.RawMessage(
		`{"recipient":"finance@example.com","meta":{"id":"1","id":"2"}}`,
	))
	if got.Action != policy.ActionDeny || got.Reason != "duplicate argument key" {
		t.Fatalf("nested duplicate keys must deny, got %s: %s", got.Action, got.Reason)
	}

	got = evalRaw(eng, "send_email", json.RawMessage(
		`{"recipient":"finance@example.com","invoice_id":"123"}`,
	))
	if got.Action != policy.ActionAllow {
		t.Fatalf("unique keys must still allow, got %s: %s", got.Action, got.Reason)
	}
}

func TestLoadInvalidYAMLFailsClosed(t *testing.T) {
	_, err := policy.Load([]byte("default_action: ["))
	if err == nil {
		t.Fatal("invalid YAML must fail closed at load")
	}
}
