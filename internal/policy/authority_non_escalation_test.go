package policy_test

import (
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

func TestLoadInvalidYAMLFailsClosed(t *testing.T) {
	_, err := policy.Load([]byte("default_action: ["))
	if err == nil {
		t.Fatal("invalid YAML must fail closed at load")
	}
}
