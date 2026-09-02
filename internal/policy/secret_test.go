package policy_test

import (
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

const credentialRotationPolicy = `
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

func loadSecretEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p, err := policy.Load([]byte(credentialRotationPolicy))
	if err != nil {
		t.Fatalf("load secret policy: %v", err)
	}
	return policy.NewEngine(p)
}

func evalGatewayTool(eng *policy.Engine, tool string, args map[string]any) policy.Decision {
	return eng.Evaluate("gateway", mcp.ToolsCallRequest{
		Name:      tool,
		Arguments: mustMarshal(args),
	})
}

func assertSecretCustodyEvidence(t *testing.T, reason string) {
	t.Helper()
	for _, token := range []string{
		"untrusted credential custody",
		"argument class SECRET",
		"effect class CREDENTIAL",
		"authority transition MANDATE->CUSTODY",
	} {
		if !strings.Contains(reason, token) {
			t.Fatalf("deny reason missing evidence %q: %s", token, reason)
		}
	}
}

func TestSecretMandateInstantiationAllowed(t *testing.T) {
	eng := loadSecretEngine(t)

	got := evalGatewayTool(eng, "file_read", map[string]any{"path": "/workspace/tickets.md"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("legitimate local read must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalGatewayTool(eng, "configure_secret", map[string]any{
		"name": "openai",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("configure_secret without a SECRET-class arg must allow, got %s: %s", got.Action, got.Reason)
	}
}

func TestSecretRotationDenied(t *testing.T) {
	eng := loadSecretEngine(t)
	got := evalGatewayTool(eng, "configure_secret", map[string]any{
		"name":    "openai",
		"api_key": "KEY_B",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("replacement api_key must deny, got %s: %s", got.Action, got.Reason)
	}
	assertSecretCustodyEvidence(t, got.Reason)
}

func TestSecretEveryPresentAliasIsChecked(t *testing.T) {
	eng := loadSecretEngine(t)
	cases := []map[string]any{
		{"name": "openai", "new_key": "KEY_B"},
		{"name": "openai", "Api_Key": "KEY_B"},
		{"name": "openai", "token": "KEY_B"},
	}
	for _, args := range cases {
		got := evalGatewayTool(eng, "configure_secret", args)
		if got.Action != policy.ActionDeny {
			t.Fatalf("present SECRET-class alias must deny, args=%v got %s: %s", args, got.Action, got.Reason)
		}
		assertSecretCustodyEvidence(t, got.Reason)
	}
}

func TestSecretBlankFailsClosed(t *testing.T) {
	eng := loadSecretEngine(t)
	cases := []struct {
		name string
		args map[string]any
	}{
		{name: "blank", args: map[string]any{"name": "openai", "api_key": "   "}},
		{name: "non-string", args: map[string]any{"name": "openai", "api_key": 123}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalGatewayTool(eng, "configure_secret", tc.args)
			if got.Action != policy.ActionDeny {
				t.Fatalf("blank/non-string secret must deny, got %s: %s", got.Action, got.Reason)
			}
			if !strings.Contains(got.Reason, "credential is required") {
				t.Fatalf("want credential is required, got %s", got.Reason)
			}
		})
	}
}

func TestAllowPathDoesNotInspectSecret(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "gateway"
    allowed: true
    tools:
      - name: "configure_secret"
        allowed: true
        rules:
          - type: allow_path
            patterns:
              - "/workspace/**"
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalGatewayTool(eng, "configure_secret", map[string]any{
		"path":    "/workspace/openai.yaml",
		"api_key": "KEY_B",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("parent gap: allow_path must not bind api_key, got %s: %s", got.Action, got.Reason)
	}
}

func TestSecretDoesNotInspectCommand(t *testing.T) {
	eng := loadSecretEngine(t)
	got := evalGatewayTool(eng, "configure_secret", map[string]any{
		"name":    "openai",
		"command": "echo KEY_B",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("command strings are out of model, got %s: %s", got.Action, got.Reason)
	}
}
