package policy_test

import (
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

const argoApplicationPolicy = `
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

func loadApplicationEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p, err := policy.Load([]byte(argoApplicationPolicy))
	if err != nil {
		t.Fatalf("load application policy: %v", err)
	}
	return policy.NewEngine(p)
}

func evalArgoTool(eng *policy.Engine, tool string, args map[string]any) policy.Decision {
	return eng.Evaluate("argocd", mcp.ToolsCallRequest{
		Name:      tool,
		Arguments: mustMarshal(args),
	})
}

func assertApplicationEvidence(t *testing.T, reason string) {
	t.Helper()
	for _, token := range []string{
		"authority-expanding application",
		"argument class APPLICATION",
		"effect class CONTROL_PLANE",
		"authority transition MANDATE->CLUSTER",
	} {
		if !strings.Contains(reason, token) {
			t.Fatalf("deny reason missing evidence %q: %s", token, reason)
		}
	}
}

func TestApplicationMandateInstantiationAllowed(t *testing.T) {
	eng := loadApplicationEngine(t)

	got := evalArgoTool(eng, "file_read", map[string]any{"path": "/workspace/tickets.md"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("legitimate local read must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalArgoTool(eng, "argocd_sync", map[string]any{
		"application": "staging-orders",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("mandated application must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalArgoTool(eng, "argocd_sync", map[string]any{
		"name": "staging-orders",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("mandated application via name must allow, got %s: %s", got.Action, got.Reason)
	}
}

func TestApplicationAuthorityExpandingDenied(t *testing.T) {
	eng := loadApplicationEngine(t)
	got := evalArgoTool(eng, "argocd_sync", map[string]any{
		"application": "production-payments",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("production application must deny, got %s: %s", got.Action, got.Reason)
	}
	assertApplicationEvidence(t, got.Reason)

	got = evalArgoTool(eng, "argocd_sync", map[string]any{
		"application": "staging-orders.evil",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("suffix spoof must deny, got %s: %s", got.Action, got.Reason)
	}
	assertApplicationEvidence(t, got.Reason)
}

func TestApplicationEveryPresentAliasIsChecked(t *testing.T) {
	eng := loadApplicationEngine(t)
	got := evalArgoTool(eng, "argocd_sync", map[string]any{
		"application": "staging-orders",
		"app":         "production-payments",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("shadow app alias must deny, got %s: %s", got.Action, got.Reason)
	}
	assertApplicationEvidence(t, got.Reason)

	got = evalArgoTool(eng, "argocd_sync", map[string]any{
		"App_Name": "production-payments",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("App_Name alias must deny, got %s: %s", got.Action, got.Reason)
	}
	assertApplicationEvidence(t, got.Reason)
}

func TestApplicationMissingFailsClosed(t *testing.T) {
	eng := loadApplicationEngine(t)
	cases := []struct {
		name string
		args map[string]any
	}{
		{name: "missing", args: map[string]any{"revision": "main"}},
		{name: "blank", args: map[string]any{"application": "   "}},
		{name: "non-string", args: map[string]any{"application": 123}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalArgoTool(eng, "argocd_sync", tc.args)
			if got.Action != policy.ActionDeny {
				t.Fatalf("missing/blank application must deny, got %s: %s", got.Action, got.Reason)
			}
			if !strings.Contains(got.Reason, "application is required") {
				t.Fatalf("want application is required, got %s", got.Reason)
			}
		})
	}
}

func TestApplicationEmptyAllowlistFailsClosed(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "argocd"
    allowed: true
    tools:
      - name: "argocd_sync"
        allowed: true
        rules:
          - type: allow_application
            patterns: ["   "]
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalArgoTool(eng, "argocd_sync", map[string]any{
		"application": "staging-orders",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("empty allowlist must deny, got %s: %s", got.Action, got.Reason)
	}
	if !strings.Contains(got.Reason, "application allowlist is empty") {
		t.Fatalf("want empty allowlist reason, got %s", got.Reason)
	}
}

func TestAllowedReposDoesNotInspectApplication(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "argocd"
    allowed: true
    tools:
      - name: "argocd_sync"
        allowed: true
        rules:
          - type: allowed_repos
            repos:
              - "org/staging-orders"
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalArgoTool(eng, "argocd_sync", map[string]any{
		"repo":        "org/staging-orders",
		"application": "production-payments",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("parent gap: allowed_repos must not bind application, got %s: %s", got.Action, got.Reason)
	}
}

func TestApplicationDoesNotInspectCommand(t *testing.T) {
	eng := loadApplicationEngine(t)
	got := evalArgoTool(eng, "argocd_sync", map[string]any{
		"application": "staging-orders",
		"command":     "argocd sync production-payments",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("command strings are out of model, got %s: %s", got.Action, got.Reason)
	}
}
