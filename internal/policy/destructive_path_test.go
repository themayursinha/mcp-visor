package policy_test

import (
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

const destructivePathPolicy = `
version: "1.0"
description: "Clean /tmp/agent-123; do not delete $HOME"
default_action: deny
servers:
  - name: "sandbox"
    allowed: true
    tools:
      - name: "cleanup_sandbox"
        allowed: true
        risk: high
        rules:
          - type: allow_path_slot
            patterns:
              - "/tmp/agent-123"
              - "/tmp/agent-123/**"
`

func loadDestructiveEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p, err := policy.Load([]byte(destructivePathPolicy))
	if err != nil {
		t.Fatalf("load destructive policy: %v", err)
	}
	return policy.NewEngine(p)
}

func evalCleanup(eng *policy.Engine, args map[string]any) policy.Decision {
	return eng.Evaluate("sandbox", mcp.ToolsCallRequest{
		Name:      "cleanup_sandbox",
		Arguments: mustMarshal(args),
	})
}

func assertDestructiveEvidence(t *testing.T, reason string) {
	t.Helper()
	for _, token := range []string{
		"destructive path outside mandate",
		"argument class PATH",
		"effect class DESTRUCTIVE",
		"authority transition MANDATE->COLLATERAL",
	} {
		if !strings.Contains(reason, token) {
			t.Fatalf("deny reason missing evidence %q: %s", token, reason)
		}
	}
}

func TestDestructivePathMandateInstantiationAllowed(t *testing.T) {
	eng := loadDestructiveEngine(t)

	got := evalCleanup(eng, map[string]any{"target": "/tmp/agent-123"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("sandbox root must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalCleanup(eng, map[string]any{"target": "/tmp/agent-123/expired.log"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("sandbox child must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalCleanup(eng, map[string]any{"Target": "/tmp/agent-123/nested/dir"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("Target alias must allow, got %s: %s", got.Action, got.Reason)
	}
}

func TestDestructivePathHomeDenied(t *testing.T) {
	eng := loadDestructiveEngine(t)

	got := evalCleanup(eng, map[string]any{"target": "/home/user"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("user home must deny, got %s: %s", got.Action, got.Reason)
	}
	assertDestructiveEvidence(t, got.Reason)

	got = evalCleanup(eng, map[string]any{"target": "$HOME"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("literal $HOME must deny, got %s: %s", got.Action, got.Reason)
	}
	assertDestructiveEvidence(t, got.Reason)
}

func TestDestructivePathEveryPresentAliasIsChecked(t *testing.T) {
	eng := loadDestructiveEngine(t)
	got := evalCleanup(eng, map[string]any{
		"path":   "/tmp/agent-123",
		"target": "/home/user",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("shadow target alias must deny, got %s: %s", got.Action, got.Reason)
	}
	assertDestructiveEvidence(t, got.Reason)
}

func TestDestructivePathMissingFailsClosed(t *testing.T) {
	eng := loadDestructiveEngine(t)
	cases := []struct {
		name string
		args map[string]any
	}{
		{name: "missing", args: map[string]any{"command": "rm -rf /tmp/agent-123"}},
		{name: "blank", args: map[string]any{"target": "   "}},
		{name: "non-string", args: map[string]any{"target": 123}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalCleanup(eng, tc.args)
			if got.Action != policy.ActionDeny {
				t.Fatalf("missing/blank/non-string effect path must deny, got %s: %s", got.Action, got.Reason)
			}
			if !strings.Contains(got.Reason, "effect path is required") {
				t.Fatalf("want effect path is required, got %s", got.Reason)
			}
		})
	}
}

func TestDestructivePathEmptyAllowlistFailsClosed(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "sandbox"
    allowed: true
    tools:
      - name: "cleanup_sandbox"
        allowed: true
        rules:
          - type: allow_path_slot
            patterns: ["   "]
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalCleanup(eng, map[string]any{"target": "/tmp/agent-123"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("empty allowlist must deny, got %s: %s", got.Action, got.Reason)
	}
	if !strings.Contains(got.Reason, "path slot allowlist is empty") {
		t.Fatalf("want empty allowlist reason, got %s", got.Reason)
	}
}

func TestAllowPathAloneDoesNotInspectTargetAlias(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "sandbox"
    allowed: true
    tools:
      - name: "cleanup_sandbox"
        allowed: true
        rules:
          - type: allow_path
            patterns:
              - "/tmp/agent-123/**"
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalCleanup(eng, map[string]any{"target": "/home/user"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("parent gap: allow_path first-match does not inspect target, got %s: %s", got.Action, got.Reason)
	}
}
