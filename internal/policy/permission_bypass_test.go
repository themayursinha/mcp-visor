package policy_test

import (
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

const spawnPermissionBypassPolicy = `
version: "1.0"
description: "Spawn workers without skipping permissions"
default_action: deny
servers:
  - name: "orchestrator"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: low
      - name: "spawn_agent"
        allowed: true
        risk: high
        rules:
          - type: deny_permission_bypass
`

func loadPermissionBypassEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p, err := policy.Load([]byte(spawnPermissionBypassPolicy))
	if err != nil {
		t.Fatalf("load permission-bypass policy: %v", err)
	}
	return policy.NewEngine(p)
}

func evalSpawnTool(eng *policy.Engine, tool string, args map[string]any) policy.Decision {
	return eng.Evaluate("orchestrator", mcp.ToolsCallRequest{
		Name:      tool,
		Arguments: mustMarshal(args),
	})
}

func assertPermissionBypassEvidence(t *testing.T, reason string) {
	t.Helper()
	for _, token := range []string{
		"permission-bypass delegation",
		"argument class PERMISSION",
		"effect class DELEGATION",
		"authority transition PARENT->CHILD",
	} {
		if !strings.Contains(reason, token) {
			t.Fatalf("deny reason missing evidence %q: %s", token, reason)
		}
	}
}

func TestPermissionBypassMandateInstantiationAllowed(t *testing.T) {
	eng := loadPermissionBypassEngine(t)

	got := evalSpawnTool(eng, "file_read", map[string]any{"path": "/workspace/tickets.md"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("legitimate local read must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalSpawnTool(eng, "spawn_agent", map[string]any{
		"task": "deploy staging",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("spawn without a bypass flag must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalSpawnTool(eng, "spawn_agent", map[string]any{
		"task":             "deploy staging",
		"skip_permissions": false,
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("explicitly-off skip_permissions must allow, got %s: %s", got.Action, got.Reason)
	}
}

func TestPermissionBypassDenied(t *testing.T) {
	eng := loadPermissionBypassEngine(t)
	got := evalSpawnTool(eng, "spawn_agent", map[string]any{
		"task":             "deploy staging",
		"skip_permissions": true,
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("skip_permissions true must deny, got %s: %s", got.Action, got.Reason)
	}
	assertPermissionBypassEvidence(t, got.Reason)

	got = evalSpawnTool(eng, "spawn_agent", map[string]any{
		"task":             "deploy staging",
		"skip_permissions": "--dangerously-skip-permissions",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("dangerously-skip-permissions string must deny, got %s: %s", got.Action, got.Reason)
	}
	assertPermissionBypassEvidence(t, got.Reason)
}

func TestPermissionBypassEveryPresentAliasIsChecked(t *testing.T) {
	eng := loadPermissionBypassEngine(t)
	got := evalSpawnTool(eng, "spawn_agent", map[string]any{
		"task":                         "deploy staging",
		"skip_permissions":             false,
		"dangerously_skip_permissions": true,
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("shadow dangerously_skip_permissions must deny, got %s: %s", got.Action, got.Reason)
	}
	assertPermissionBypassEvidence(t, got.Reason)

	got = evalSpawnTool(eng, "spawn_agent", map[string]any{
		"Skip_Permissions": true,
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("Skip_Permissions alias must deny, got %s: %s", got.Action, got.Reason)
	}
	assertPermissionBypassEvidence(t, got.Reason)
}

func TestPermissionBypassBlankFailsClosed(t *testing.T) {
	eng := loadPermissionBypassEngine(t)
	cases := []struct {
		name string
		args map[string]any
	}{
		{name: "blank", args: map[string]any{"skip_permissions": "   "}},
		{name: "non-string", args: map[string]any{"skip_permissions": 123}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalSpawnTool(eng, "spawn_agent", tc.args)
			if got.Action != policy.ActionDeny {
				t.Fatalf("blank/non-bool bypass must deny, got %s: %s", got.Action, got.Reason)
			}
			if !strings.Contains(got.Reason, "permission bypass is required") {
				t.Fatalf("want permission bypass is required, got %s", got.Reason)
			}
		})
	}
}

func TestAllowCommandPatternDoesNotInspectPermissionBypass(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "orchestrator"
    allowed: true
    tools:
      - name: "spawn_agent"
        allowed: true
        rules:
          - type: allow_command_pattern
            patterns:
              - "spawn"
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalSpawnTool(eng, "spawn_agent", map[string]any{
		"command":          "spawn worker",
		"skip_permissions": true,
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("parent gap: allow_command_pattern must not bind skip_permissions, got %s: %s", got.Action, got.Reason)
	}
}

func TestPermissionBypassDoesNotInspectCommand(t *testing.T) {
	eng := loadPermissionBypassEngine(t)
	got := evalSpawnTool(eng, "spawn_agent", map[string]any{
		"task":    "deploy staging",
		"command": "spawn --dangerously-skip-permissions",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("command strings are out of model, got %s: %s", got.Action, got.Reason)
	}
}
