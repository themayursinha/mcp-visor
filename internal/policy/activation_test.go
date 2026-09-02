package policy_test

import (
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

const mcpRegistrationPolicy = `
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
              - "mcp.internal"
`

func loadActivationEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p, err := policy.Load([]byte(mcpRegistrationPolicy))
	if err != nil {
		t.Fatalf("load activation policy: %v", err)
	}
	return policy.NewEngine(p)
}

func evalRegisterTool(eng *policy.Engine, tool string, args map[string]any) policy.Decision {
	return eng.Evaluate("mcphub", mcp.ToolsCallRequest{
		Name:      tool,
		Arguments: mustMarshal(args),
	})
}

func assertActivationSpawnEvidence(t *testing.T, reason string) {
	t.Helper()
	for _, token := range []string{
		"unauthorized configuration activation",
		"argument class EXECUTABLE",
		"effect class PROCESS",
		"authority transition CONFIG->SPAWN",
	} {
		if !strings.Contains(reason, token) {
			t.Fatalf("deny reason missing evidence %q: %s", token, reason)
		}
	}
}

func assertActivationNetworkEvidence(t *testing.T, reason string) {
	t.Helper()
	for _, token := range []string{
		"unauthorized configuration activation",
		"argument class URL",
		"effect class NETWORK",
		"authority transition CONFIG->EGRESS",
	} {
		if !strings.Contains(reason, token) {
			t.Fatalf("deny reason missing evidence %q: %s", token, reason)
		}
	}
}

func TestActivationMandateInstantiationAllowed(t *testing.T) {
	eng := loadActivationEngine(t)

	got := evalRegisterTool(eng, "file_read", map[string]any{"path": "/workspace/tickets.md"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("legitimate local read must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalRegisterTool(eng, "register_mcp", map[string]any{
		"command": "/usr/bin/node",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("mandated binary must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalRegisterTool(eng, "register_mcp", map[string]any{
		"url": "https://mcp.internal/sse",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("mandated host must allow, got %s: %s", got.Action, got.Reason)
	}
}

func TestActivationSpawnDenied(t *testing.T) {
	eng := loadActivationEngine(t)
	got := evalRegisterTool(eng, "register_mcp", map[string]any{
		"command": "/bin/sh",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("/bin/sh must deny, got %s: %s", got.Action, got.Reason)
	}
	assertActivationSpawnEvidence(t, got.Reason)

	got = evalRegisterTool(eng, "register_mcp", map[string]any{
		"command": "/usr/bin/node.evil",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("suffix spoof must deny, got %s: %s", got.Action, got.Reason)
	}
	assertActivationSpawnEvidence(t, got.Reason)
}

func TestActivationNetworkDenied(t *testing.T) {
	eng := loadActivationEngine(t)
	got := evalRegisterTool(eng, "register_mcp", map[string]any{
		"url": "http://169.254.169.254/",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("link-local metadata must deny, got %s: %s", got.Action, got.Reason)
	}
	assertActivationNetworkEvidence(t, got.Reason)
}

func TestActivationEveryPresentAliasIsChecked(t *testing.T) {
	eng := loadActivationEngine(t)
	got := evalRegisterTool(eng, "register_mcp", map[string]any{
		"command": "/usr/bin/node",
		"url":     "http://169.254.169.254/",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("shadow metadata url must deny, got %s: %s", got.Action, got.Reason)
	}
	assertActivationNetworkEvidence(t, got.Reason)

	got = evalRegisterTool(eng, "register_mcp", map[string]any{
		"Stdio_Command": "/bin/sh",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("Stdio_Command alias must deny, got %s: %s", got.Action, got.Reason)
	}
	assertActivationSpawnEvidence(t, got.Reason)
}

func TestActivationMissingFailsClosed(t *testing.T) {
	eng := loadActivationEngine(t)
	cases := []struct {
		name   string
		args   map[string]any
		reason string
	}{
		{name: "missing", args: map[string]any{"name": "helper"}, reason: "activation target is required"},
		{name: "blank", args: map[string]any{"command": "   "}, reason: "executable is required"},
		{name: "non-string", args: map[string]any{"command": 123}, reason: "executable is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalRegisterTool(eng, "register_mcp", tc.args)
			if got.Action != policy.ActionDeny {
				t.Fatalf("missing/blank activation must deny, got %s: %s", got.Action, got.Reason)
			}
			if !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("want %s, got %s", tc.reason, got.Reason)
			}
		})
	}
}

func TestActivationEmptyAllowlistFailsClosed(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "mcphub"
    allowed: true
    tools:
      - name: "register_mcp"
        allowed: true
        rules:
          - type: allow_activation
            patterns: ["   "]
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalRegisterTool(eng, "register_mcp", map[string]any{
		"command": "/usr/bin/node",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("empty allowlist must deny, got %s: %s", got.Action, got.Reason)
	}
	if !strings.Contains(got.Reason, "activation allowlist is empty") {
		t.Fatalf("want empty allowlist reason, got %s", got.Reason)
	}
}

func TestAllowCommandPatternDoesNotInspectStdioCommand(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "mcphub"
    allowed: true
    tools:
      - name: "register_mcp"
        allowed: true
        rules:
          - type: allow_command_pattern
            patterns:
              - "node"
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalRegisterTool(eng, "register_mcp", map[string]any{
		"stdio_command": "/bin/sh",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("parent gap: allow_command_pattern must not bind stdio_command, got %s: %s", got.Action, got.Reason)
	}
}

func TestActivationDoesNotInspectArgs(t *testing.T) {
	eng := loadActivationEngine(t)
	got := evalRegisterTool(eng, "register_mcp", map[string]any{
		"command": "/usr/bin/node",
		"args":    []any{"-c", "/bin/sh"},
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("args arrays are out of model, got %s: %s", got.Action, got.Reason)
	}
}
