package policy_test

import (
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

const environmentLaunderingPolicy = `
version: "1.0"
description: "Run decoder only under /workspace/safe"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: low
      - name: "run_python"
        allowed: true
        risk: high
        rules:
          - type: allow_working_directory
            patterns:
              - "/workspace/safe"
              - "/workspace/safe/**"
`

func loadWorkingDirectoryEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p, err := policy.Load([]byte(environmentLaunderingPolicy))
	if err != nil {
		t.Fatalf("load working directory policy: %v", err)
	}
	return policy.NewEngine(p)
}

func evalWorkspaceTool(eng *policy.Engine, tool string, args map[string]any) policy.Decision {
	return eng.Evaluate("workspace", mcp.ToolsCallRequest{
		Name:      tool,
		Arguments: mustMarshal(args),
	})
}

func assertWorkingDirectoryEvidence(t *testing.T, reason string) {
	t.Helper()
	for _, token := range []string{
		"untrusted execution environment",
		"argument class PATH",
		"effect class EXECUTION",
		"authority transition MANDATE->ENVIRONMENT",
	} {
		if !strings.Contains(reason, token) {
			t.Fatalf("deny reason missing evidence %q: %s", token, reason)
		}
	}
}

func TestWorkingDirectoryMandateInstantiationAllowed(t *testing.T) {
	eng := loadWorkingDirectoryEngine(t)

	got := evalWorkspaceTool(eng, "file_read", map[string]any{"path": "/workspace/tickets.md"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("legitimate local read must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalWorkspaceTool(eng, "run_python", map[string]any{
		"script": "/workspace/decoder.py",
		"cwd":    "/workspace/safe",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("mandated cwd must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalWorkspaceTool(eng, "run_python", map[string]any{
		"script":            "/workspace/decoder.py",
		"working_directory": "/workspace/safe/pkg",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("mandated nested cwd via working_directory must allow, got %s: %s", got.Action, got.Reason)
	}
}

func TestWorkingDirectoryUntrustedExtractDenied(t *testing.T) {
	eng := loadWorkingDirectoryEngine(t)
	got := evalWorkspaceTool(eng, "run_python", map[string]any{
		"script": "/workspace/decoder.py",
		"cwd":    "/tmp/attacker-extract",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("untrusted extract cwd must deny, got %s: %s", got.Action, got.Reason)
	}
	assertWorkingDirectoryEvidence(t, got.Reason)
}

func TestWorkingDirectoryEveryPresentAliasIsChecked(t *testing.T) {
	eng := loadWorkingDirectoryEngine(t)
	got := evalWorkspaceTool(eng, "run_python", map[string]any{
		"script":            "/workspace/decoder.py",
		"cwd":               "/workspace/safe",
		"working_directory": "/tmp/attacker-extract",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("shadow working_directory alias must deny, got %s: %s", got.Action, got.Reason)
	}
	assertWorkingDirectoryEvidence(t, got.Reason)
}

func TestWorkingDirectoryMissingFailsClosed(t *testing.T) {
	eng := loadWorkingDirectoryEngine(t)
	cases := []struct {
		name string
		args map[string]any
	}{
		{name: "missing", args: map[string]any{"script": "/workspace/decoder.py"}},
		{name: "blank", args: map[string]any{"script": "/workspace/decoder.py", "cwd": "   "}},
		{name: "non-string", args: map[string]any{"script": "/workspace/decoder.py", "cwd": 123}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalWorkspaceTool(eng, "run_python", tc.args)
			if got.Action != policy.ActionDeny {
				t.Fatalf("missing/blank cwd must deny, got %s: %s", got.Action, got.Reason)
			}
			if !strings.Contains(got.Reason, "working directory is required") {
				t.Fatalf("want working directory is required, got %s", got.Reason)
			}
		})
	}
}

func TestWorkingDirectoryEmptyAllowlistFailsClosed(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "run_python"
        allowed: true
        rules:
          - type: allow_working_directory
            patterns: ["   "]
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalWorkspaceTool(eng, "run_python", map[string]any{
		"script": "/workspace/decoder.py",
		"cwd":    "/workspace/safe",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("empty allowlist must deny, got %s: %s", got.Action, got.Reason)
	}
	if !strings.Contains(got.Reason, "working directory allowlist is empty") {
		t.Fatalf("want empty allowlist reason, got %s", got.Reason)
	}
}

func TestAllowPathSlotDoesNotInspectCwd(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "run_python"
        allowed: true
        rules:
          - type: allow_path_slot
            patterns:
              - "/workspace/**"
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalWorkspaceTool(eng, "run_python", map[string]any{
		"path": "/workspace/decoder.py",
		"cwd":  "/tmp/attacker-extract",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("parent gap: allow_path_slot must not bind cwd, got %s: %s", got.Action, got.Reason)
	}
}

func TestWorkingDirectoryDoesNotInspectCommand(t *testing.T) {
	eng := loadWorkingDirectoryEngine(t)
	got := evalWorkspaceTool(eng, "run_python", map[string]any{
		"cwd":     "/workspace/safe",
		"command": "python /tmp/attacker-extract/struct.py",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("command strings are out of model, got %s: %s", got.Action, got.Reason)
	}
}
