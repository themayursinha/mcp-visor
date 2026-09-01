package policy_test

import (
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

func evalNamed(eng *policy.Engine, server, tool string, args map[string]any) policy.Decision {
	return eng.Evaluate(server, mcp.ToolsCallRequest{
		Name:      tool,
		Arguments: mustMarshal(args),
	})
}

func TestTimeRestrictionEmptyOutsideActionFailsClosed(t *testing.T) {
	day := strings.ToLower(time.Now().Weekday().String())
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "neo"
    allowed: true
    tools:
      - name: "check_syntax"
        allowed: true
        rules:
          - type: require_path_literal
time_restrictions:
  - name: "weekends"
    servers: ["neo"]
    tools: ["check_syntax"]
    denied_days: ["` + day + `"]
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalNamed(eng, "neo", "check_syntax", map[string]any{"path": "/workspace/src/app.mjs"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("omitted outside_action must fail closed, got %s: %s", got.Action, got.Reason)
	}
	if !strings.Contains(got.Reason, "unsupported policy action") {
		t.Fatalf("deny must name the unsupported action, got %s", got.Reason)
	}
}

func TestTimeRestrictionEmptyOutsideActionDoesNotDefaultAllowPastApproval(t *testing.T) {
	day := strings.ToLower(time.Now().Weekday().String())
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "neo"
    allowed: true
    tools:
      - name: "check_syntax"
        allowed: true
        rules:
          - type: require_approval_always
          - type: require_path_literal
time_restrictions:
  - name: "weekends"
    servers: ["neo"]
    tools: ["check_syntax"]
    denied_days: ["` + day + `"]
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalNamed(eng, "neo", "check_syntax", map[string]any{"path": "/workspace/src/app.mjs"})
	if got.Action == policy.ActionAllow || got.Action == "" {
		t.Fatalf("pending approval must not become allow via empty outside_action, got %s: %s", got.Action, got.Reason)
	}
	if got.Action != policy.ActionDeny {
		t.Fatalf("unsupported time action must deny, got %s: %s", got.Action, got.Reason)
	}
}

func TestTimeRestrictionAllowPreservesPendingApproval(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "neo"
    allowed: true
    tools:
      - name: "check_syntax"
        allowed: true
        rules:
          - type: require_approval_always
          - type: require_path_literal
time_restrictions:
  - name: "never_matches"
    servers: ["neo"]
    tools: ["check_syntax"]
    denied_days: ["not-a-real-day"]
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalNamed(eng, "neo", "check_syntax", map[string]any{"path": "/workspace/src/app.mjs"})
	if got.Action != policy.ActionRequireApproval {
		t.Fatalf("non-matching time restriction must keep pending approval, got %s: %s", got.Action, got.Reason)
	}
}

func TestTimeRestrictionDenyBeatsPendingApproval(t *testing.T) {
	day := strings.ToLower(time.Now().Weekday().String())
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "neo"
    allowed: true
    tools:
      - name: "check_syntax"
        allowed: true
        rules:
          - type: require_approval_always
          - type: require_path_literal
time_restrictions:
  - name: "weekends"
    servers: ["neo"]
    tools: ["check_syntax"]
    denied_days: ["` + day + `"]
    outside_action: deny
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalNamed(eng, "neo", "check_syntax", map[string]any{"path": "/workspace/src/app.mjs"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("time deny must beat pending approval, got %s: %s", got.Action, got.Reason)
	}
	if strings.Contains(got.Reason, "unsupported policy action") {
		t.Fatalf("configured deny must keep the time-restriction reason, got %s", got.Reason)
	}
}

func TestTimeRestrictionRedactThenAllowFailsClosed(t *testing.T) {
	day := strings.ToLower(time.Now().Weekday().String())
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "neo"
    allowed: true
    tools:
      - name: "check_syntax"
        allowed: true
        rules:
          - type: require_path_literal
time_restrictions:
  - name: "weekends"
    servers: ["neo"]
    tools: ["check_syntax"]
    denied_days: ["` + day + `"]
    outside_action: redact_then_allow
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalNamed(eng, "neo", "check_syntax", map[string]any{"path": "/workspace/src/app.mjs"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("redact_then_allow is not an Evaluate action and must deny, got %s: %s", got.Action, got.Reason)
	}
	if !strings.Contains(got.Reason, "unsupported policy action") {
		t.Fatalf("deny must name the unsupported action, got %s", got.Reason)
	}
}

func TestPathShellDenyStillBeatsTimeAndApproval(t *testing.T) {
	day := strings.ToLower(time.Now().Weekday().String())
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "neo"
    allowed: true
    tools:
      - name: "check_syntax"
        allowed: true
        rules:
          - type: require_approval_always
          - type: require_path_literal
time_restrictions:
  - name: "weekends"
    servers: ["neo"]
    tools: ["check_syntax"]
    denied_days: ["` + day + `"]
    outside_action: require_approval
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalNamed(eng, "neo", "check_syntax", map[string]any{"path": "/workspace/src/app.mjs; id"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("PATH→SHELL must deny before time/approval, got %s: %s", got.Action, got.Reason)
	}
	assertPathToShellEvidence(t, got.Reason)
}
