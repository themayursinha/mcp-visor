package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
)

type mandateSample struct {
	patterns  []string
	admitted  string
	violating string
}

var mandateSamples = map[string]mandateSample{
	"allow_recipient": {
		patterns:  []string{"finance@example.com"},
		admitted:  "finance@example.com",
		violating: "attacker@example.com",
	},
	"allow_working_directory": {
		patterns:  []string{"/workspace/safe", "/workspace/safe/**"},
		admitted:  "/workspace/safe",
		violating: "/tmp/attacker-extract",
	},
}

func TestMandateRuleTableRoutesConvertedTypes(t *testing.T) {
	for _, ruleType := range []string{"allow_recipient", "allow_working_directory"} {
		t.Run(ruleType, func(t *testing.T) {
			entry, ok := mandateRules[ruleType]
			if !ok {
				t.Fatalf("mandateRules missing entry for %s", ruleType)
			}
			sample, ok := mandateSamples[ruleType]
			if !ok {
				t.Fatalf("no sample for %s", ruleType)
			}
			if len(entry.aliases) == 0 {
				t.Fatalf("%s declares no alias", ruleType)
			}
			alias := entry.aliases[0]

			orig := entry
			patched := orig
			patched.emptyReason = ruleType + ":empty"
			patched.missingReason = ruleType + ":missing"
			patched.violationReason = ruleType + ":violation"
			mandateRules[ruleType] = patched
			t.Cleanup(func() {
				mandateRules[ruleType] = orig
			})

			eng := loadMandateEngine(t, ruleType, sample.patterns)
			emptyEng := loadMandateEngine(t, ruleType, []string{})

			cases := []struct {
				name   string
				eng    *Engine
				args   map[string]any
				action Action
				reason string
			}{
				{name: "missing alias", eng: eng, args: map[string]any{}, action: ActionDeny, reason: patched.missingReason},
				{name: "blank alias", eng: eng, args: map[string]any{alias: "   "}, action: ActionDeny, reason: patched.missingReason},
				{name: "empty allowlist", eng: emptyEng, args: map[string]any{alias: sample.admitted}, action: ActionDeny, reason: patched.emptyReason},
				{name: "non-admitted slot", eng: eng, args: map[string]any{alias: sample.violating}, action: ActionDeny, reason: patched.violationReason},
				{name: "admitted slot", eng: eng, args: map[string]any{alias: sample.admitted}, action: ActionAllow},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					got := evalRunTool(t, tc.eng, tc.args)
					if got.Action != tc.action {
						t.Fatalf("got %s (%s), want %s", got.Action, got.Reason, tc.action)
					}
					if tc.action == ActionDeny && got.Reason != tc.reason {
						t.Fatalf("got reason %q, want %q", got.Reason, tc.reason)
					}
				})
			}
		})
	}
}

func TestMandateRuleTableEntriesAreFailClosed(t *testing.T) {
	for ruleType, entry := range mandateRules {
		t.Run(ruleType, func(t *testing.T) {
			rule := entry
			sample, ok := mandateSamples[ruleType]
			if !ok {
				t.Fatalf("no sample for mandate rule type %q", ruleType)
			}
			if len(rule.aliases) == 0 {
				t.Fatalf("%s declares no alias", ruleType)
			}
			alias := rule.aliases[0]

			eng := loadMandateEngine(t, ruleType, sample.patterns)
			emptyEng := loadMandateEngine(t, ruleType, []string{})

			cases := []struct {
				name   string
				eng    *Engine
				args   map[string]any
				action Action
				reason string
			}{
				{name: "empty allowlist", eng: emptyEng, args: map[string]any{alias: sample.admitted}, action: ActionDeny, reason: rule.emptyReason},
				{name: "missing alias", eng: eng, args: map[string]any{}, action: ActionDeny, reason: rule.missingReason},
				{name: "blank alias", eng: eng, args: map[string]any{alias: "   "}, action: ActionDeny, reason: rule.missingReason},
				{name: "non-string alias", eng: eng, args: map[string]any{alias: 123}, action: ActionDeny, reason: rule.missingReason},
				{name: "violating slot", eng: eng, args: map[string]any{alias: sample.violating}, action: ActionDeny, reason: rule.violationReason},
				{name: "admitted slot", eng: eng, args: map[string]any{alias: sample.admitted}, action: ActionAllow},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					got := evalRunTool(t, tc.eng, tc.args)
					if got.Action != tc.action {
						t.Fatalf("got %s (%s), want %s", got.Action, got.Reason, tc.action)
					}
					if tc.action == ActionDeny && got.Reason != tc.reason {
						t.Fatalf("got reason %q, want %q", got.Reason, tc.reason)
					}
				})
			}
		})
	}

	if len(mandateRules) != 2 {
		t.Fatalf("mandateRules has %d entries, want 2", len(mandateRules))
	}
	if _, ok := mandateRules["allow_recipient"]; !ok {
		t.Fatal("mandateRules missing allow_recipient")
	}
	if _, ok := mandateRules["allow_working_directory"]; !ok {
		t.Fatal("mandateRules missing allow_working_directory")
	}
	var exact, glob int
	for _, entry := range mandateRules {
		switch entry.admitKind {
		case "exact":
			exact++
		case "glob":
			glob++
		}
	}
	if exact != 1 || glob != 1 {
		t.Fatalf("admitKind: exact=%d glob=%d, want one exact and one glob", exact, glob)
	}
}

func loadMandateEngine(t *testing.T, ruleType string, patterns []string) *Engine {
	t.Helper()
	block := "[]"
	if len(patterns) > 0 {
		lines := make([]string, len(patterns))
		for i, p := range patterns {
			lines[i] = fmt.Sprintf("              - %q", p)
		}
		block = "\n" + strings.Join(lines, "\n")
	}
	yaml := fmt.Sprintf(`
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "run_tool"
        allowed: true
        rules:
          - type: %s
            patterns: %s
`, ruleType, block)
	p, err := Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return NewEngine(p)
}

func evalRunTool(t *testing.T, eng *Engine, args map[string]any) Decision {
	t.Helper()
	data, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal arguments: %v", err)
	}
	return eng.Evaluate("workspace", mcp.ToolsCallRequest{
		Name:      "run_tool",
		Arguments: data,
	})
}
