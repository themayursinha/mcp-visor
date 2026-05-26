package policy

import (
	"strings"
	"testing"
	"time"
)

func TestLintResult_ToText(t *testing.T) {
	t.Run("empty result", func(t *testing.T) {
		res := &LintResult{
			Policy:     "test-policy",
			FilePath:   "/tmp/policy.yaml",
			Violations: []LintViolation{},
			Summary:    LintSummary{},
		}
		out := res.ToText()
		if !strings.Contains(out, "No issues found") {
			t.Errorf("expected 'No issues found', got: %s", out)
		}
	})

	t.Run("errors and warnings", func(t *testing.T) {
		res := &LintResult{
			Policy:   "test",
			FilePath: "policy.yaml",
			Violations: []LintViolation{
				{
					Path:     "servers[0].tools[0].rules[0].patterns[0]",
					Type:     ViolationTypeError,
					Severity: SeverityError,
					Field:    "regex",
					Message:  "invalid regex '[invalid'",
				},
				{
					Path:     "servers[0].tools[0].rules[1]",
					Type:     ViolationTypeWarning,
					Severity: SeverityWarning,
					Field:    "type",
					Message:  "unknown rule type 'banana'",
				},
			},
			Summary: LintSummary{Errors: 1, Warnings: 1, Total: 2},
		}
		out := res.ToText()
		if !strings.Contains(out, "[ERROR]") || !strings.Contains(out, "[WARN]") {
			t.Errorf("expected [ERROR] and [WARN] markers, got: %s", out)
		}
		if !strings.Contains(out, "invalid regex") {
			t.Errorf("expected regex error message, got: %s", out)
		}
	})
}

func TestLintResult_ToJSON(t *testing.T) {
	res := &LintResult{
		Policy:   "test",
		FilePath: "/tmp/policy.yaml",
		Violations: []LintViolation{
			{
				Path:     "redaction.patterns[0]",
				Type:     ViolationTypeError,
				Severity: SeverityError,
				Field:    "regex",
				Message:  "invalid regex",
			},
		},
	}
	data, err := res.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if !strings.Contains(string(data), "invalid regex") {
		t.Errorf("expected JSON to contain error message, got: %s", string(data))
	}
	if !strings.Contains(string(data), "errors") {
		t.Errorf("expected JSON to have errors field, got: %s", string(data))
	}
}

func TestLintValidPolicy(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		Description:   "valid test policy",
		DefaultAction: ActionDeny,
		Settings: Settings{
			MaxArgumentSizeBytes: 1048576,
			MaxOutputSizeBytes:   10485760,
			SessionMaxTools:      100,
			SessionTimeoutSecs:   3600,
			ApprovalTimeoutSecs:  300,
			ChainWindowSize:      10,
		},
		Servers: []Server{
			{
				Name:    "filesystem",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name:     "file_read",
						Allowed:  true,
						Risk:     RiskMedium,
						Rules: []ArgRule{
							{Type: "deny_path", Patterns: []string{"**/.env", "**/*.pem"}},
						},
					},
				},
			},
			{
				Name:    "shell",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name:             "shell_exec",
						Allowed:          true,
						Risk:             RiskCritical,
						ApprovalRequired: true,
						Rules: []ArgRule{
							{Type: "deny_command_pattern", Patterns: []string{"rm\\s+-rf"}},
						},
					},
				},
			},
		},
		ToolChains: []ChainRule{
			{
				Name: "prevent_exfil",
				Sources: []ChainMatch{{Server: "*", ToolPattern: "file_read"}},
				Sinks:   []ChainMatch{{Server: "*", ToolPattern: "http_post"}},
				Action:   ActionDeny,
			},
		},
		Identities: []Identity{
			{
				Name:           "dev-agent",
				AllowedServers: []string{"filesystem"},
				AllowedTools:  []string{"filesystem/file_read"},
			},
		},
		TimeRestrictions: []TimeRestriction{
			{
				Name:  "business_hours",
				Tools: []string{"shell_exec"},
				AllowedHours: []TimeWindow{
					{Start: "09:00", End: "17:00", Timezone: "America/Chicago", Days: []string{"monday", "tuesday"}},
				},
				DeniedDays:    []string{"saturday", "sunday"},
				OutsideAction: ActionDeny,
			},
		},
		Redaction: RedactionConfig{
			Patterns: []RedactionPattern{
				{Name: "test", Regex: `sk-[a-zA-Z0-9_-]{20,}`, Replacement: "[REDACTED]"},
			},
		},
	}

	res := Lint(p)
	if res.Summary.Errors > 0 {
		t.Errorf("expected no errors for valid policy, got %d:\n%s", res.Summary.Errors, res.ToText())
	}
}

func TestLintInvalidRegex(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "shell",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name:  "shell_exec",
						Rules: []ArgRule{
							{Type: "deny_command_pattern", Patterns: []string{"[invalid(regex"}},
						},
					},
				},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "invalid regex") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected regex error to be detected, violations: %+v", res.Violations)
	}
}

func TestLintUnknownRuleType(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name: "test_tool",
						Rules: []ArgRule{
							{Type: "unknown_rule_type_xyz"},
						},
					},
				},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityWarning && strings.Contains(v.Message, "unknown rule type") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unknown rule type warning, violations: %+v", res.Violations)
	}
}

func TestLintEmptyRuleType(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name: "test_tool",
						Rules: []ArgRule{
							{Type: ""},
						},
					},
				},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "rule type is empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected empty rule type error, violations: %+v", res.Violations)
	}
}

func TestLintInvalidTimezone(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{{Name: "test"}},
			},
		},
		TimeRestrictions: []TimeRestriction{
			{
				Name:  "bad_timezone",
				Tools: []string{"test_tool"},
				AllowedHours: []TimeWindow{
					{Start: "09:00", End: "17:00", Timezone: "Invalid/NotAZone"},
				},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "invalid IANA timezone") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid timezone error, violations: %+v", res.Violations)
	}
}

func TestLintInvalidTimeFormat(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{{Name: "test"}},
			},
		},
		TimeRestrictions: []TimeRestriction{
			{
				Name:  "bad_time",
				Tools: []string{"test_tool"},
				AllowedHours: []TimeWindow{
					{Start: "9am", End: "5pm", Timezone: "UTC"},
				},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "invalid time format") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid time format error, violations: %+v", res.Violations)
	}
}

func TestLintInvalidDayName(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{{Name: "test"}},
			},
		},
		TimeRestrictions: []TimeRestriction{
			{
				Name:  "bad_day",
				Tools: []string{"test_tool"},
				AllowedHours: []TimeWindow{
					{Days: []string{"monday", "wensday"}},
				},
				DeniedDays: []string{"frriday"},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "invalid day") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid day name error, violations: %+v", res.Violations)
	}
}

func TestLintInvalidIdentityToolFormat(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "filesystem",
				Allowed: true,
				Tools: []ToolRule{{Name: "file_read"}},
			},
		},
		Identities: []Identity{
			{
				Name:          "bad-identity",
				AllowedTools:  []string{"no_slash_at_all"},
				AllowedServers: []string{"filesystem"},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "server/tool") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected tool format error, violations: %+v", res.Violations)
	}
}

func TestLintIdentityReferencesUnknownTool(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "filesystem",
				Allowed: true,
				Tools: []ToolRule{{Name: "file_read"}},
			},
		},
		Identities: []Identity{
			{
				Name:          "bad-identity",
				AllowedTools:  []string{"filesystem/nonexistent_tool"},
				AllowedServers: []string{"filesystem"},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityWarning && strings.Contains(v.Message, "unknown tool") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unknown tool warning, violations: %+v", res.Violations)
	}
}

func TestLintDuplicateIdentityName(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{{Name: "test"}},
			},
		},
		Identities: []Identity{
			{Name: "dup-name"},
			{Name: "dup-name"},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "duplicate identity name") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected duplicate identity error, violations: %+v", res.Violations)
	}
}

func TestLintMaxFileSizeZeroBytes(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name: "file_read",
						Rules: []ArgRule{
							{Type: "max_file_size", Bytes: 0},
						},
					},
				},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "max_file_size") && strings.Contains(v.Message, "bytes > 0") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected max_file_size bytes error, violations: %+v", res.Violations)
	}
}

func TestLintMaxRowsZeroRows(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name: "db_query",
						Rules: []ArgRule{
							{Type: "max_result_rows", Rows: 0},
						},
					},
				},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "max_result_rows") && strings.Contains(v.Message, "rows > 0") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected max_result_rows rows error, violations: %+v", res.Violations)
	}
}

func TestLintInvalidChainAction(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{{Name: "test"}},
			},
		},
		ToolChains: []ChainRule{
			{
				Name:   "bad_action_rule",
				Action: Action("invalid_action"),
				Sources: []ChainMatch{{Server: "*", ToolPattern: "file_read"}},
				Sinks:   []ChainMatch{{Server: "*", ToolPattern: "http_post"}},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "invalid action") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid chain action error, violations: %+v", res.Violations)
	}
}

func TestLintInvalidToolPattern(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{{Name: "test"}},
			},
		},
		ToolChains: []ChainRule{
			{
				Name: "bad_pattern",
				Sources: []ChainMatch{{Server: "*", ToolPattern: "[invalid_regex("}},
				Sinks:   []ChainMatch{{Server: "*", ToolPattern: "http_post"}},
				Action:  ActionDeny,
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "invalid regex") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid tool pattern error, violations: %+v", res.Violations)
	}
}

func TestLintNegativeSettings(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings: Settings{
			MaxArgumentSizeBytes: -1,
			MaxOutputSizeBytes:   -100,
			SessionMaxTools:      -5,
			ApprovalTimeoutSecs:  -10,
			ChainWindowSize:      0,
		},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{{Name: "test"}},
			},
		},
	}

	res := Lint(p)
	errorCount := 0
	for _, v := range res.Violations {
		if v.Severity == SeverityError {
			errorCount++
		}
	}
	if errorCount < 5 {
		t.Errorf("expected at least 5 negative settings errors, got %d: %+v", errorCount, res.Violations)
	}
}

func TestLintEmptyServerName(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{Name: "", Allowed: true, Tools: []ToolRule{{Name: "test_tool"}}},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "server name is empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected empty server name error, violations: %+v", res.Violations)
	}
}

func TestLintEmptyToolName(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test_server",
				Allowed: true,
				Tools: []ToolRule{
					{Name: "", Rules: []ArgRule{}},
				},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "tool name is empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected empty tool name error, violations: %+v", res.Violations)
	}
}

func TestLintRuleWithNoPatterns(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name: "test_tool",
						Rules: []ArgRule{
							{Type: "deny_path", Patterns: []string{}},
						},
					},
				},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityWarning && strings.Contains(v.Message, "has no patterns") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'no patterns' warning, violations: %+v", res.Violations)
	}
}

func TestIsValidAction(t *testing.T) {
	tests := []struct {
		action   Action
		expected bool
	}{
		{ActionAllow, true},
		{ActionDeny, true},
		{ActionRequireApproval, true},
		{ActionRedactThenAllow, true},
		{Action("invalid"), false},
		{Action(""), false},
	}

	for _, tc := range tests {
		result := isValidAction(tc.action)
		if result != tc.expected {
			t.Errorf("isValidAction(%q) = %v, want %v", tc.action, result, tc.expected)
		}
	}
}

func TestIsValidTimeFormat(t *testing.T) {
	valid := []string{"00:00", "23:59", "09:30", "9:00"}
	invalid := []string{"9am", "5pm", "25:00", "23:60", "", "9:00am"}

	for _, s := range valid {
		if !isValidTimeFormat(s) {
			t.Errorf("isValidTimeFormat(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if isValidTimeFormat(s) {
			t.Errorf("isValidTimeFormat(%q) = true, want false", s)
		}
	}
}

func TestIsValidDay(t *testing.T) {
	valid := []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
	invalid := []string{"mondayy", "fri", "someday", ""}

	for _, s := range valid {
		if !isValidDay(s) {
			t.Errorf("isValidDay(%q) = false, want true", s)
		}
		// Also test case-insensitive variants
		if !isValidDay(strings.Title(s)) {
			t.Errorf("isValidDay(%q) = false, want true (case-insensitive)", strings.Title(s))
		}
	}
	for _, s := range invalid {
		if isValidDay(s) {
			t.Errorf("isValidDay(%q) = true, want false", s)
		}
	}
}

func TestSummarize(t *testing.T) {
	res := &LintResult{
		Violations: []LintViolation{
			{Severity: SeverityError},
			{Severity: SeverityError},
			{Severity: SeverityWarning},
			{Severity: SeverityInfo},
			{Severity: SeverityInfo},
			{Severity: SeverityInfo},
		},
	}
	res.Summary = summarize(*res)
	if res.Summary.Errors != 2 {
		t.Errorf("expected 2 errors, got %d", res.Summary.Errors)
	}
	if res.Summary.Warnings != 1 {
		t.Errorf("expected 1 warning, got %d", res.Summary.Warnings)
	}
	if res.Summary.Info != 3 {
		t.Errorf("expected 3 info, got %d", res.Summary.Info)
	}
	if res.Summary.Total != 6 {
		t.Errorf("expected 6 total, got %d", res.Summary.Total)
	}
}

func TestLintRealPolicies(t *testing.T) {
	policyFiles := []string{
		"../../examples/policies/full-approval.yaml",
		"../../examples/policies/business-hours.yaml",
		"../../examples/policies/per-identity.yaml",
		"../../examples/policies/strict-deny.yaml",
		"../../examples/policies/developer-medium.yaml",
		"../../examples/policies/demo-policy.yaml",
		"../../examples/policies/source-repo-policy.yaml",
	}

	for _, f := range policyFiles {
		t.Run(f, func(t *testing.T) {
			pol, err := LoadFile(f)
			if err != nil {
				t.Fatalf("failed to load %s: %v", f, err)
			}
			res := Lint(pol)
			if res.Summary.Errors > 0 {
				t.Errorf("policy %s has %d errors:\n%s", f, res.Summary.Errors, res.ToText())
			}
		})
	}
}

func TestLintRuleMissingKeywords(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name: "shell",
						Rules: []ArgRule{
							{Type: "deny_command_keyword", Keywords: []string{}},
						},
					},
				},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityWarning && strings.Contains(v.Message, "no keywords") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'no keywords' warning, violations: %+v", res.Violations)
	}
}

func TestLintRuleMissingDomains(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name: "email",
						Rules: []ArgRule{
							{Type: "deny_recipient_domain", Domains: []string{}},
						},
					},
				},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityWarning && strings.Contains(v.Message, "has no domains") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'no domains' warning, violations: %+v", res.Violations)
	}
}

func TestLintRuleMissingRepos(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{ChainWindowSize: 10},
		Servers: []Server{
			{
				Name:    "test",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name: "github",
						Rules: []ArgRule{
							{Type: "allowed_repos", Repos: []string{}},
						},
					},
				},
			},
		},
	}

	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityWarning && strings.Contains(v.Message, "has no repos") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'no repos' warning, violations: %+v", res.Violations)
	}
}

func TestLintTime(t *testing.T) {
	_ = time.Now
}

func BenchmarkLintPolicy(b *testing.B) {
	pol := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings: Settings{
			MaxArgumentSizeBytes: 1048576,
			MaxOutputSizeBytes:   10485760,
			SessionMaxTools:      100,
			SessionTimeoutSecs:   3600,
			ApprovalTimeoutSecs:  300,
			ChainWindowSize:      10,
		},
		Servers: []Server{
			{
				Name:    "filesystem",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name:  "file_read",
						Allowed: true,
						Risk:  RiskMedium,
						Rules: []ArgRule{
							{Type: "deny_path", Patterns: []string{"**/.env", "**/*.pem", "**/.ssh/**"}},
							{Type: "allow_path", Patterns: []string{"/home/**", "/tmp/**"}},
							{Type: "max_file_size", Bytes: 10485760},
						},
					},
					{
						Name:  "file_write",
						Allowed: true,
						Risk:  RiskHigh,
						Rules: []ArgRule{
							{Type: "deny_path", Patterns: []string{"/etc/**", "/usr/**", "/bin/**"}},
							{Type: "allow_path", Patterns: []string{"/home/**", "/tmp/**"}},
						},
					},
					{
						Name:              "file_delete",
						Allowed:           true,
						Risk:              RiskCritical,
						ApprovalRequired:  true,
					},
				},
			},
			{
				Name:    "shell",
				Allowed: true,
				Tools: []ToolRule{
					{
						Name:  "shell_exec",
						Allowed: true,
						Risk:  RiskCritical,
						Rules: []ArgRule{
							{Type: "deny_command_pattern", Patterns: []string{"rm\\s+-rf\\s+/", "curl.*\\|.*(bash|sh)"}},
							{Type: "allow_command_pattern", Patterns: []string{"^ls\\s", "^cat\\s", "^echo\\s"}},
						},
					},
				},
			},
			{
				Name:    "github",
				Allowed: true,
				Tools: []ToolRule{
					{Name: "github_create_issue", Allowed: true, Risk: RiskMedium},
					{Name: "github_create_pr", Allowed: true, Risk: RiskMedium, ApprovalRequired: true},
					{Name: "github_read_code", Allowed: true, Risk: RiskLow},
					{Name: "github_merge_pr", Allowed: true, Risk: RiskHigh, ApprovalRequired: true},
				},
			},
		},
		ToolChains: []ChainRule{
			{
				Name: "prevent_exfil",
				Sources: []ChainMatch{{Server: "*", ToolPattern: "file_read"}},
				Sinks:   []ChainMatch{{Server: "*", ToolPattern: "(http_post|slack_send)"}},
				Action:  ActionDeny,
			},
			{
				Name: "read_then_destroy",
				Sources: []ChainMatch{{Server: "*", ToolPattern: ".*_read"}},
				Sinks:   []ChainMatch{{Server: "*", ToolPattern: ".*_delete"}},
				Action:  ActionRequireApproval,
			},
		},
		Identities: []Identity{
			{
				Name:           "dev",
				AllowedServers: []string{"filesystem", "github"},
				AllowedTools:   []string{"filesystem/file_read", "github/github_read_code"},
			},
		},
		TimeRestrictions: []TimeRestriction{
			{
				Name:  "biz_hours",
				Tools: []string{"shell_exec"},
				AllowedHours: []TimeWindow{
					{Start: "09:00", End: "17:00", Timezone: "America/Chicago", Days: []string{"monday", "tuesday", "wednesday", "thursday", "friday"}},
				},
			},
		},
		Redaction: RedactionConfig{
			Patterns: []RedactionPattern{
				{Name: "openai_key", Regex: `sk-[a-zA-Z0-9_-]{20,}`, Replacement: "[REDACTED]"},
				{Name: "gh_token", Regex: `ghp_[a-zA-Z0-9]{36}`, Replacement: "[REDACTED]"},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Lint(pol)
	}
}
