package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return Load(data)
}

func Load(data []byte) (*Policy, error) {
	policy := DefaultPolicy()
	if err := yaml.Unmarshal(data, policy); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("validate policy: %w", err)
	}
	return policy, nil
}

func DefaultPolicy() *Policy {
	return &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings: Settings{
			MaxArgumentSizeBytes: 1048576,
			MaxOutputSizeBytes:   10485760,
			SessionMaxTools:      100,
			SessionTimeoutSecs:   3600,
			ApprovalTimeoutSecs:  300,
			ChainWindowSize:      10,
			LogLevel:             "info",
		},
		Redaction: RedactionConfig{
			OutputRedaction: true,
			Patterns:        DefaultRedactionPatterns(),
			OutputPatterns:  DefaultOutputRedactionPatterns(),
			SensitiveFiles: []string{
				"**/.env", "**/.env.*",
				"**/credentials", "**/secrets",
				"**/.aws/credentials", "**/.ssh/**",
				"**/.docker/config.json", "**/kubeconfig",
				"**/.npmrc", "**/*.pem", "**/*.key",
			},
		},
	}
}

func DefaultRedactionPatterns() []RedactionPattern {
	return []RedactionPattern{
		{Name: "openai_api_key", Regex: `sk-[a-zA-Z0-9_-]{20,}`, Replacement: "[REDACTED: OpenAI API Key]"},
		{Name: "github_token", Regex: `ghp_[a-zA-Z0-9]{36}`, Replacement: "[REDACTED: GitHub Token]"},
		{Name: "slack_token", Regex: `xox[baprs]-[a-zA-Z0-9-]+`, Replacement: "[REDACTED: Slack Token]"},
		{Name: "aws_key", Regex: `AKIA[0-9A-Z]{16}`, Replacement: "[REDACTED: AWS Access Key]"},
		{Name: "jwt_token", Regex: `eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`, Replacement: "[REDACTED: JWT]"},
		{Name: "private_key", Regex: `-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`, Replacement: "[REDACTED: Private Key]"},
		{Name: "connection_string", Regex: `(mongodb|postgresql|mysql|redis|jdbc)://[^:]+:[^@]+@[^\s]+`, Replacement: "[REDACTED: Connection String]"},
		{Name: "internal_ip", Regex: `(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`, Replacement: "[REDACTED: Internal IP]"},
	}
}

func DefaultOutputRedactionPatterns() []RedactionPattern {
	return []RedactionPattern{
		{Name: "secrets_in_output", Regex: `(password|secret|token|key|credential)\s*[:=]\s*["']?([^"'\s]+)["']?`, Replacement: "$1=[REDACTED]"},
	}
}

func (p *Policy) Validate() error {
	if p.Version == "" {
		return fmt.Errorf("policy version is required")
	}
	if p.DefaultAction != ActionAllow && p.DefaultAction != ActionDeny {
		return fmt.Errorf("default_action must be 'allow' or 'deny', got '%s'", p.DefaultAction)
	}

	seenServers := make(map[string]bool)
	for i, srv := range p.Servers {
		if srv.Name == "" {
			return fmt.Errorf("server at index %d: name is required", i)
		}
		if seenServers[srv.Name] {
			return fmt.Errorf("duplicate server: %s", srv.Name)
		}
		seenServers[srv.Name] = true

		seenTools := make(map[string]bool)
		for j, tool := range srv.Tools {
			if tool.Name == "" {
				return fmt.Errorf("server %s, tool index %d: name is required", srv.Name, j)
			}
			if seenTools[tool.Name] {
				return fmt.Errorf("server %s: duplicate tool: %s", srv.Name, tool.Name)
			}
			seenTools[tool.Name] = true

			if tool.Risk != "" {
				switch tool.Risk {
				case RiskCritical, RiskHigh, RiskMedium, RiskLow, RiskUnknown:
				default:
					return fmt.Errorf("server %s, tool %s: invalid risk level '%s'", srv.Name, tool.Name, tool.Risk)
				}
			}
		}
	}

	for i, chain := range p.ToolChains {
		if chain.Name == "" {
			return fmt.Errorf("chain rule at index %d: name is required", i)
		}
		if len(chain.Sources) == 0 {
			return fmt.Errorf("chain rule %s: at least one source is required", chain.Name)
		}
		if len(chain.Sinks) == 0 {
			return fmt.Errorf("chain rule %s: at least one sink is required", chain.Name)
		}
	}

	return nil
}

func (p *Policy) SetDefaults() {
	if p.DefaultAction == "" {
		p.DefaultAction = ActionDeny
	}
	if p.Settings.MaxArgumentSizeBytes == 0 {
		p.Settings.MaxArgumentSizeBytes = 1048576
	}
	if p.Settings.MaxOutputSizeBytes == 0 {
		p.Settings.MaxOutputSizeBytes = 10485760
	}
	if p.Settings.SessionMaxTools == 0 {
		p.Settings.SessionMaxTools = 100
	}
	if p.Settings.SessionTimeoutSecs == 0 {
		p.Settings.SessionTimeoutSecs = 3600
	}
	if p.Settings.ApprovalTimeoutSecs == 0 {
		p.Settings.ApprovalTimeoutSecs = 300
	}
	if p.Settings.ChainWindowSize == 0 {
		p.Settings.ChainWindowSize = 10
	}
	if p.Settings.LogLevel == "" {
		p.Settings.LogLevel = "info"
	}
}
