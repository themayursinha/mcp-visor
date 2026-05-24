package policy

type Action string

const (
	ActionAllow           Action = "allow"
	ActionDeny            Action = "deny"
	ActionRequireApproval Action = "require_approval"
	ActionRedactThenAllow Action = "redact_then_allow"
)

type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
	RiskUnknown  RiskLevel = "unknown"
)

type Policy struct {
	Version        string          `yaml:"version"`
	Description    string          `yaml:"description"`
	DefaultAction  Action          `yaml:"default_action"`
	Settings       Settings        `yaml:"settings"`
	Servers        []Server        `yaml:"servers"`
	ToolChains     []ChainRule     `yaml:"tool_chains"`
	Identities     []Identity      `yaml:"identities"`
	TimeRestrictions []TimeRestriction `yaml:"time_restrictions"`
	Redaction      RedactionConfig `yaml:"redaction"`
}

type Settings struct {
	MaxArgumentSizeBytes int    `yaml:"max_argument_size_bytes"`
	MaxOutputSizeBytes   int    `yaml:"max_output_size_bytes"`
	SessionMaxTools      int    `yaml:"session_max_tools"`
	SessionTimeoutSecs   int    `yaml:"session_timeout_seconds"`
	ApprovalTimeoutSecs  int    `yaml:"approval_timeout_seconds"`
	ChainWindowSize      int    `yaml:"chain_window_size"`
	LogLevel             string `yaml:"log_level"`
}

type Server struct {
	Name                string           `yaml:"name"`
	Transport           string           `yaml:"transport"`
	Allowed             bool             `yaml:"allowed"`
	AllowedDestinations []string         `yaml:"allowed_destinations"`
	DeniedDestinations  []string         `yaml:"denied_destinations"`
	Tools               []ToolRule       `yaml:"tools"`
}

type ToolRule struct {
	Name             string      `yaml:"name"`
	Allowed          bool        `yaml:"allowed"`
	Risk             RiskLevel   `yaml:"risk"`
	ApprovalRequired bool        `yaml:"approval_required"`
	Rules            []ArgRule   `yaml:"rules"`
}

type ArgRule struct {
	Type             string   `yaml:"type"`
	Patterns         []string `yaml:"patterns"`
	Keywords         []string `yaml:"keywords"`
	Bytes            int      `yaml:"bytes"`
	Rows             int      `yaml:"rows"`
	Count            int      `yaml:"count"`
	Domains          []string `yaml:"domains"`
	Repos            []string `yaml:"repos"`
	Days             []string `yaml:"days"`
	Start            string   `yaml:"start"`
	End              string   `yaml:"end"`
	Timezone         string   `yaml:"timezone"`
}

type ChainRule struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Sources     []ChainMatch `yaml:"sources"`
	Sinks       []ChainMatch `yaml:"sinks"`
	Action      Action       `yaml:"action"`
	WithinCalls int          `yaml:"within_calls"`
}

type ChainMatch struct {
	Server      string `yaml:"server"`
	ToolPattern string `yaml:"tool_pattern"`
}

type Identity struct {
	Name          string   `yaml:"name"`
	Description   string   `yaml:"description"`
	AllowedServers []string `yaml:"allowed_servers"`
	AllowedTools  []string `yaml:"allowed_tools"`
}

type TimeRestriction struct {
	Name          string   `yaml:"name"`
	Description   string   `yaml:"description"`
	Servers       []string `yaml:"servers"`
	Tools         []string `yaml:"tools"`
	AllowedHours  []TimeWindow `yaml:"allowed_hours"`
	DeniedDays    []string `yaml:"denied_days"`
	OutsideAction Action   `yaml:"outside_action"`
}

type TimeWindow struct {
	Start    string   `yaml:"start"`
	End      string   `yaml:"end"`
	Timezone string   `yaml:"timezone"`
	Days     []string `yaml:"days"`
}

type RedactionConfig struct {
	Patterns       []RedactionPattern `yaml:"patterns"`
	OutputRedaction bool              `yaml:"output_redaction"`
	OutputPatterns []RedactionPattern `yaml:"output_patterns"`
	SensitiveFiles []string           `yaml:"sensitive_files"`
}

type RedactionPattern struct {
	Name        string `yaml:"name"`
	Regex       string `yaml:"regex"`
	Replacement string `yaml:"replacement"`
}

type Decision struct {
	Action Action
	Reason string
}
