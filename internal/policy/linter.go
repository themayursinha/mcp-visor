package policy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func Lint(p *Policy) LintResult {
	var res LintResult
	res.Policy = p.Description
	res.FilePath = p.Version

	knownRuleTypes := map[string]bool{
		"deny_path": true, "allow_path": true,
		"deny_command_pattern_composite": true,
		"deny_command_pattern": true, "allow_command_pattern": true,
		"deny_command_keyword": true,
		"deny_query_pattern": true, "allow_query_pattern": true,
		"deny_recipient_domain": true, "allow_recipient_domain": true,
		"allowed_repos": true,
		"max_file_size": true,
		"max_result_rows": true, "max_export_rows": true,
		"require_approval_always": true,
	}

	for i, srv := range p.Servers {
		path := fmt.Sprintf("servers[%d]", i)
		lv := LintViolation{
			Path:  path,
			Type:  ViolationTypeInfo,
			Field: "name",
		}
		switch srv.Name {
		case "":
			lv.Message = "server name is empty"
			lv.Severity = SeverityError
			res.Violations = append(res.Violations, lv)
		default:
			lv.Message = fmt.Sprintf("server '%s'", srv.Name)
			lv.Severity = SeverityInfo
			lv.Type = ViolationTypeServer
			res.Violations = append(res.Violations, lv)
		}

		for j, tool := range srv.Tools {
			tp := fmt.Sprintf("%s.tools[%d]", path, j)
			if tool.Name == "" {
				res.Violations = append(res.Violations, LintViolation{
					Path:     tp,
					Type:     ViolationTypeError,
					Field:    "name",
					Severity: SeverityError,
					Message:  "tool name is empty",
				})
			}

			for k, rule := range tool.Rules {
				rp := fmt.Sprintf("%s.tools[%q].rules[%d]", path, tool.Name, k)
				res.checkRule(rp, rule, knownRuleTypes)
			}
		}
	}

	for i, chain := range p.ToolChains {
		path := fmt.Sprintf("tool_chains[%d]", i)
		if chain.Name == "" {
			res.Violations = append(res.Violations, LintViolation{
				Path: path, Type: ViolationTypeError, Field: "name",
				Severity: SeverityError, Message: "chain rule name is empty",
			})
		} else {
			res.Violations = append(res.Violations, LintViolation{
				Path: path, Type: ViolationTypeChain, Field: "name",
				Severity: SeverityInfo, Message: fmt.Sprintf("chain '%s'", chain.Name),
			})
		}

		if chain.Action != "" && !isValidAction(chain.Action) {
			res.Violations = append(res.Violations, LintViolation{
				Path: fmt.Sprintf("%s.action", path), Type: ViolationTypeError,
				Severity: SeverityError, Field: "action",
				Message: fmt.Sprintf("invalid action '%s' (must be allow/deny/require_approval)", chain.Action),
			})
		}

		for si, src := range chain.Sources {
			sp := fmt.Sprintf("%s.sources[%d].tool_pattern", path, si)
			res.checkRegex(sp, src.ToolPattern, "tool_pattern")
		}

		for si, snk := range chain.Sinks {
			sp := fmt.Sprintf("%s.sinks[%d].tool_pattern", path, si)
			res.checkRegex(sp, snk.ToolPattern, "tool_pattern")
		}
	}

	seenIdentities := make(map[string]bool)
	knownServers := make(map[string]bool)
	knownTools := make(map[string]map[string]bool)
	for _, srv := range p.Servers {
		if srv.Name == "" {
			continue
		}
		knownServers[srv.Name] = true
		knownTools[srv.Name] = make(map[string]bool)
		for _, tool := range srv.Tools {
			if tool.Name != "" {
				knownTools[srv.Name][tool.Name] = true
			}
		}
	}

	for i, id := range p.Identities {
		path := fmt.Sprintf("identities[%d]", i)
		if id.Name == "" {
			res.Violations = append(res.Violations, LintViolation{
				Path: path, Type: ViolationTypeError, Field: "name",
				Severity: SeverityError, Message: "identity name is empty",
			})
		} else {
			if seenIdentities[id.Name] {
				res.Violations = append(res.Violations, LintViolation{
					Path: path, Type: ViolationTypeError, Field: "name",
					Severity: SeverityError,
					Message: fmt.Sprintf("duplicate identity name: %s", id.Name),
				})
			}
			seenIdentities[id.Name] = true

			for _, srvName := range id.AllowedServers {
				if srvName != "" && !knownServers[srvName] {
					res.Violations = append(res.Violations, LintViolation{
						Path: fmt.Sprintf("%s.allowed_servers", path), Type: ViolationTypeWarning,
						Severity: SeverityWarning, Field: "allowed_servers",
						Message: fmt.Sprintf("identity '%s' references unknown server: %s", id.Name, srvName),
					})
				}
			}

			for ti, toolFQ := range id.AllowedTools {
				if !strings.Contains(toolFQ, "/") {
					res.Violations = append(res.Violations, LintViolation{
						Path: fmt.Sprintf("%s.allowed_tools[%d]", path, ti), Type: ViolationTypeError,
						Severity: SeverityError, Field: "allowed_tools",
						Message: fmt.Sprintf("identity tool must be 'server/tool' format, got: %s", toolFQ),
					})
					continue
				}
				parts := strings.SplitN(toolFQ, "/", 2)
				srvName := parts[0]
				toolName := parts[1]

				if !knownServers[srvName] {
					res.Violations = append(res.Violations, LintViolation{
						Path: fmt.Sprintf("%s.allowed_tools[%d]", path, ti), Type: ViolationTypeWarning,
						Severity: SeverityWarning, Field: "allowed_tools",
						Message: fmt.Sprintf("identity '%s' references unknown server '%s' in tool '%s'", id.Name, srvName, toolName),
					})
				} else if _, ok := knownTools[srvName]; !ok {
					// server known but tools map not populated
				} else if _, ok := knownTools[srvName][toolName]; !ok {
					res.Violations = append(res.Violations, LintViolation{
						Path: fmt.Sprintf("%s.allowed_tools[%d]", path, ti), Type: ViolationTypeWarning,
						Severity: SeverityWarning, Field: "allowed_tools",
						Message: fmt.Sprintf("identity '%s' references unknown tool '%s' on server '%s'", id.Name, toolName, srvName),
					})
				}
			}
		}
	}

	for i, tr := range p.TimeRestrictions {
		path := fmt.Sprintf("time_restrictions[%d]", i)
		if tr.Name == "" {
			res.Violations = append(res.Violations, LintViolation{
				Path: path, Type: ViolationTypeError, Field: "name",
				Severity: SeverityError, Message: "time_restriction name is empty",
			})
		}

		for ti, tool := range tr.Tools {
			res.checkGlob(path, fmt.Sprintf("tools[%d]", ti), tool, "tools glob")
		}

		for wi, win := range tr.AllowedHours {
			wp := fmt.Sprintf("%s.allowed_hours[%d]", path, wi)

			if !isValidTimeFormat(win.Start) {
				res.Violations = append(res.Violations, LintViolation{
					Path: fmt.Sprintf("%s.start", wp), Type: ViolationTypeError, Field: "start",
					Severity: SeverityError,
					Message: fmt.Sprintf("invalid time format '%s' (expected HH:MM)", win.Start),
				})
			}
			if !isValidTimeFormat(win.End) {
				res.Violations = append(res.Violations, LintViolation{
					Path: fmt.Sprintf("%s.end", wp), Type: ViolationTypeError, Field: "end",
					Severity: SeverityError,
					Message: fmt.Sprintf("invalid time format '%s' (expected HH:MM)", win.End),
				})
			}

			if win.Timezone != "" {
				if _, err := time.LoadLocation(win.Timezone); err != nil {
					res.Violations = append(res.Violations, LintViolation{
						Path: fmt.Sprintf("%s.timezone", wp), Type: ViolationTypeError, Field: "timezone",
						Severity: SeverityError,
						Message: fmt.Sprintf("invalid IANA timezone '%s': %v", win.Timezone, err),
					})
				}
			}

			for di, day := range win.Days {
				if !isValidDay(day) {
					res.Violations = append(res.Violations, LintViolation{
						Path: fmt.Sprintf("%s.days[%d]", wp, di), Type: ViolationTypeError,
						Severity: SeverityError, Field: "days",
						Message: fmt.Sprintf("invalid day '%s' (expected monday-sunday)", day),
					})
				}
			}
		}

		for di, day := range tr.DeniedDays {
			if !isValidDay(day) {
				res.Violations = append(res.Violations, LintViolation{
					Path: fmt.Sprintf("%s.denied_days[%d]", path, di), Type: ViolationTypeError,
					Severity: SeverityError, Field: "denied_days",
					Message: fmt.Sprintf("invalid day '%s' (expected monday-sunday)", day),
				})
			}
		}

		if tr.OutsideAction != "" && !isValidAction(tr.OutsideAction) {
			res.Violations = append(res.Violations, LintViolation{
				Path: fmt.Sprintf("%s.outside_action", path), Type: ViolationTypeError, Field: "outside_action",
				Severity: SeverityError,
				Message: fmt.Sprintf("invalid outside_action '%s'", tr.OutsideAction),
			})
		}
	}

	for i, pat := range p.Redaction.Patterns {
		res.checkRegex(fmt.Sprintf("redaction.patterns[%d]", i), pat.Regex, "regex")
	}
	for i, pat := range p.Redaction.OutputPatterns {
		res.checkRegex(fmt.Sprintf("redaction.output_patterns[%d]", i), pat.Regex, "regex")
	}
	for i, f := range p.Redaction.SensitiveFiles {
		res.checkGlob("redaction", fmt.Sprintf("sensitive_files[%d]", i), f, "sensitive_files glob")
	}

	if p.Settings.MaxArgumentSizeBytes < 0 {
		res.Violations = append(res.Violations, LintViolation{
			Path: "settings.max_argument_size_bytes", Type: ViolationTypeError, Field: "max_argument_size_bytes",
			Severity: SeverityError, Message: "max_argument_size_bytes must be non-negative",
		})
	}
	if p.Settings.MaxOutputSizeBytes < 0 {
		res.Violations = append(res.Violations, LintViolation{
			Path: "settings.max_output_size_bytes", Type: ViolationTypeError, Field: "max_output_size_bytes",
			Severity: SeverityError, Message: "max_output_size_bytes must be non-negative",
		})
	}
	if p.Settings.SessionMaxTools < 0 {
		res.Violations = append(res.Violations, LintViolation{
			Path: "settings.session_max_tools", Type: ViolationTypeError, Field: "session_max_tools",
			Severity: SeverityError, Message: "session_max_tools must be non-negative",
		})
	}
	if p.Settings.ApprovalTimeoutSecs < 0 {
		res.Violations = append(res.Violations, LintViolation{
			Path: "settings.approval_timeout_seconds", Type: ViolationTypeError, Field: "approval_timeout_seconds",
			Severity: SeverityError, Message: "approval_timeout_seconds must be non-negative",
		})
	}
	if p.Settings.ChainWindowSize < 1 {
		res.Violations = append(res.Violations, LintViolation{
			Path: "settings.chain_window_size", Type: ViolationTypeError, Field: "chain_window_size",
			Severity: SeverityError, Message: "chain_window_size must be at least 1",
		})
	}

	sortViolations(res.Violations)
	res.computeSummary()
	return res
}

func (res *LintResult) checkRule(path string, rule ArgRule, knownTypes map[string]bool) {
	if rule.Type == "" {
		res.Violations = append(res.Violations, LintViolation{
			Path: path, Type: ViolationTypeError, Field: "type",
			Severity: SeverityError, Message: "rule type is empty",
		})
		return
	}

	if !knownTypes[rule.Type] {
		res.Violations = append(res.Violations, LintViolation{
			Path: path, Type: ViolationTypeWarning, Field: "type",
			Severity: SeverityWarning,
			Message: fmt.Sprintf("unknown rule type '%s' (will never match)", rule.Type),
		})
	}

	if rule.Type == "deny_path" || rule.Type == "allow_path" {
		if len(rule.Patterns) == 0 {
			res.Violations = append(res.Violations, LintViolation{
				Path: path, Type: ViolationTypeWarning, Field: "patterns",
				Severity: SeverityWarning,
				Message: fmt.Sprintf("rule type '%s' has no patterns", rule.Type),
			})
		}
		for pi, pat := range rule.Patterns {
 pp := fmt.Sprintf("%s.patterns[%d]", path, pi)
			res.checkGlob(path, pp, pat, "path pattern")
		}
	}

	if rule.Type == "deny_command_pattern" || rule.Type == "allow_command_pattern" ||
		rule.Type == "deny_query_pattern" || rule.Type == "allow_query_pattern" {
		if len(rule.Patterns) == 0 {
			res.Violations = append(res.Violations, LintViolation{
				Path: path, Type: ViolationTypeWarning, Field: "patterns",
				Severity: SeverityWarning,
				Message: fmt.Sprintf("rule type '%s' has no patterns", rule.Type),
			})
		}
		for pi := range rule.Patterns {
 pp := fmt.Sprintf("%s.patterns[%d]", path, pi)
			res.checkRegex(pp, rule.Patterns[pi], "pattern")
		}
	}

	if rule.Type == "deny_command_keyword" {
		if len(rule.Keywords) == 0 {
			res.Violations = append(res.Violations, LintViolation{
				Path: path, Type: ViolationTypeWarning, Field: "keywords",
				Severity: SeverityWarning,
				Message: "'deny_command_keyword' rule has no keywords",
			})
		}
	}

	if rule.Type == "deny_recipient_domain" || rule.Type == "allow_recipient_domain" {
		if len(rule.Domains) == 0 {
			res.Violations = append(res.Violations, LintViolation{
				Path: path, Type: ViolationTypeWarning, Field: "domains",
				Severity: SeverityWarning,
				Message: fmt.Sprintf("rule type '%s' has no domains", rule.Type),
			})
		}
	}

	if rule.Type == "allowed_repos" {
		if len(rule.Repos) == 0 {
			res.Violations = append(res.Violations, LintViolation{
				Path: path, Type: ViolationTypeWarning, Field: "repos",
				Severity: SeverityWarning,
				Message: "'allowed_repos' rule has no repos",
			})
		}
	}

	if rule.Type == "max_file_size" && rule.Bytes <= 0 {
		res.Violations = append(res.Violations, LintViolation{
			Path: path, Type: ViolationTypeError, Field: "bytes",
			Severity: SeverityError,
			Message: "'max_file_size' rule requires bytes > 0",
		})
	}

	if (rule.Type == "max_result_rows" || rule.Type == "max_export_rows") && rule.Rows <= 0 {
		res.Violations = append(res.Violations, LintViolation{
			Path: path, Type: ViolationTypeError, Field: "rows",
			Severity: SeverityError,
			Message: fmt.Sprintf("'%s' rule requires rows > 0", rule.Type),
		})
	}
}

func (res *LintResult) checkRegex(path, pattern, field string) {
	if pattern == "" {
		return
	}
	_, err := regexp.Compile(pattern)
	if err != nil {
		res.Violations = append(res.Violations, LintViolation{
			Path: path, Type: ViolationTypeError, Field: field,
			Severity: SeverityError,
			Message: fmt.Sprintf("invalid regex '%s': %v", pattern, err),
		})
	}
}

func (res *LintResult) checkGlob(path, field, pattern, label string) {
	_ = path
	if pattern == "" {
		return
	}
	err := globValidation(pattern)
	if err != nil {
		res.Violations = append(res.Violations, LintViolation{
			Path:     field,
			Type:     ViolationTypeWarning,
			Field:    label,
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("suspicious glob pattern '%s': %v", pattern, err),
		})
	}
}

func isValidAction(a Action) bool {
	switch a {
	case ActionAllow, ActionDeny, ActionRequireApproval, ActionRedactThenAllow:
		return true
	}
	return false
}

func globValidation(pattern string) error {
	// Check for obviously broken glob patterns
	if pattern == "" {
		return nil
	}
	stack := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '[':
			// Check for unclosed bracket or bad character classes
			if i+1 < len(pattern) && pattern[i+1] == '!' {
				// negation, skip past it
				i++
				continue
			}
			stack++
		case ']':
			if stack == 0 && i > 0 {
				return fmt.Errorf("unmatched ']' in glob pattern")
			}
			stack--
		}
	}
	if stack > 0 {
		return fmt.Errorf("unclosed '[ ... ]' in glob pattern")
	}
	// Validate with filepath.Match
	if _, err := filepath.Match(pattern, "test-placeholder"); err != nil {
		return err
	}
	return nil
}

func isValidTimeFormat(t string) bool {
	_, err := time.Parse("15:04", t)
	return err == nil
}

func isValidDay(s string) bool {
	switch strings.ToLower(s) {
	case "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday":
		return true
	}
	return false
}

func sortViolations(violations []LintViolation) {
	bySeverity := make(map[Severity]int)
	bySeverity[SeverityError] = 0
	bySeverity[SeverityWarning] = 1
	bySeverity[SeverityInfo] = 2

	for i := range violations {
		for j := i + 1; j < len(violations); j++ {
			if bySeverity[violations[j].Severity] < bySeverity[violations[i].Severity] {
				violations[i], violations[j] = violations[j], violations[i]
			}
		}
	}
}

func summarize(res LintResult) LintSummary {
	var s LintSummary
	for _, v := range res.Violations {
		switch v.Severity {
		case SeverityError:
			s.Errors++
		case SeverityWarning:
			s.Warnings++
		case SeverityInfo:
			s.Info++
		}
	}
	s.Total = len(res.Violations)
	return s
}

func (res *LintResult) computeSummary() {
	res.Summary = summarize(*res)
}

type LintResult struct {
	Policy     string          `json:"policy,omitempty"`
	FilePath   string          `json:"file,omitempty"`
	Violations []LintViolation `json:"violations"`
	Summary    LintSummary     `json:"summary"`
}

type LintViolation struct {
	Path     string          `json:"path"`
	Type     ViolationType   `json:"type"`
	Severity Severity        `json:"severity"`
	Field    string          `json:"field,omitempty"`
	Message  string          `json:"message"`
}

type ViolationType string

const (
	ViolationTypeError   ViolationType = "error"
	ViolationTypeWarning ViolationType = "warning"
	ViolationTypeInfo    ViolationType = "info"
	ViolationTypeServer  ViolationType = "server"
	ViolationTypeChain   ViolationType = "chain"
)

type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

type LintSummary struct {
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

func ParseTimeFormat(format string) (time.Time, error) {
	return time.Parse("15:04", format)
}

const (
	FieldType           = "type"
	FieldPatterns       = "patterns"
	FieldBytes          = "bytes"
	FieldRows           = "rows"
	FieldKeywords       = "keywords"
	FieldDomains        = "domains"
	FieldRepos          = "repos"
	FieldTimezone       = "timezone"
	FieldStart          = "start"
	FieldEnd            = "end"
	FieldDays           = "days"
	FieldDeniedDays     = "denied_days"
	FieldOutsideAction  = "outside_action"
	FieldAction         = "action"
	FieldName           = "name"
	FieldAllowedServers = "allowed_servers"
	FieldAllowedTools   = "allowed_tools"
	FieldMaxArgs        = "max_argument_size_bytes"
	FieldMaxOutput      = "max_output_size_bytes"
	FieldSessionMaxTools = "session_max_tools"
	FieldApprovalTimeout = "approval_timeout_seconds"
	FieldChainWindowSize = "chain_window_size"
	FieldSensitiveFiles = "sensitive_files"
)

func (r *LintResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (r *LintResult) ToText() string {
	var sb strings.Builder
	if r.Policy != "" {
		fmt.Fprintf(&sb, "Policy: %s\n", r.Policy)
	}
	if r.FilePath != "" {
		fmt.Fprintf(&sb, "File: %s\n", r.FilePath)
	}
	if r.Summary.Total == 0 {
		sb.WriteString("No issues found.\n")
		return sb.String()
	}

	if r.Summary.Errors > 0 {
		fmt.Fprintf(&sb, "ERRORS: %d  WARNINGS: %d  INFO: %d\n\n",
			r.Summary.Errors, r.Summary.Warnings, r.Summary.Info)
	} else {
		fmt.Fprintf(&sb, "Warnings: %d  Info: %d\n\n",
			r.Summary.Warnings, r.Summary.Info)
	}

	for _, v := range r.Violations {
		prefix := "[INFO]  "
		switch v.Severity {
		case SeverityError:
			prefix = "[ERROR] "
		case SeverityWarning:
			prefix = "[WARN]  "
		}
		fmt.Fprintf(&sb, "%s%s\n", prefix, v.Message)
		fmt.Fprintf(&sb, "        path=%s  field=%s\n", v.Path, v.Field)
	}
	return sb.String()
}

type LintConfig struct {
	Strict     bool
	NoInfo     bool
	NoWarnings bool
	JSONOutput bool
}
