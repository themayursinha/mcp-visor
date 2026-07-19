package policy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/themayursinha/mcp-visor/internal/mcp"
)

type Engine struct {
	mu        sync.RWMutex
	policy    *Policy
	registry  *Registry
	logger    *slog.Logger
	hooks     []ReloadHook
	committer ReloadCommitter

	watcher  *Watcher
	clientID string
}

func NewEngine(p *Policy) *Engine {
	if p == nil {
		p = DefaultPolicy()
	}
	return &Engine{
		policy:   p,
		registry: NewRegistry(p),
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	}
}

func NewEngineWithWatcher(w *Watcher) *Engine {
	pol, reg := w.Current()
	return &Engine{
		policy:   pol,
		registry: reg,
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
		watcher: w,
	}
}

func (e *Engine) SetClientID(id string) {
	e.clientID = id
}

// OnReload registers a hook for successful policy reloads.
// When a watcher is present, hooks attach to the watcher so filesystem
// reloads refresh dependent runtime surfaces (redactor, audit patterns, approval).
// Without a watcher, hooks fire from Engine.Reload.
func (e *Engine) OnReload(hook ReloadHook) {
	if hook == nil {
		return
	}
	if e.watcher != nil {
		e.watcher.OnReload(hook)
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hooks = append(e.hooks, hook)
}

// SetReloadCommitter installs the transaction that publishes an engine policy
// with dependent runtime surfaces. With a watcher, it delegates to the watcher.
func (e *Engine) SetReloadCommitter(committer ReloadCommitter) {
	if e.watcher != nil {
		e.watcher.SetReloadCommitter(committer)
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.committer = committer
}

func (e *Engine) Reload(p *Policy) {
	if p == nil {
		return
	}
	e.mu.RLock()
	committer := e.committer
	hooks := append([]ReloadHook(nil), e.hooks...)
	e.mu.RUnlock()

	var publishOnce sync.Once
	publish := func() {
		publishOnce.Do(func() {
			e.mu.Lock()
			e.policy = p
			e.registry = NewRegistry(p)
			e.mu.Unlock()
		})
	}
	if committer != nil {
		committer(p, publish)
	} else {
		publish()
	}
	for _, hook := range hooks {
		if hook != nil {
			hook(p)
		}
	}
}

func (e *Engine) Close() {
	if e.watcher != nil {
		e.watcher.Close()
	}
}

func (e *Engine) current() (policy *Policy, registry *Registry) {
	if e.watcher != nil {
		return e.watcher.Current()
	}
	return e.policy, e.registry
}

func (e *Engine) Evaluate(serverName string, req mcp.ToolsCallRequest) Decision {
	pol, reg := e.current()
	tool, known := reg.Tool(serverName, req.Name)
	srv, srvKnown := reg.Server(serverName)

	if !srvKnown {
		e.logger.Warn("unknown server", "server", serverName, "tool", req.Name)
		if pol.DefaultAction == ActionDeny {
			return Decision{Action: ActionDeny, Reason: fmt.Sprintf("server '%s' is not registered", serverName)}
		}
	}

	if !known {
		e.logger.Warn("unknown tool", "server", serverName, "tool", req.Name)
		if pol.DefaultAction == ActionDeny {
			return Decision{Action: ActionDeny, Reason: fmt.Sprintf("tool '%s' from server '%s' is not registered", req.Name, serverName)}
		}
	}

	if srvKnown && !srv.Allowed {
		return Decision{Action: ActionDeny, Reason: fmt.Sprintf("server '%s' is denied by policy", serverName)}
	}

	if known && !tool.Allowed {
		return Decision{Action: ActionDeny, Reason: fmt.Sprintf("tool '%s' is explicitly denied", req.Name)}
	}

	if !known && !srvKnown && pol.DefaultAction == ActionDeny {
		return Decision{Action: ActionDeny, Reason: "unknown tool/server; default-deny policy"}
	}

	if known && len(tool.Rules) > 0 {
		args := extractArgs(req.Arguments)
		for _, rule := range tool.Rules {
			decision := e.evaluateRule(rule, args, req.Name)
			if decision.Action != ActionAllow {
				return decision
			}
		}
	}

	if len(pol.Identities) > 0 && e.clientID != "" {
		decision := e.evaluateIdentity(serverName, req.Name, pol)
		if decision.Action != ActionAllow {
			return decision
		}
	}

	if len(pol.TimeRestrictions) > 0 {
		decision := e.evaluateTimeRestriction(serverName, req.Name, pol)
		if decision.Action != ActionAllow {
			return decision
		}
	}

	if known && tool.ApprovalRequired {
		return Decision{Action: ActionRequireApproval, Reason: fmt.Sprintf("tool '%s' requires approval", req.Name)}
	}

	return Decision{Action: ActionAllow, Reason: "allowed by policy"}
}

func (e *Engine) EvaluateChain(serverName string, req mcp.ToolsCallRequest, previousCalls []string) Decision {
	pol, _ := e.current()
	for _, chain := range pol.ToolChains {
		if chain.WithinCalls > 0 && len(previousCalls) > chain.WithinCalls {
			previousCalls = previousCalls[len(previousCalls)-chain.WithinCalls:]
		}

		for _, source := range chain.Sources {
			if e.matchesSource(source, previousCalls) {
				for _, sink := range chain.Sinks {
					if e.matchesSink(sink, serverName, req.Name) {
						return Decision{
							Action: chain.Action,
							Reason: fmt.Sprintf("chain rule '%s': tool sequence matches dangerous pattern", chain.Name),
						}
					}
				}
			}
		}
	}

	return Decision{Action: ActionAllow, Reason: "no chain rule matched"}
}

func (e *Engine) EvaluateApproval(serverName string, req mcp.ToolsCallRequest) bool {
	_, reg := e.current()
	tool, known := reg.Tool(serverName, req.Name)
	if !known {
		return false
	}
	return tool.ApprovalRequired
}

func (e *Engine) GetRiskLevel(serverName, toolName string) RiskLevel {
	_, reg := e.current()
	tool, known := reg.Tool(serverName, toolName)
	if known && tool.Risk != "" {
		return tool.Risk
	}
	return e.inferRisk(toolName)
}

func (e *Engine) evaluateRule(rule ArgRule, args map[string]any, toolName string) Decision {
	switch rule.Type {
	case "deny_path":
		if path, ok := getStringArg(args, "path", "file", "file_path"); ok {
			if matchesAnyPattern(rule.Patterns, path) {
				return Decision{Action: ActionDeny, Reason: "path matches deny pattern"}
			}
		}

	case "allow_path":
		if path, ok := getStringArg(args, "path", "file", "file_path"); ok {
			if !matchesAnyPattern(rule.Patterns, path) {
				return Decision{Action: ActionDeny, Reason: "path does not match any allow pattern"}
			}
		}

	case "deny_command_pattern":
		if cmd, ok := getStringArg(args, "command", "cmd", "exec"); ok {
			for _, pattern := range rule.Patterns {
				if matched, _ := regexp.MatchString("(?i)"+pattern, cmd); matched {
					return Decision{Action: ActionDeny, Reason: fmt.Sprintf("command matches deny pattern: %s", pattern)}
				}
			}
		}

	case "allow_command_pattern":
		if cmd, ok := getStringArg(args, "command", "cmd", "exec"); ok {
			allowed := false
			for _, pattern := range rule.Patterns {
				if matched, _ := regexp.MatchString("(?i)"+pattern, cmd); matched {
					allowed = true
					break
				}
			}
			if !allowed {
				return Decision{Action: ActionDeny, Reason: "command does not match any allow pattern"}
			}
		}

	case "deny_command_keyword":
		if cmd, ok := getStringArg(args, "command", "cmd", "exec"); ok {
			lower := strings.ToLower(cmd)
			for _, kw := range rule.Keywords {
				if strings.Contains(lower, strings.ToLower(kw)) {
					return Decision{Action: ActionDeny, Reason: fmt.Sprintf("command contains denied keyword: %s", kw)}
				}
			}
		}

	case "deny_query_pattern":
		if query, ok := getStringArg(args, "query", "sql", "statement"); ok {
			for _, pattern := range rule.Patterns {
				if matched, _ := regexp.MatchString("(?i)"+pattern, query); matched {
					return Decision{Action: ActionDeny, Reason: fmt.Sprintf("query matches deny pattern: %s", pattern)}
				}
			}
		}

	case "allow_query_pattern":
		if query, ok := getStringArg(args, "query", "sql", "statement"); ok {
			allowed := false
			for _, pattern := range rule.Patterns {
				if matched, _ := regexp.MatchString("(?i)"+pattern, query); matched {
					allowed = true
					break
				}
			}
			if !allowed {
				return Decision{Action: ActionDeny, Reason: "query does not match any allow pattern"}
			}
		}

	case "deny_recipient_domain", "allow_recipient_domain":
		if domain, ok := getStringArg(args, "recipient", "to", "email", "domain"); ok {
			matched, _ := MatchesAnyDomainPattern(rule.Domains, domain)
			if rule.Type == "deny_recipient_domain" && matched {
				return Decision{Action: ActionDeny, Reason: "recipient domain is denied"}
			}
			if rule.Type == "allow_recipient_domain" && !matched {
				return Decision{Action: ActionDeny, Reason: "recipient domain is not in allowlist"}
			}
		}

	case "allowed_repos":
		if repo, ok := getStringArg(args, "repo", "repository", "owner/repo"); ok {
			if !MatchesAnyRepo(rule.Repos, repo) {
				return Decision{Action: ActionDeny, Reason: fmt.Sprintf("repository '%s' is not in allowlist", repo)}
			}
		}

	case "max_file_size":
		if size := getSizeArg(args); size > 0 && rule.Bytes > 0 && size > rule.Bytes {
			return Decision{Action: ActionDeny, Reason: fmt.Sprintf("file size %d exceeds max %d bytes", size, rule.Bytes)}
		}

	case "max_result_rows", "max_export_rows":
		if rows := getRowsArg(args); rows > 0 && rule.Rows > 0 && rows > rule.Rows {
			return Decision{Action: ActionDeny, Reason: fmt.Sprintf("rows %d exceeds max %d", rows, rule.Rows)}
		}

	case "require_approval_always":
		return Decision{Action: ActionRequireApproval, Reason: "approval is required for this tool"}
	}

	return Decision{Action: ActionAllow, Reason: "rule passed"}
}

func (e *Engine) matchesSource(match ChainMatch, previousCalls []string) bool {
	for _, call := range previousCalls {
		parts := strings.SplitN(call, ":", 2)
		if len(parts) != 2 {
			continue
		}
		serverMatch := match.Server == "*" || match.Server == parts[0]
		toolMatch, _ := regexp.MatchString("(?i)^"+match.ToolPattern+"$", parts[1])
		if serverMatch && toolMatch {
			return true
		}
	}
	return false
}

func (e *Engine) matchesSink(match ChainMatch, serverName, toolName string) bool {
	serverMatch := match.Server == "*" || match.Server == serverName
	toolMatch, _ := regexp.MatchString("(?i)^"+match.ToolPattern+"$", toolName)
	return serverMatch && toolMatch
}

func (e *Engine) evaluateIdentity(serverName, toolName string, pol *Policy) Decision {
	identity := e.findIdentity(pol)
	if identity == nil {
		return Decision{Action: ActionDeny, Reason: fmt.Sprintf("client '%s' has no matching identity in policy", e.clientID)}
	}

	serverAllowed := false
	for _, idSrv := range identity.AllowedServers {
		if idSrv == serverName {
			serverAllowed = true
			break
		}
	}
	if !serverAllowed {
		return Decision{Action: ActionDeny, Reason: fmt.Sprintf("server '%s' not allowed for identity '%s'", serverName, identity.Name)}
	}

	toolAllowed := false
	fqTool := serverName + "/" + toolName
	for _, idTool := range identity.AllowedTools {
		if idTool == fqTool {
			toolAllowed = true
			break
		}
	}
	if !toolAllowed {
		return Decision{Action: ActionDeny, Reason: fmt.Sprintf("tool '%s' not allowed for identity '%s'", fqTool, identity.Name)}
	}

	return Decision{Action: ActionAllow, Reason: "allowed by identity policy"}
}

func (e *Engine) findIdentity(pol *Policy) *Identity {
	for i := range pol.Identities {
		if pol.Identities[i].Name == e.clientID {
			return &pol.Identities[i]
		}
	}
	return nil
}

func (e *Engine) evaluateTimeRestriction(serverName, toolName string, pol *Policy) Decision {
	now := time.Now()

	for _, tr := range pol.TimeRestrictions {
		if !matchesServerOrTool(tr.Servers, serverName) {
			continue
		}
		if !matchesAnyTool(tr.Tools, toolName) {
			continue
		}

		if len(tr.DeniedDays) > 0 {
			currentDay := strings.ToLower(now.Weekday().String())
			for _, d := range tr.DeniedDays {
				if strings.ToLower(d) == currentDay {
					return Decision{
						Action: tr.OutsideAction,
						Reason: fmt.Sprintf("time restriction '%s': current day %s is denied", tr.Name, currentDay),
					}
				}
			}
		}

		if len(tr.AllowedHours) > 0 {
			inWindow := false
			for _, tw := range tr.AllowedHours {
				loc := time.Local
				if tw.Timezone != "" {
					if l, err := time.LoadLocation(tw.Timezone); err == nil {
						loc = l
					}
				}
				tNow := now.In(loc)
				currentDay := strings.ToLower(tNow.Weekday().String())

				dayOK := len(tw.Days) == 0
				for _, d := range tw.Days {
					if strings.ToLower(d) == currentDay {
						dayOK = true
						break
					}
				}
				if !dayOK {
					continue
				}

				start, err := time.ParseInLocation("15:04", tw.Start, loc)
				if err != nil {
					continue
				}
				end, err := time.ParseInLocation("15:04", tw.End, loc)
				if err != nil {
					continue
				}
				startTime := time.Date(tNow.Year(), tNow.Month(), tNow.Day(), start.Hour(), start.Minute(), 0, 0, loc)
				endTime := time.Date(tNow.Year(), tNow.Month(), tNow.Day(), end.Hour(), end.Minute(), 0, 0, loc)

				if tNow.After(startTime) && tNow.Before(endTime) {
					inWindow = true
					break
				}
			}
			if !inWindow {
				return Decision{
					Action: tr.OutsideAction,
					Reason: fmt.Sprintf("time restriction '%s': outside allowed hours", tr.Name),
				}
			}
		}
	}

	return Decision{Action: ActionAllow, Reason: "within allowed time"}
}

func matchesServerOrTool(servers []string, serverName string) bool {
	for _, s := range servers {
		if s == serverName {
			return true
		}
	}
	return false
}

func matchesAnyTool(tools []string, toolName string) bool {
	for _, t := range tools {
		if matched, _ := regexp.MatchString("(?i)^"+strings.ReplaceAll(regexp.QuoteMeta(t), `\*`, ".*")+"$", toolName); matched {
			return true
		}
	}
	return false
}

func (e *Engine) inferRisk(toolName string) RiskLevel {
	name := strings.ToLower(toolName)

	criticalKeywords := []string{"delete", "drop", "iam", "shell", "exec", "sudo", "root"}
	for _, kw := range criticalKeywords {
		if strings.Contains(name, kw) {
			return RiskCritical
		}
	}

	highKeywords := []string{"write", "send", "post", "create", "modify", "update", "upload", "database", "query", "secret", "credential", "key", "token"}
	for _, kw := range highKeywords {
		if strings.Contains(name, kw) {
			return RiskHigh
		}
	}

	mediumKeywords := []string{"read", "fetch", "get", "search", "download", "ssh", "connect"}
	for _, kw := range mediumKeywords {
		if strings.Contains(name, kw) {
			return RiskMedium
		}
	}

	return RiskLow
}

func (e *Engine) Registry() *Registry {
	_, reg := e.current()
	return reg
}

func (e *Engine) Policy() *Policy {
	pol, _ := e.current()
	return pol
}

func extractArgs(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil
	}
	return args
}

func getStringArg(args map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if val, ok := args[key]; ok {
			if s, ok := val.(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

func getSizeArg(args map[string]any) int {
	for _, key := range []string{"size", "content_length", "file_size"} {
		if val, ok := args[key]; ok {
			switch v := val.(type) {
			case float64:
				return int(v)
			case int:
				return v
			case int64:
				return int(v)
			}
		}
	}
	return 0
}

func getRowsArg(args map[string]any) int {
	for _, key := range []string{"limit", "rows", "count", "max_results"} {
		if val, ok := args[key]; ok {
			switch v := val.(type) {
			case float64:
				return int(v)
			case int:
				return v
			case int64:
				return int(v)
			}
		}
	}
	return 0
}

func matchesAnyPattern(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if matchesGlob(pattern, value) {
			return true
		}
	}
	return false
}

func matchesGlob(pattern, value string) bool {
	if strings.Contains(pattern, "**") {
		regexStr := globToRegexString(pattern)
		matched, _ := regexp.MatchString(regexStr, value)
		return matched
	}

	match, err := filepath.Match(pattern, value)
	if err == nil && match {
		return true
	}
	match, err = filepath.Match(strings.ToLower(pattern), strings.ToLower(value))
	return err == nil && match
}

func globToRegexString(pattern string) string {
	s := regexp.QuoteMeta(pattern)
	s = strings.ReplaceAll(s, `\*\*`, `.*`)
	s = strings.ReplaceAll(s, `\*`, `[^/]*`)
	return "(?i)^" + s + "$"
}
