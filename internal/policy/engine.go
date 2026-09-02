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
// with dependent runtime surfaces and reconciles the currently published
// generation before returning. With a watcher, it delegates to the watcher.
// reconcile must not call publish() or Engine/Watcher methods that acquire
// the same mutex this transaction holds.
func (e *Engine) SetReloadCommitter(committer ReloadCommitter, reconcile func(*Policy)) {
	if e.watcher != nil {
		e.watcher.SetReloadCommitter(committer, reconcile)
		return
	}
	e.mu.Lock()
	e.committer = committer
	current := e.policy
	if reconcile != nil {
		reconcile(current)
	}
	e.mu.Unlock()
}

func (e *Engine) Reload(p *Policy) {
	if p == nil {
		return
	}
	var publishOnce sync.Once
	publish := func() {
		publishOnce.Do(func() {
			e.mu.Lock()
			e.policy = p
			e.registry = NewRegistry(p)
			e.mu.Unlock()
		})
	}

	// Hold the lock across the nil-committer publish decision so a concurrent
	// SetReloadCommitter cannot observe a committed generation without the
	// committer installed, so an in-flight reload re-reads a committer
	// registered while LoadFile was running, and so install+reconcile excludes
	// later Engine.Reload publication until reconciliation finishes.
	e.mu.Lock()
	committer := e.committer
	hooks := append([]ReloadHook(nil), e.hooks...)
	if committer == nil {
		e.policy = p
		e.registry = NewRegistry(p)
		e.mu.Unlock()
	} else {
		e.mu.Unlock()
		committer(p, publish)
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

	// Fold every Evaluate stage the same way: deny stops; require_approval is
	// remembered; allow continues; any other action (empty, redact_then_allow)
	// is a fail-closed deny. YAML order and later stages cannot skip a deny
	// or turn an unsupported action into a proxy default-allow.
	var pendingApproval Decision
	if known && len(tool.Rules) > 0 {
		args := extractArgs(req.Arguments)
		for _, rule := range tool.Rules {
			if d, stop := mergeEvalDecision(&pendingApproval, e.evaluateRule(rule, args, req.Name)); stop {
				return d
			}
		}
	}

	if len(pol.Identities) > 0 && e.clientID != "" {
		if d, stop := mergeEvalDecision(&pendingApproval, e.evaluateIdentity(serverName, req.Name, pol)); stop {
			return d
		}
	}

	if len(pol.TimeRestrictions) > 0 {
		if d, stop := mergeEvalDecision(&pendingApproval, e.evaluateTimeRestriction(serverName, req.Name, pol)); stop {
			return d
		}
	}

	if known && tool.ApprovalRequired {
		reqApproval := Decision{Action: ActionRequireApproval, Reason: fmt.Sprintf("tool '%s' requires approval", req.Name)}
		if d, stop := mergeEvalDecision(&pendingApproval, reqApproval); stop {
			return d
		}
	}

	if pendingApproval.Action == ActionRequireApproval {
		return pendingApproval
	}

	return Decision{Action: ActionAllow, Reason: "allowed by policy"}
}

// mergeEvalDecision folds one Evaluate stage into the running result.
// stop is true when the caller must return d immediately.
func mergeEvalDecision(pending *Decision, next Decision) (d Decision, stop bool) {
	switch next.Action {
	case ActionAllow:
		return Decision{}, false
	case ActionDeny:
		return next, true
	case ActionRequireApproval:
		if pending.Action != ActionRequireApproval {
			*pending = next
		}
		return Decision{}, false
	default:
		reason := strings.TrimSpace(next.Reason)
		if reason == "" {
			reason = "policy decision is not allow, deny, or require_approval"
		}
		return Decision{
			Action: ActionDeny,
			Reason: fmt.Sprintf("unsupported policy action %q (%s)", next.Action, reason),
		}, true
	}
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

	case "require_path_literal":
		// PATH-class arguments must remain path literals. Shell grammar in a
		// path slot is PATH→SHELL authority amplification (CVE-2026-18482).
		// Attaching this rule is the implementation attestation; Visor does
		// not inspect the MCP server binary.
		slots, reason := collectPathSlots(args)
		if reason != "" {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		for _, slot := range slots {
			if pathContainsShellGrammar(slot) {
				return Decision{Action: ActionDeny, Reason: reasonPathToShellAmplification}
			}
		}

	case "allow_path_slot":
		// Fail-closed mandate path: a tool allowed to clean /tmp/agent-123
		// must not delete $HOME. Declared PATH/TARGET fields are the effect
		// target; Visor does not expand shell variables inside the MCP server.
		if !recipientAllowlistConfigured(rule.Patterns) {
			return Decision{Action: ActionDeny, Reason: "path slot allowlist is empty"}
		}
		slots, reason := collectEffectPathSlots(args)
		if reason != "" {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		for _, slot := range slots {
			if !matchesAnyPattern(rule.Patterns, slot) {
				return Decision{Action: ActionDeny, Reason: reasonDestructivePathOutsideMandate}
			}
		}

	case "allow_destination":
		// Fail-closed mandate host: a tool allowed to reach docs.internal
		// must not post to evil.example. Declared URL/HOST fields are the
		// effect destination; Visor does not follow redirects or resolve
		// DNS. Every present alias is checked.
		if !recipientAllowlistConfigured(rule.Patterns) {
			return Decision{Action: ActionDeny, Reason: "destination allowlist is empty"}
		}
		slots, reason := collectDestinationSlots(args)
		if reason != "" {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		for _, slot := range slots {
			if !recipientInAllowlist(rule.Patterns, slot) {
				return Decision{Action: ActionDeny, Reason: reasonAuthorityExpandingDestination}
			}
		}

	case "allow_working_directory":
		// Fail-closed mandate cwd: a tool allowed to run a decoder under
		// /workspace/safe must not execute with cwd in an attacker extract
		// dir. Declared CWD fields are the execution environment; Visor
		// does not parse imports or PYTHONPATH. Every present alias is checked.
		if !recipientAllowlistConfigured(rule.Patterns) {
			return Decision{Action: ActionDeny, Reason: "working directory allowlist is empty"}
		}
		slots, reason := collectWorkingDirectorySlots(args)
		if reason != "" {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		for _, slot := range slots {
			if !matchesAnyPattern(rule.Patterns, slot) {
				return Decision{Action: ActionDeny, Reason: reasonUntrustedExecutionEnvironment}
			}
		}

	case "deny_secret":
		// Fail-closed secret slot: a tool allowed to configure a gateway
		// must not carry a replacement credential on the wire. Declared
		// SECRET fields are the custody signal; Visor does not attest the
		// provisioning runtime. Any present alias is denied. Credential
		// validity is not custody.
		slots, reason := collectPresentSecretSlots(args)
		if reason != "" {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		if len(slots) > 0 {
			return Decision{Action: ActionDeny, Reason: reasonUntrustedCredentialCustody}
		}

	case "allow_application":
		// Fail-closed mandate application: a tool allowed to sync
		// staging-orders must not sync production-payments. Declared
		// APPLICATION fields are the control-plane target; Visor does
		// not walk k8s/ServiceAccount graphs. Every present alias is
		// checked. Tool-provider credentials are not caller authority.
		if !recipientAllowlistConfigured(rule.Patterns) {
			return Decision{Action: ActionDeny, Reason: "application allowlist is empty"}
		}
		slots, reason := collectApplicationSlots(args)
		if reason != "" {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		for _, slot := range slots {
			if !recipientInAllowlist(rule.Patterns, slot) {
				return Decision{Action: ActionDeny, Reason: reasonAuthorityExpandingApplication}
			}
		}

	case "allow_skill":
		// Fail-closed mandate skill: a tool allowed to install
		// workspace-lint must not promote attacker-registry. Declared
		// SKILL identity fields are the promotion target; Visor does
		// not parse skill bodies or trajectory provenance. Every
		// present alias is checked. Experience cannot manufacture a
		// new skill name.
		if !recipientAllowlistConfigured(rule.Patterns) {
			return Decision{Action: ActionDeny, Reason: "skill allowlist is empty"}
		}
		slots, reason := collectSkillSlots(args)
		if reason != "" {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		for _, slot := range slots {
			if !recipientInAllowlist(rule.Patterns, slot) {
				return Decision{Action: ActionDeny, Reason: reasonUnauthorizedSkillPromotion}
			}
		}

	case "deny_permission_bypass":
		// Fail-closed permission-bypass slot: a tool allowed to spawn a
		// worker must not disable permission mediation on the child.
		// Declared PERMISSION-bypass fields are the weakening signal;
		// Visor does not compare parent/child obligation graphs.
		// Explicitly-off values are not a bypass. Command strings are
		// not parsed. Nested principals are out of model.
		slots, reason := collectPresentPermissionBypassSlots(args)
		if reason != "" {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		if len(slots) > 0 {
			return Decision{Action: ActionDeny, Reason: reasonPermissionBypassDelegation}
		}

	case "allow_activation":
		// Fail-closed dual-mode registration: a tool allowed to register
		// /usr/bin/node or mcp.internal must not activate /bin/sh or
		// 169.254.169.254. Declared EXECUTABLE and URL fields are the
		// instantiation target; Visor does not spawn processes or fetch
		// URLs. Every present alias in each family is checked. Missing
		// both families denies. Args arrays are out of model.
		if !recipientAllowlistConfigured(rule.Patterns) {
			return Decision{Action: ActionDeny, Reason: "activation allowlist is empty"}
		}
		execs, reason := collectOptionalExecutableSlots(args)
		if reason != "" {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		dests, reason := collectOptionalActivationDestinationSlots(args)
		if reason != "" {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		if len(execs) == 0 && len(dests) == 0 {
			return Decision{Action: ActionDeny, Reason: "activation target is required"}
		}
		for _, slot := range execs {
			if !recipientInAllowlist(rule.Patterns, slot) {
				return Decision{Action: ActionDeny, Reason: reasonConfigActivationSpawn}
			}
		}
		for _, slot := range dests {
			if !recipientInAllowlist(rule.Patterns, slot) {
				return Decision{Action: ActionDeny, Reason: reasonConfigActivationNetwork}
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

	case "allow_recipient":
		// Exact mandate slot: observations may fill this value, they may not
		// enlarge it. Every present destination alias is checked; a mandated
		// mailbox in one key cannot cover an attacker mailbox in another.
		// Domain substring matching is intentionally not reused.
		if !recipientAllowlistConfigured(rule.Patterns) {
			return Decision{Action: ActionDeny, Reason: "recipient allowlist is empty"}
		}
		slots, reason := collectRecipientSlots(args)
		if reason != "" {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		for _, slot := range slots {
			if !recipientInAllowlist(rule.Patterns, slot) {
				return Decision{Action: ActionDeny, Reason: "recipient is not in allowlist"}
			}
		}

	case "allow_resource_owner":
		// Exact mandate principal: a tool that is allowed to act for alice
		// must not cancel bob. Declared owner fields are the ownership
		// signal; Visor does not look up a world model. Every present
		// PRINCIPAL-class alias is checked.
		if !recipientAllowlistConfigured(rule.Patterns) {
			return Decision{Action: ActionDeny, Reason: "resource owner allowlist is empty"}
		}
		slots, reason := collectOwnerSlots(args)
		if reason != "" {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		for _, slot := range slots {
			if !recipientInAllowlist(rule.Patterns, slot) {
				return Decision{Action: ActionDeny, Reason: reasonCrossPrincipalEffect}
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

// recipientSlotKeys are the destination aliases inspected by allow_recipient.
// First-match is not used: every present key that case-insensitively matches
// an alias must be an allowlisted string (Go json struct tags are case-insensitive).
var recipientSlotKeys = []string{"recipient", "to", "email", "cc", "bcc"}

// reasonCrossPrincipalEffect is the deny evidence for allow_resource_owner.
const reasonCrossPrincipalEffect = "cross-principal effect: argument class PRINCIPAL, effect class THIRD_PARTY, authority transition USER->OTHER"

// ownerSlotKeys are PRINCIPAL-class aliases inspected by allow_resource_owner.
// First-match is not used. userId EqualFold-matches userid; user_id is distinct.
var ownerSlotKeys = []string{"owner", "user_id", "userid", "resource_owner", "account_id", "principal"}

// reasonPathToShellAmplification is the deny evidence for require_path_literal.
// Tests assert these field tokens: argument class, effect class, transition.
const reasonPathToShellAmplification = "path-to-shell amplification: argument class PATH, effect class SHELL, authority transition PATH->SHELL"

// pathSlotKeys are PATH-class aliases inspected by require_path_literal.
// First-match is not used: every present key that case-insensitively matches
// an alias must be a path literal. absolutePath (Neo.mjs / CVE-2026-18482)
// EqualFold-matches absolutepath; absolute_path is a distinct alias.
var pathSlotKeys = []string{"path", "file", "file_path", "filepath", "absolute_path", "absolutepath"}

// reasonDestructivePathOutsideMandate is the deny evidence for allow_path_slot.
const reasonDestructivePathOutsideMandate = "destructive path outside mandate: argument class PATH, effect class DESTRUCTIVE, authority transition MANDATE->COLLATERAL"

// effectPathSlotKeys are PATH/TARGET-class aliases inspected by allow_path_slot.
// First-match is not used. target (Fable cleanup) is a distinct alias from path.
// directory EqualFold-matches Directory; dir is distinct.
var effectPathSlotKeys = []string{"path", "file", "file_path", "filepath", "absolute_path", "absolutepath", "target", "dir", "directory"}

// reasonAuthorityExpandingDestination is the deny evidence for allow_destination.
const reasonAuthorityExpandingDestination = "authority-expanding destination: argument class URL, effect class NETWORK, authority transition MANDATE->EGRESS"

// destinationSlotKeys are URL/HOST-class aliases inspected by allow_destination.
// First-match is not used. dest_host EqualFold-matches DestHost; dest is distinct.
var destinationSlotKeys = []string{"url", "uri", "host", "hostname", "endpoint", "dest", "dest_host", "destination", "domain"}

// reasonUntrustedExecutionEnvironment is the deny evidence for allow_working_directory.
const reasonUntrustedExecutionEnvironment = "untrusted execution environment: argument class PATH, effect class EXECUTION, authority transition MANDATE->ENVIRONMENT"

// workingDirectorySlotKeys are CWD-class aliases inspected by allow_working_directory.
// First-match is not used. working_dir EqualFold-matches Working_Dir; workingdir is distinct.
var workingDirectorySlotKeys = []string{"cwd", "working_directory", "working_dir", "workingdir", "workdir", "chdir"}

// reasonUntrustedCredentialCustody is the deny evidence for deny_secret.
const reasonUntrustedCredentialCustody = "untrusted credential custody: argument class SECRET, effect class CREDENTIAL, authority transition MANDATE->CUSTODY"

// secretSlotKeys are SECRET-class aliases inspected by deny_secret.
// First-match is not used. api_key EqualFold-matches Api_Key; apikey is distinct.
var secretSlotKeys = []string{"api_key", "apikey", "access_key", "secret", "password", "credential", "private_key", "token", "new_key"}

// reasonAuthorityExpandingApplication is the deny evidence for allow_application.
const reasonAuthorityExpandingApplication = "authority-expanding application: argument class APPLICATION, effect class CONTROL_PLANE, authority transition MANDATE->CLUSTER"

// applicationSlotKeys are APPLICATION-class aliases inspected by allow_application.
// First-match is not used. app_name EqualFold-matches App_Name; appname is distinct.
// name is the Argo MCP application identifier when this rule is attached.
var applicationSlotKeys = []string{"application", "app", "application_name", "app_name", "applicationname", "appname", "name"}

// reasonUnauthorizedSkillPromotion is the deny evidence for allow_skill.
const reasonUnauthorizedSkillPromotion = "unauthorized skill promotion: argument class SKILL, effect class AUTHORITY, authority transition EXPERIENCE->SKILL"

// skillSlotKeys are SKILL-class identity aliases inspected by allow_skill.
// First-match is not used. skill_name EqualFold-matches Skill_Name; skillname is distinct.
// skill_content / body are not identity aliases; Visor does not parse skill text.
var skillSlotKeys = []string{"skill", "skill_id", "skill_name", "skillname", "skill_key", "skill_slug"}

// reasonPermissionBypassDelegation is the deny evidence for deny_permission_bypass.
const reasonPermissionBypassDelegation = "permission-bypass delegation: argument class PERMISSION, effect class DELEGATION, authority transition PARENT->CHILD"

// permissionBypassSlotKeys are PERMISSION-bypass aliases inspected by deny_permission_bypass.
// First-match is not used. skip_permissions EqualFold-matches Skip_Permissions;
// skippermissions is distinct. permission_mode / flags / args / command are not aliases.
var permissionBypassSlotKeys = []string{
	"skip_permissions", "skip_permission", "skippermissions",
	"dangerously_skip_permissions", "dangerouslyskippermissions",
	"bypass_permissions", "bypasspermissions",
}

// reasonConfigActivationSpawn is the deny evidence for allow_activation
// when an EXECUTABLE-class slot is not the mandate binary.
const reasonConfigActivationSpawn = "unauthorized configuration activation: argument class EXECUTABLE, effect class PROCESS, authority transition CONFIG->SPAWN"

// reasonConfigActivationNetwork is the deny evidence for allow_activation
// when a URL-class slot is not the mandate host.
const reasonConfigActivationNetwork = "unauthorized configuration activation: argument class URL, effect class NETWORK, authority transition CONFIG->EGRESS"

// executableSlotKeys are EXECUTABLE-class aliases inspected by allow_activation.
// First-match is not used. stdio_command EqualFold-matches Stdio_Command;
// stdiocommand is distinct. args / argv / path / transport are not aliases.
var executableSlotKeys = []string{
	"command", "cmd", "exec", "binary", "executable",
	"stdio_command", "stdiocommand", "server_command", "servercommand",
}

// pathShellMetacharacters are ASCII runes that turn a PATH-class argument
// into a SHELL fragment when interpolated into a command. This is not a
// shell parser. Unicode homoglyphs, percent-encoding, and glob-only
// characters are out of scope.
const pathShellMetacharacters = ";|&`$()<>\n\r\x00'\"#"

func isDestinationSlotKey(key string) bool {
	for _, alias := range destinationSlotKeys {
		if strings.EqualFold(key, alias) {
			return true
		}
	}
	return false
}

func destinationHostname(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", false
	}
	// Scheme is only a leading `scheme://` prefix. Indexing for `://`
	// anywhere lets `https:evil.example://docs.internal/x` bind the
	// allowlisted host while WHATWG uses evil.example.
	if i := strings.Index(v, "://"); i >= 0 {
		if i == 0 || !destinationBoringScheme(v[:i]) {
			return "", false
		}
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	// Authority must be a boring host[:port]. Userinfo, backslash,
	// percent-encoding, brackets, and whitespace are unparseable: those
	// are the characters that split WHATWG / net/url / string-surgery
	// hosts. Visor is not a URL parser for a downstream tool.
	if v == "" || strings.ContainsAny(v, "@\\% \t\r\n\x00[]<>\"'`") {
		return "", false
	}
	if i := strings.LastIndex(v, ":"); i >= 0 {
		if strings.Contains(v[:i], ":") {
			return "", false
		}
		port := v[i+1:]
		if !destinationPortDigits(port) {
			return "", false
		}
		v = v[:i]
	}
	v = strings.TrimSuffix(v, ".")
	if !destinationBoringHost(v) {
		return "", false
	}
	return v, true
}

func destinationBoringScheme(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

func destinationPortDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func destinationBoringHost(s string) bool {
	if s == "" || s[0] == '.' || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.':
		default:
			return false
		}
	}
	return !strings.Contains(s, "..")
}

func collectDestinationSlots(args map[string]any) ([]string, string) {
	if args == nil {
		return nil, "destination is required"
	}
	values := make([]string, 0, len(destinationSlotKeys))
	for key, val := range args {
		if !isDestinationSlotKey(key) {
			continue
		}
		s, isString := val.(string)
		if !isString {
			return nil, "destination is required"
		}
		host, ok := destinationHostname(s)
		if !ok {
			return nil, "destination is required"
		}
		values = append(values, host)
	}
	if len(values) == 0 {
		return nil, "destination is required"
	}
	return values, ""
}

func isWorkingDirectorySlotKey(key string) bool {
	for _, alias := range workingDirectorySlotKeys {
		if strings.EqualFold(key, alias) {
			return true
		}
	}
	return false
}

func collectWorkingDirectorySlots(args map[string]any) ([]string, string) {
	if args == nil {
		return nil, "working directory is required"
	}
	values := make([]string, 0, len(workingDirectorySlotKeys))
	for key, val := range args {
		if !isWorkingDirectorySlotKey(key) {
			continue
		}
		s, isString := val.(string)
		if !isString || strings.TrimSpace(s) == "" {
			return nil, "working directory is required"
		}
		values = append(values, s)
	}
	if len(values) == 0 {
		return nil, "working directory is required"
	}
	return values, ""
}

func isSecretSlotKey(key string) bool {
	for _, alias := range secretSlotKeys {
		if strings.EqualFold(key, alias) {
			return true
		}
	}
	return false
}

func collectPresentSecretSlots(args map[string]any) ([]string, string) {
	if args == nil {
		return nil, ""
	}
	values := make([]string, 0, len(secretSlotKeys))
	for key, val := range args {
		if !isSecretSlotKey(key) {
			continue
		}
		s, isString := val.(string)
		if !isString || strings.TrimSpace(s) == "" {
			return nil, "credential is required"
		}
		values = append(values, s)
	}
	return values, ""
}

func isApplicationSlotKey(key string) bool {
	for _, alias := range applicationSlotKeys {
		if strings.EqualFold(key, alias) {
			return true
		}
	}
	return false
}

func collectApplicationSlots(args map[string]any) ([]string, string) {
	if args == nil {
		return nil, "application is required"
	}
	values := make([]string, 0, len(applicationSlotKeys))
	for key, val := range args {
		if !isApplicationSlotKey(key) {
			continue
		}
		s, isString := val.(string)
		if !isString || strings.TrimSpace(s) == "" {
			return nil, "application is required"
		}
		values = append(values, s)
	}
	if len(values) == 0 {
		return nil, "application is required"
	}
	return values, ""
}

func isSkillSlotKey(key string) bool {
	for _, alias := range skillSlotKeys {
		if strings.EqualFold(key, alias) {
			return true
		}
	}
	return false
}

func collectSkillSlots(args map[string]any) ([]string, string) {
	if args == nil {
		return nil, "skill is required"
	}
	values := make([]string, 0, len(skillSlotKeys))
	for key, val := range args {
		if !isSkillSlotKey(key) {
			continue
		}
		s, isString := val.(string)
		if !isString || strings.TrimSpace(s) == "" {
			return nil, "skill is required"
		}
		values = append(values, s)
	}
	if len(values) == 0 {
		return nil, "skill is required"
	}
	return values, ""
}

func isPermissionBypassSlotKey(key string) bool {
	for _, alias := range permissionBypassSlotKeys {
		if strings.EqualFold(key, alias) {
			return true
		}
	}
	return false
}

func collectPresentPermissionBypassSlots(args map[string]any) ([]string, string) {
	if args == nil {
		return nil, ""
	}
	values := make([]string, 0, len(permissionBypassSlotKeys))
	for key, val := range args {
		if !isPermissionBypassSlotKey(key) {
			continue
		}
		weakens, reason := permissionBypassWeakens(val)
		if reason != "" {
			return nil, reason
		}
		if weakens {
			values = append(values, "bypass")
		}
	}
	return values, ""
}

func permissionBypassWeakens(val any) (bool, string) {
	switch v := val.(type) {
	case bool:
		return v, ""
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return false, "permission bypass is required"
		}
		if permissionBypassExplicitlyOff(s) {
			return false, ""
		}
		return true, ""
	default:
		return false, "permission bypass is required"
	}
}

func permissionBypassExplicitlyOff(s string) bool {
	switch strings.ToLower(s) {
	case "false", "0", "no", "off":
		return true
	default:
		return false
	}
}

func isExecutableSlotKey(key string) bool {
	for _, alias := range executableSlotKeys {
		if strings.EqualFold(key, alias) {
			return true
		}
	}
	return false
}

func collectOptionalExecutableSlots(args map[string]any) ([]string, string) {
	if args == nil {
		return nil, ""
	}
	values := make([]string, 0, len(executableSlotKeys))
	found := false
	for key, val := range args {
		if !isExecutableSlotKey(key) {
			continue
		}
		found = true
		s, isString := val.(string)
		if !isString || strings.TrimSpace(s) == "" {
			return nil, "executable is required"
		}
		values = append(values, s)
	}
	if !found {
		return nil, ""
	}
	return values, ""
}

func collectOptionalActivationDestinationSlots(args map[string]any) ([]string, string) {
	if args == nil {
		return nil, ""
	}
	values := make([]string, 0, len(destinationSlotKeys))
	found := false
	for key, val := range args {
		if !isDestinationSlotKey(key) {
			continue
		}
		found = true
		s, isString := val.(string)
		if !isString {
			return nil, "destination is required"
		}
		host, ok := destinationHostname(s)
		if !ok {
			return nil, "destination is required"
		}
		values = append(values, host)
	}
	if !found {
		return nil, ""
	}
	return values, ""
}

func isOwnerSlotKey(key string) bool {
	for _, alias := range ownerSlotKeys {
		if strings.EqualFold(key, alias) {
			return true
		}
	}
	return false
}

func collectOwnerSlots(args map[string]any) ([]string, string) {
	if args == nil {
		return nil, "resource owner is required"
	}
	values := make([]string, 0, len(ownerSlotKeys))
	for key, val := range args {
		if !isOwnerSlotKey(key) {
			continue
		}
		s, isString := val.(string)
		if !isString || strings.TrimSpace(s) == "" {
			return nil, "resource owner is required"
		}
		values = append(values, s)
	}
	if len(values) == 0 {
		return nil, "resource owner is required"
	}
	return values, ""
}

func isRecipientSlotKey(key string) bool {
	for _, alias := range recipientSlotKeys {
		if strings.EqualFold(key, alias) {
			return true
		}
	}
	return false
}

func isEffectPathSlotKey(key string) bool {
	for _, alias := range effectPathSlotKeys {
		if strings.EqualFold(key, alias) {
			return true
		}
	}
	return false
}

func collectEffectPathSlots(args map[string]any) ([]string, string) {
	if args == nil {
		return nil, "effect path is required"
	}
	values := make([]string, 0, len(effectPathSlotKeys))
	for key, val := range args {
		if !isEffectPathSlotKey(key) {
			continue
		}
		s, isString := val.(string)
		if !isString || strings.TrimSpace(s) == "" {
			return nil, "effect path is required"
		}
		values = append(values, s)
	}
	if len(values) == 0 {
		return nil, "effect path is required"
	}
	return values, ""
}

func isPathSlotKey(key string) bool {
	for _, alias := range pathSlotKeys {
		if strings.EqualFold(key, alias) {
			return true
		}
	}
	return false
}

func collectPathSlots(args map[string]any) ([]string, string) {
	if args == nil {
		return nil, "path is required"
	}
	values := make([]string, 0, len(pathSlotKeys))
	for key, val := range args {
		if !isPathSlotKey(key) {
			continue
		}
		s, isString := val.(string)
		if !isString || strings.TrimSpace(s) == "" {
			return nil, "path is required"
		}
		values = append(values, s)
	}
	if len(values) == 0 {
		return nil, "path is required"
	}
	return values, ""
}

func pathContainsShellGrammar(path string) bool {
	return strings.ContainsAny(path, pathShellMetacharacters)
}

func collectRecipientSlots(args map[string]any) ([]string, string) {
	if args == nil {
		return nil, "recipient is required"
	}
	values := make([]string, 0, len(recipientSlotKeys))
	for key, val := range args {
		if !isRecipientSlotKey(key) {
			continue
		}
		s, isString := val.(string)
		if !isString || strings.TrimSpace(s) == "" {
			return nil, "recipient is required"
		}
		values = append(values, s)
	}
	if len(values) == 0 {
		return nil, "recipient is required"
	}
	return values, ""
}

func recipientAllowlistConfigured(patterns []string) bool {
	for _, pattern := range patterns {
		if strings.TrimSpace(pattern) != "" {
			return true
		}
	}
	return false
}

func recipientInAllowlist(patterns []string, recipient string) bool {
	got := strings.TrimSpace(recipient)
	if got == "" {
		return false
	}
	for _, pattern := range patterns {
		if strings.EqualFold(strings.TrimSpace(pattern), got) {
			return true
		}
	}
	return false
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
