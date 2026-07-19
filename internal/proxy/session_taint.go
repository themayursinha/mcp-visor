package proxy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

type egressTaintDecision struct {
	decision policy.Decision
	control  policy.EgressControlRule
	taint    SessionTaint
}

func (p *Proxy) markMatchingTaints(serverName string, callReq mcp.ToolsCallRequest, args map[string]any, risk policy.RiskLevel, pol *policy.Policy) {
	if pol == nil {
		return
	}
	for _, rule := range pol.Taints {
		matched, sourceValue := taintSourceMatches(rule, serverName, callReq.Name, args)
		if !matched {
			continue
		}

		reason := fmt.Sprintf("taint rule '%s': %s matched %s", rule.Name, callReq.Name, sourceValue)
		taint := SessionTaint{
			Name:         rule.Name,
			SourceServer: serverName,
			SourceTool:   callReq.Name,
			SourceValue:  sourceValue,
			PolicyRule:   rule.Name,
			Reason:       reason,
		}
		if !p.session.AddTaint(taint) {
			continue
		}

		p.logAudit(audit.Event{
			EventType:     audit.EventSessionTainted,
			SessionID:     p.session.ID,
			AgentID:       p.cfg.ClientID,
			Server:        serverName,
			Tool:          callReq.Name,
			Arguments:     args,
			Decision:      string(policy.ActionAllow),
			Reason:        reason,
			RiskLevel:     string(risk),
			SessionTaints: p.session.TaintNames(),
			TaintSource:   serverName + ":" + callReq.Name,
			TaintReason:   reason,
			PolicyRule:    rule.Name,
		})
		p.logger.Warn("session tainted",
			"session", p.session.ID,
			"taint", rule.Name,
			"source", serverName+":"+callReq.Name,
			"reason", reason,
		)
	}
}

func (p *Proxy) evaluateEgressControls(serverName string, callReq mcp.ToolsCallRequest) (egressTaintDecision, bool) {
	pol := p.engine.Policy()
	for _, control := range pol.EgressControls {
		if control.WhenTainted == "" || !p.session.HasTaint(control.WhenTainted) {
			continue
		}
		if !matchesAnyNamePattern(control.SinkTools, callReq.Name) {
			continue
		}
		if len(control.SinkServers) > 0 && !matchesAnyNamePattern(control.SinkServers, serverName) {
			continue
		}
		taint, _ := p.session.GetTaint(control.WhenTainted)
		reason := control.Reason
		if reason == "" {
			reason = fmt.Sprintf("egress control '%s': session tainted with '%s' from %s:%s", control.Name, taint.Name, taint.SourceServer, taint.SourceTool)
		}
		return egressTaintDecision{
			decision: policy.Decision{Action: control.Action, Reason: reason},
			control:  control,
			taint:    taint,
		}, true
	}
	return egressTaintDecision{}, false
}

func taintSourceMatches(rule policy.TaintRule, serverName, toolName string, args map[string]any) (bool, string) {
	if len(rule.SourceServers) > 0 && !matchesAnyNamePattern(rule.SourceServers, serverName) {
		return false, ""
	}
	if !matchesAnyNamePattern(rule.SourceTools, toolName) {
		return false, ""
	}
	if len(rule.SourcePatterns) == 0 {
		return true, toolName
	}
	for _, value := range collectStringValues(args) {
		if matchesAnyValuePattern(rule.SourcePatterns, value) {
			return true, value
		}
	}
	return false, ""
}

func matchesAnyNamePattern(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if matchesNamePattern(pattern, value) {
			return true
		}
	}
	return false
}

func matchesNamePattern(pattern, value string) bool {
	if pattern == "" {
		return false
	}
	if pattern == "*" || strings.EqualFold(pattern, value) {
		return true
	}
	re := "(?i)^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	matched, _ := regexp.MatchString(re, value)
	return matched
}

func matchesAnyValuePattern(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if matchesValuePattern(pattern, value) {
			return true
		}
	}
	return false
}

func matchesValuePattern(pattern, value string) bool {
	if pattern == "" {
		return false
	}
	if pattern == value || strings.EqualFold(pattern, value) {
		return true
	}
	if strings.Contains(pattern, "**") {
		re := regexp.QuoteMeta(pattern)
		re = strings.ReplaceAll(re, `\*\*`, `.*`)
		re = strings.ReplaceAll(re, `\*`, `[^/]*`)
		matched, _ := regexp.MatchString("(?i)^"+re+"$", value)
		return matched
	}
	matched, err := filepath.Match(pattern, value)
	if err == nil && matched {
		return true
	}
	matched, err = filepath.Match(strings.ToLower(pattern), strings.ToLower(value))
	return err == nil && matched
}

func collectStringValues(value any) []string {
	var out []string
	collectStringValuesInto(value, &out)
	return out
}

func collectStringValuesInto(value any, out *[]string) {
	switch v := value.(type) {
	case nil:
		return
	case string:
		*out = append(*out, v)
	case []byte:
		var decoded any
		if err := json.Unmarshal(v, &decoded); err == nil {
			collectStringValuesInto(decoded, out)
			return
		}
		*out = append(*out, string(v))
	case json.RawMessage:
		var decoded any
		if err := json.Unmarshal(v, &decoded); err == nil {
			collectStringValuesInto(decoded, out)
			return
		}
		*out = append(*out, string(v))
	case map[string]any:
		for _, item := range v {
			collectStringValuesInto(item, out)
		}
	case []any:
		for _, item := range v {
			collectStringValuesInto(item, out)
		}
	}
}
