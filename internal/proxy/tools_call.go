package proxy

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/redaction"
)

// toolsCallResponder sends JSON-RPC errors back to the MCP client.
type toolsCallResponder func(id any, message string)

func (p *Proxy) processToolsCall(
	req mcp.Request,
	callReq mcp.ToolsCallRequest,
	raw, originalRaw json.RawMessage,
	serverName string,
	respond toolsCallResponder,
) (json.RawMessage, string) {
	started := time.Now()
	argsMap := extractArgs(callReq.Arguments)
	p.metrics.IncrementProcessed()

	if decision := p.evaluateRuntimeLimits(callReq); decision.Action == policy.ActionDeny {
		respond(req.ID, decision.Reason)
		p.metrics.IncrementDenied()
		p.logDenied(serverName, callReq.Name, nil, decision.Reason, p.engine.GetRiskLevel(serverName, callReq.Name))
		p.observeToolCall("denied", decision.Reason, serverName, callReq.Name, string(p.engine.GetRiskLevel(serverName, callReq.Name)), false, started)
		return raw, "denied"
	}

	redactedArgs, redactionResult := p.redactor.RedactArgs(argsMap)
	if redactionResult.Redacted {
		p.metrics.AddBytesRedacted(int64(len(raw)))
		p.logger.Info("arguments redacted",
			"tool", callReq.Name,
			"fields", redactionResult.RedactedFields,
			"session", p.session.ID,
		)
		// Do not audit here: emit a single terminal decision event after policy
		// evaluation so allow/deny/approval paths stay one-event-per-call.
		rewritten, err := p.rewriteArgs(raw, redactedArgs)
		if err == nil {
			raw = rewritten
		}
	}

	sensitivePath := p.extractPath(callReq)
	if sensitivePath != "" && p.redactor.IsSensitiveFile(sensitivePath) {
		reason := fmt.Sprintf("sensitive file: %s", sensitivePath)
		respond(req.ID, fmt.Sprintf("access to sensitive file denied: %s", sensitivePath))
		p.metrics.IncrementDenied()
		risk := p.engine.GetRiskLevel(serverName, callReq.Name)

		p.logAudit(audit.Event{
			EventType: audit.EventToolDenied,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Arguments: redactedArgs,
			Decision:  string(policy.ActionDeny),
			Reason:    withRedactionNote(reason, redactionResult),
			RiskLevel: string(risk),
		})
		p.logger.Warn("sensitive file denied",
			"tool", callReq.Name,
			"path", sensitivePath,
			"session", p.session.ID,
		)
		p.observeToolCall("denied", reason, serverName, callReq.Name, string(risk), false, started)
		return raw, "denied"
	}

	decision := p.engine.Evaluate(serverName, callReq)
	risk := p.engine.GetRiskLevel(serverName, callReq.Name)
	var chainContext []string
	chainTriggered := false
	var egressContext egressTaintDecision
	egressTriggered := false

	if decision.Action != policy.ActionDeny {
		if egressDecision, matched := p.evaluateEgressControls(serverName, callReq); matched {
			egressTriggered = true
			egressContext = egressDecision
			decision = egressDecision.decision
		}
	}

	if decision.Action != policy.ActionDeny {
		chainDecision, previousCalls := p.checkChain(serverName, callReq, redactedArgs, risk)
		if chainDecision.Action == policy.ActionDeny {
			p.metrics.IncrementDenied()
			p.metrics.IncrementChains()
			respond(req.ID, "chain rule: tool sequence matches dangerous pattern")
			p.observeToolCall("denied", chainDecision.Reason, serverName, callReq.Name, string(risk), true, started)
			return raw, "denied"
		}
		if chainDecision.Action == policy.ActionRequireApproval {
			p.metrics.IncrementChains()
			chainTriggered = true
			decision = chainDecision
			chainContext = previousCalls
		}
	}

	switch decision.Action {
	case policy.ActionDeny:
		p.metrics.IncrementDenied()
		respond(req.ID, decision.Reason)

		deniedEvent := audit.Event{
			EventType: audit.EventToolDenied,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Arguments: redactedArgs,
			Decision:  string(decision.Action),
			Reason:    withRedactionNote(decision.Reason, redactionResult),
			RiskLevel: string(risk),
		}
		if egressTriggered {
			deniedEvent.SessionTaints = p.session.TaintNames()
			deniedEvent.TaintSource = egressContext.taint.SourceServer + ":" + egressContext.taint.SourceTool
			deniedEvent.TaintReason = egressContext.taint.Reason
			deniedEvent.PolicyRule = egressContext.control.Name
		}
		p.logAudit(deniedEvent)
		p.logger.Warn("policy denied",
			"tool", callReq.Name,
			"reason", decision.Reason,
			"session", p.session.ID,
		)
		p.observeToolCall("denied", decision.Reason, serverName, callReq.Name, string(risk), chainTriggered, started)
		return raw, "denied"

	case policy.ActionRequireApproval:
		outcome := p.requestApproval(serverName, callReq, redactedArgs, decision.Reason, risk, originalRaw, chainContext)
		if !outcome.Approved {
			reason := fmt.Sprintf("execution denied: approval not granted (%s)", outcome.Reason)
			respond(req.ID, reason)
			p.metrics.IncrementDenied()
			p.observeToolCall("denied", reason, serverName, callReq.Name, string(risk), chainTriggered, started)
			return raw, "denied"
		}

		allowEvent := audit.Event{
			EventType: audit.EventToolAllowed,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Arguments: redactedArgs,
			Decision:  string(policy.ActionAllow),
			Reason:    "approved by human operator",
			RiskLevel: string(risk),
		}
		p.attachReceiptEvidence(&allowEvent, outcome.Receipt)
		p.logAudit(allowEvent)
		p.markMatchingTaints(serverName, callReq, redactedArgs, risk)
		p.logger.Info("approval granted", "tool", callReq.Name, "session", p.session.ID)
		p.metrics.IncrementApproved()
		p.observeToolCall("approved", "approved by human operator", serverName, callReq.Name, string(risk), chainTriggered, started)
		return raw, "forward"

	case policy.ActionAllow:
		p.metrics.IncrementAllowed()
		p.markMatchingTaints(serverName, callReq, redactedArgs, risk)
		reason := withRedactionNote(decision.Reason, redactionResult)
		p.logAudit(audit.Event{
			EventType: audit.EventToolAllowed,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Arguments: redactedArgs,
			Decision:  string(policy.ActionAllow),
			Reason:    reason,
			RiskLevel: string(risk),
		})
		p.observeToolCall("allowed", reason, serverName, callReq.Name, string(risk), chainTriggered, started)
		return raw, "forward"

	default:
		p.metrics.IncrementAllowed()
		p.markMatchingTaints(serverName, callReq, redactedArgs, risk)
		reason := withRedactionNote(decision.Reason, redactionResult)
		p.logAudit(audit.Event{
			EventType: audit.EventToolAllowed,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Arguments: redactedArgs,
			Decision:  string(policy.ActionAllow),
			Reason:    reason,
			RiskLevel: string(risk),
		})
		p.observeToolCall("allowed", reason, serverName, callReq.Name, string(risk), chainTriggered, started)
		return raw, "forward"
	}
}

func withRedactionNote(reason string, result redaction.Result) string {
	if !result.Redacted || len(result.RedactedFields) == 0 {
		return reason
	}
	note := fmt.Sprintf("redacted fields: %v", result.RedactedFields)
	if reason == "" {
		return note
	}
	return reason + "; " + note
}
