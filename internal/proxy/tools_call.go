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

	// Hold a shared barrier with applyPolicyRuntime so a single call cannot
	// redact under the old redactor and evaluate against a newly published policy.
	p.runtimeMu.RLock()
	held := true
	release := func() {
		if held {
			p.runtimeMu.RUnlock()
			held = false
		}
	}
	defer release()
	redactor := p.redactor

	// Server identity attestation is the first tools/call gate. It runs
	// before runtime limits, redaction, argument policy, taint, chains,
	// approval, or relay so poisoned MCP metadata can never reach
	// argument-dependent authorization without an artifact proof.
	if verdict := p.evaluateServerIdentity(p.engine.Policy(), serverName); verdict.configured && !verdict.matched {
		reason := "server identity attestation failed: " + verdict.reason
		respond(req.ID, reason)
		p.metrics.IncrementDenied()
		attested := false
		risk := p.engine.GetRiskLevel(serverName, callReq.Name)
		identityDeniedEvent := audit.Event{
			EventType:              audit.EventToolDenied,
			SessionID:              p.session.ID,
			AgentID:                p.cfg.ClientID,
			Server:                 serverName,
			Tool:                   callReq.Name,
			Decision:               string(policy.ActionDeny),
			Reason:                 reason,
			RiskLevel:              string(risk),
			ServerIdentityKind:     verdict.kind,
			ServerIdentityExpected: verdict.expected,
			ServerIdentityResolved: verdict.resolved,
			ServerAttested:         &attested,
			ServerClaimedName:      p.serverClaimedName,
			ServerClaimedVersion:   p.serverClaimedVersion,
		}
		p.audit.Log(identityDeniedEvent)
		release()
		p.forwardAudit(identityDeniedEvent)
		p.logger.Warn("server identity attestation failed",
			"tool", callReq.Name,
			"server", serverName,
			"reason", verdict.reason,
			"session", p.session.ID,
		)
		p.observeToolCall("denied", reason, serverName, callReq.Name, string(risk), false, started)
		return raw, "denied"
	}

	if decision := p.evaluateRuntimeLimits(callReq); decision.Action == policy.ActionDeny {
		respond(req.ID, decision.Reason)
		p.metrics.IncrementDenied()
		rtDeniedEvent := audit.Event{
			EventType: audit.EventToolDenied,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Decision:  string(policy.ActionDeny),
			Reason:    decision.Reason,
			RiskLevel: string(p.engine.GetRiskLevel(serverName, callReq.Name)),
		}
		p.attachServerIdentity(&rtDeniedEvent, p.engine.Policy(), serverName)
		p.audit.Log(rtDeniedEvent)
		release()
		p.forwardAudit(rtDeniedEvent)
		p.observeToolCall("denied", decision.Reason, serverName, callReq.Name, string(p.engine.GetRiskLevel(serverName, callReq.Name)), false, started)
		return raw, "denied"
	}

	redactedArgs, redactionResult := redactor.RedactArgs(argsMap)
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
	if sensitivePath != "" && redactor.IsSensitiveFile(sensitivePath) {
		reason := fmt.Sprintf("sensitive file: %s", sensitivePath)
		respond(req.ID, fmt.Sprintf("access to sensitive file denied: %s", sensitivePath))
		p.metrics.IncrementDenied()
		risk := p.engine.GetRiskLevel(serverName, callReq.Name)

		sensitiveDeniedEvent := audit.Event{
			EventType: audit.EventToolDenied,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Arguments: redactedArgs,
			Decision:  string(policy.ActionDeny),
			Reason:    withRedactionNote(reason, redactionResult),
			RiskLevel: string(risk),
		}
		p.attachServerIdentity(&sensitiveDeniedEvent, p.engine.Policy(), serverName)
		p.audit.Log(sensitiveDeniedEvent)
		release()
		p.forwardAudit(sensitiveDeniedEvent)
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

			chainDeniedEvent := audit.Event{
				EventType:    audit.EventToolDenied,
				SessionID:    p.session.ID,
				AgentID:      p.cfg.ClientID,
				Server:       serverName,
				Tool:         callReq.Name,
				Arguments:    redactedArgs,
				Decision:     string(policy.ActionDeny),
				Reason:       withRedactionNote(chainDecision.Reason, redactionResult),
				RiskLevel:    string(risk),
				ChainContext: previousCalls,
			}
			p.attachServerIdentity(&chainDeniedEvent, p.engine.Policy(), serverName)
			p.audit.Log(chainDeniedEvent)
			release()
			p.forwardAudit(chainDeniedEvent)
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
		p.attachServerIdentity(&deniedEvent, p.engine.Policy(), serverName)
		p.audit.Log(deniedEvent)
		release()
		p.forwardAudit(deniedEvent)
		p.logger.Warn("policy denied",
			"tool", callReq.Name,
			"reason", decision.Reason,
			"session", p.session.ID,
		)
		p.observeToolCall("denied", decision.Reason, serverName, callReq.Name, string(risk), chainTriggered, started)
		return raw, "denied"

	case policy.ActionRequireApproval:
		// Pin evidence, receipt metadata, and approval timeout while the same
		// runtime snapshot used for evaluation is still protected. Release only
		// before the blocking approval wait so reloads are not stalled.
		snapshot := p.runtimeSnapshotLocked()
		evidence := p.buildApprovalEvidence(originalRaw, redactedArgs, chainContext, snapshot.policy)
		approvalEvent := approvalRequiredEvent(p, serverName, callReq, redactedArgs, withRedactionNote(decision.Reason, redactionResult), risk, chainContext, evidence)
		// Write the JSONL ledger record while holding runtimeMu to
		// preserve audit ordering with respect to policy reloads.
		p.audit.Log(approvalEvent)
		// Release barrier before the blocking wait and before SIEM
		// forwarding so slow SIEM/webhook sinks cannot stall reloads.
		release()
		p.forwardAudit(approvalEvent)
		outcome := p.requestApproval(serverName, callReq, redactedArgs, decision.Reason, risk, originalRaw, chainContext, snapshot, evidence, redactionResult)
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
			Reason:    withRedactionNote("approved by human operator", redactionResult),
			RiskLevel: string(risk),
		}
		p.attachServerIdentity(&allowEvent, snapshot.policy, serverName)
		p.attachReceiptEvidence(&allowEvent, outcome.Receipt)
		p.logAudit(allowEvent)
		p.markMatchingTaints(serverName, callReq, redactedArgs, risk, snapshot.policy)
		p.logger.Info("approval granted", "tool", callReq.Name, "session", p.session.ID)
		p.metrics.IncrementApproved()
		p.observeToolCall("approved", "approved by human operator", serverName, callReq.Name, string(risk), chainTriggered, started)
		return raw, "forward"

	case policy.ActionAllow:
		p.metrics.IncrementAllowed()
		p.markMatchingTaints(serverName, callReq, redactedArgs, risk, p.engine.Policy())
		reason := withRedactionNote(decision.Reason, redactionResult)
		allowEvent := audit.Event{
			EventType: audit.EventToolAllowed,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Arguments: redactedArgs,
			Decision:  string(policy.ActionAllow),
			Reason:    reason,
			RiskLevel: string(risk),
		}
		p.attachServerIdentity(&allowEvent, p.engine.Policy(), serverName)
		p.audit.Log(allowEvent)
		release()
		p.forwardAudit(allowEvent)
		p.observeToolCall("allowed", reason, serverName, callReq.Name, string(risk), chainTriggered, started)
		return raw, "forward"

	default:
		p.metrics.IncrementAllowed()
		p.markMatchingTaints(serverName, callReq, redactedArgs, risk, p.engine.Policy())
		reason := withRedactionNote(decision.Reason, redactionResult)
		defaultAllowEvent := audit.Event{
			EventType: audit.EventToolAllowed,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Arguments: redactedArgs,
			Decision:  string(policy.ActionAllow),
			Reason:    reason,
			RiskLevel: string(risk),
		}
		p.attachServerIdentity(&defaultAllowEvent, p.engine.Policy(), serverName)
		p.audit.Log(defaultAllowEvent)
		release()
		p.forwardAudit(defaultAllowEvent)
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

// serverIdentityVerdict reports the attestation result for the current call.
// configured=false means the logical server has no attestation pin and the
// legacy pipeline runs unchanged. matched=true means the resolved stdio
// executable digest equals the current policy expectation.
type serverIdentityVerdict struct {
	configured bool
	matched    bool
	kind       string
	expected   string
	resolved   string
	reason     string
}

// evaluateServerIdentity compares the immutable resolved stdio executable
// identity with the attestation expected by the CURRENT policy snapshot. It
// is called while runtimeMu.RLock is held so a hot reload can never pair the
// gate with a stale expectation.
func (p *Proxy) evaluateServerIdentity(pol *policy.Policy, serverName string) serverIdentityVerdict {
	srv := findServerByName(pol, serverName)
	if srv == nil || srv.Attestation == nil {
		return serverIdentityVerdict{}
	}
	v := serverIdentityVerdict{
		configured: true,
		kind:       srv.Attestation.Kind,
		expected:   srv.Attestation.Digest,
	}
	if !p.identityResolved {
		v.reason = "configured stdio identity could not be resolved"
		return v
	}
	v.resolved = p.resolvedIdentity.Digest
	if p.resolvedIdentity.Digest != srv.Attestation.Digest {
		v.reason = "resolved executable digest does not match policy expectation"
		return v
	}
	v.matched = true
	return v
}

// attachServerIdentity records attestation evidence on a terminal allow/deny
// event for a call that passed the identity gate. Policies without an
// attestation omit all identity fields so legacy events never claim a
// verdict.
func (p *Proxy) attachServerIdentity(event *audit.Event, pol *policy.Policy, serverName string) {
	srv := findServerByName(pol, serverName)
	if srv == nil || srv.Attestation == nil {
		return
	}
	event.ServerIdentityKind = srv.Attestation.Kind
	event.ServerIdentityExpected = srv.Attestation.Digest
	matched := p.identityResolved && p.resolvedIdentity.Digest == srv.Attestation.Digest
	event.ServerAttested = &matched
	if p.identityResolved {
		event.ServerIdentityResolved = p.resolvedIdentity.Digest
	}
	event.ServerClaimedName = p.serverClaimedName
	event.ServerClaimedVersion = p.serverClaimedVersion
}

func findServerByName(pol *policy.Policy, name string) *policy.Server {
	for i := range pol.Servers {
		if pol.Servers[i].Name == name {
			return &pol.Servers[i]
		}
	}
	return nil
}
