package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/capability"
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
	// Capture the FULL runtime snapshot (policy, redactor, approval, and the
	// immutable server identity evidence) ONCE while the barrier is held.
	// Every terminal allow/deny/approval event for this call copies identity
	// evidence from this same snapshot; nothing after the identity gate may
	// recompute it from mutable live proxy state or from the filesystem.
	snapshot := p.runtimeSnapshotLocked(serverName)
	redactor := snapshot.redactor

	// Server identity attestation is the first tools/call gate. It runs
	// before runtime limits, redaction, argument policy, taint, chains,
	// approval, or relay so poisoned MCP metadata can never reach
	// argument-dependent authorization without an artifact proof. The verdict
	// is derived from the snapshot evidence: a configured pin that the
	// captured launch identity does not satisfy (or that was never captured
	// because the proxy started unattested) fails closed and requires a
	// server restart. A reload can never retroactively attest an
	// already-running process.
	identity := snapshot.identity
	if identity.configured && !identity.attested {
		reason := "server identity attestation failed: " + identity.reason
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
			ServerIdentityKind:     identity.kind,
			ServerIdentityExpected: identity.expected,
			ServerIdentityResolved: identity.resolved,
			ServerAttested:         &attested,
			ServerClaimedName:      identity.claimedName,
			ServerClaimedVersion:   identity.claimedVersion,
		}
		_ = p.audit.Log(identityDeniedEvent)
		release()
		p.forwardAudit(identityDeniedEvent)
		p.logger.Warn("server identity attestation failed",
			"tool", callReq.Name,
			"server", serverName,
			"reason", identity.reason,
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
		p.attachServerIdentity(&rtDeniedEvent, snapshot.identity)
		_ = p.audit.Log(rtDeniedEvent)
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
		p.attachServerIdentity(&sensitiveDeniedEvent, snapshot.identity)
		_ = p.audit.Log(sensitiveDeniedEvent)
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
			p.attachServerIdentity(&chainDeniedEvent, snapshot.identity)
			_ = p.audit.Log(chainDeniedEvent)
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

	// Capability accounting adapter (opt-in). With the evaluator disabled
	// (nil = no-op default) this block is skipped entirely: zero behavioral
	// delta. When opted in, the redacted observation of this call is reduced
	// to a hash-linked receipt BEFORE the policy switch. The evaluator is
	// ACCOUNTING, not a second allow gate: an ALLOW receipt falls through to
	// the existing decision unchanged; a PAUSE_REQUIRE_NEW_PROOF receipt or
	// an evaluator error routes to the EXISTING approval gate (pause-to-
	// approval) so an operator can supply fresh proof, and fails closed
	// (denies) only when approval is unavailable or rejected. Never a silent
	// allow and never a hard deny that skips the approval gate.
	capPauseReason := ""
	var capPauseReceipt *capability.PauseReceipt
	if p.capEval != nil {
		step := capability.Step{
			SessionID: p.session.ID,
			Tool:      callReq.Name,
			Args:      stringArgs(redactedArgs),
			Path:      pathArgFromRedacted(redactedArgs),
			DestIP:    destIPFromArgs(redactedArgs),
			DestHost:  destHostFromArgs(redactedArgs),
			Declared:  capabilityDeclaredAuthority(snapshot.policy, serverName),
		}
		p.capEvalMu.Lock()
		p.capStepID++
		step.StepID = p.capStepID
		receipt, err := p.capEval.Eval(context.Background(), step, p.capLastHash)
		if err != nil {
			stepID := step.StepID
			prevHash := p.capLastHash
			p.capEvalMu.Unlock()
			// Evaluator error: build the pause-to-proof artifact and route to
			// the approval gate (pause-to-approval, fail closed on approval
			// unavailable/rejected). Do not deny inline.
			if pr, err2 := capability.NewPauseReceipt(p.session.ID, stepID, prevHash, err); err2 == nil {
				capPauseReceipt = pr
			}
			capPauseReason = "capability boundary: PAUSE_REQUIRE_NEW_PROOF (evaluator error)"
		} else {
			p.capLastHash = receipt.Hash
			p.capEvalMu.Unlock()
			if receipt.Decision == capability.DecisionPauseRequireProof {
				// Boundary signal not attributable to the declared envelope (E5):
				// route to the approval gate so an operator can supply fresh proof.
				// Fail closed when approval is unavailable or rejected. Never deny
				// inline and never silently allow.
				capPauseReason = "capability boundary: PAUSE_REQUIRE_NEW_PROOF (effect outside declared envelope)"
			}
		}
		// Route the pause through the existing approval gate: set decision to
		// ActionRequireApproval and fall through to the switch below. The
		// approval case owns evidence, the audit event, the blocking operator
		// wait, fail-closed denial on unavailable/rejected approval, and the
		// allow/forward path. Do NOT release here — the approval case owns the
		// barrier release.
		//
		// Guard: the capability adapter is ACCOUNTING and may only upgrade a
		// non-deny decision to pause-to-approval. A terminal policy/chain deny
		// is the strongest fail-closed signal and must never be downgraded
		// into an approvable request.
		if capPauseReason != "" && decision.Action != policy.ActionDeny {
			decision = policy.Decision{Action: policy.ActionRequireApproval, Reason: capPauseReason}
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
		p.attachServerIdentity(&deniedEvent, snapshot.identity)
		_ = p.audit.Log(deniedEvent)
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
		// The runtime snapshot was captured at the top of this call while
		// runtimeMu.RLock was held and remains authoritative: the barrier is
		// held until just before the blocking approval wait, so reloads
		// cannot change policy, redactor, or identity evidence underneath it.
		// Evidence, receipt metadata, and approval timeout stay pinned to the
		// SAME snapshot used for evaluation and the identity gate.
		evidence := p.buildApprovalEvidence(originalRaw, redactedArgs, chainContext, snapshot.policy)
		approvalEvent := approvalRequiredEvent(p, serverName, callReq, redactedArgs, withRedactionNote(decision.Reason, redactionResult), risk, chainContext, evidence)
		// Persist the capability pause receipt (if any) durably on the
		// approval-required event so the pause-to-proof artifact is never lost
		// (P2): it carries the stable error_code and the hash-linked receipt
		// for downstream audit, dedup, and alerting. The receipt is the
		// error-to-pause artifact the contract requires.
		if capPauseReceipt != nil {
			if data, err := json.Marshal(capPauseReceipt); err == nil {
				approvalEvent.ApprovalReceiptHash = sha256Hex(data)
				var recMap map[string]any
				if err := json.Unmarshal(data, &recMap); err == nil {
					approvalEvent.ApprovalReceipt = recMap
				}
			}
		}
		// Write the JSONL ledger record while holding runtimeMu to
		// preserve audit ordering with respect to policy reloads.
		_ = p.audit.Log(approvalEvent)
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
		p.attachServerIdentity(&allowEvent, snapshot.identity)
		p.attachReceiptEvidence(&allowEvent, outcome.Receipt)
		// Durable commit before any relay: the runtime barrier is already
		// released (approval wait happened above), so a failure here only
		// denies; it does not touch chain/taint/metric state.
		if err := p.audit.CommitAuthorization(allowEvent); err != nil {
			p.denyCommitFailure(req, respond, serverName, callReq.Name, risk, chainTriggered, started)
			return raw, "denied"
		}
		p.markMatchingTaints(serverName, callReq, redactedArgs, risk, snapshot.policy)
		p.logger.Info("approval granted", "tool", callReq.Name, "session", p.session.ID)
		p.metrics.IncrementApproved()
		p.forwardAudit(allowEvent)
		p.observeToolCall("approved", "approved by human operator", serverName, callReq.Name, string(risk), chainTriggered, started)
		return raw, "forward"

	case policy.ActionAllow:
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
		p.attachServerIdentity(&allowEvent, snapshot.identity)
		if err := p.audit.CommitAuthorization(allowEvent); err != nil {
			release()
			p.denyCommitFailure(req, respond, serverName, callReq.Name, risk, chainTriggered, started)
			return raw, "denied"
		}
		p.markMatchingTaints(serverName, callReq, redactedArgs, risk, snapshot.policy)
		p.metrics.IncrementAllowed()
		release()
		p.forwardAudit(allowEvent)
		p.observeToolCall("allowed", reason, serverName, callReq.Name, string(risk), chainTriggered, started)
		return raw, "forward"

	default:
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
		p.attachServerIdentity(&defaultAllowEvent, snapshot.identity)
		if err := p.audit.CommitAuthorization(defaultAllowEvent); err != nil {
			release()
			p.denyCommitFailure(req, respond, serverName, callReq.Name, risk, chainTriggered, started)
			return raw, "denied"
		}
		p.markMatchingTaints(serverName, callReq, redactedArgs, risk, snapshot.policy)
		p.metrics.IncrementAllowed()
		release()
		p.forwardAudit(defaultAllowEvent)
		p.observeToolCall("allowed", reason, serverName, callReq.Name, string(risk), chainTriggered, started)
		return raw, "forward"
	}
}

// denyCommitFailure responds to a durable authorization commit failure and
// records the denied metric/observation without touching chain, taint, or
// allowed/approved state. Callers must release the runtime barrier if held.
func (p *Proxy) denyCommitFailure(req mcp.Request, respond toolsCallResponder, serverName, toolName string, risk policy.RiskLevel, chainTriggered bool, started time.Time) {
	reason := "execution denied: durable authorization audit commit failed"
	respond(req.ID, reason)
	p.metrics.IncrementDenied()
	p.observeToolCall("denied", reason, serverName, toolName, string(risk), chainTriggered, started)
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

// identityEvidence derives the immutable attestation evidence for the
// supplied policy snapshot and logical server using ONLY the identity
// captured at proxy construction for the launched stdio child. It never
// resolves the current filesystem artifact: attestation is restart-bound, so
// a reload that introduces or changes a pin cannot re-attest an
// already-running process. configured=false means the snapshot policy has no
// pin for this logical server and the legacy pipeline runs unchanged.
// attested=true means the captured launch identity satisfies the snapshot
// pin. It is computed while the runtime snapshot is authoritative
// (runtimeSnapshotLocked), and terminal audit helpers copy the result.
func (p *Proxy) identityEvidence(pol *policy.Policy, serverName string) serverIdentityEvidence {
	srv := findServerByName(pol, serverName)
	if srv == nil || srv.Attestation == nil {
		return serverIdentityEvidence{}
	}
	ev := serverIdentityEvidence{
		configured:     true,
		kind:           srv.Attestation.Kind,
		expected:       srv.Attestation.Digest,
		claimedName:    p.serverClaimedName,
		claimedVersion: p.serverClaimedVersion,
	}
	if !p.identityResolved {
		ev.reason = "configured stdio identity was not captured for this server session; server restart is required to satisfy attestation"
		return ev
	}
	if !p.attestationShapeMatches(srv.Attestation) {
		ev.reason = "attestation resolution shape changed after launch; server restart is required to satisfy the new pin"
		return ev
	}
	ev.resolved = p.resolvedIdentity.Digest
	if p.resolvedIdentity.Digest != srv.Attestation.Digest {
		ev.reason = "attestation expectation differs from the launched server identity; server restart is required to satisfy the new pin"
		return ev
	}
	ev.attested = true
	return ev
}

// attachServerIdentity copies the immutable attestation evidence captured
// with the runtime snapshot onto a terminal allow/deny event. Evidence with
// configured=false (no pin in the snapshot policy) omits all identity fields
// so legacy events never claim a verdict. Callers must pass the SAME evidence
// that passed the identity gate; this function never reads live proxy state
// and never re-resolves identity from disk.
func (p *Proxy) attachServerIdentity(event *audit.Event, evidence serverIdentityEvidence) {
	if !evidence.configured {
		return
	}
	event.ServerIdentityKind = evidence.kind
	event.ServerIdentityExpected = evidence.expected
	attested := evidence.attested
	event.ServerAttested = &attested
	if evidence.resolved != "" {
		event.ServerIdentityResolved = evidence.resolved
	}
	event.ServerClaimedName = evidence.claimedName
	event.ServerClaimedVersion = evidence.claimedVersion
}

func findServerByName(pol *policy.Policy, name string) *policy.Server {
	for i := range pol.Servers {
		if pol.Servers[i].Name == name {
			return &pol.Servers[i]
		}
	}
	return nil
}

// stringArgs converts the redacted args map into the evaluator's typed
// observation surface: only plain string values are carried; non-string
// values (numbers, booleans, nested objects) are skipped. Deterministic —
// map iteration order does not matter because the result is a map.
func stringArgs(redactedArgs map[string]any) map[string]string {
	if len(redactedArgs) == 0 {
		return nil
	}
	out := make(map[string]string, len(redactedArgs))
	for k, v := range redactedArgs {
		switch tv := v.(type) {
		case string:
			out[k] = tv
		case []any, []string:
			// Command-bearing args often arrive as an argv array (e.g.
			// {"args":["bash","-c","id"]}). Preserve them as a space-joined
			// string so the capability package's commandBearingArgs can see
			// the shell invocation. Dropping them would be fail-open: an
			// args-derived host_exec/net_egress boundary signal would never
			// be extracted. Nested objects are flattened the same way only
			// under command-bearing keys; ordinary payload arrays (e.g. a
			// list of paths) are also joined so the args surface is never
			// silently lost.
			out[k] = joinArgSlice(tv)
		default:
			// Numbers, booleans, and nested objects are not string-scalar
			// command surfaces; leave them out of the typed args map. They
			// cannot carry a command invocation token.
		}
	}
	return out
}

// joinArgSlice flattens an argv slice into a space-joined string. Nested
// string elements are joined in order; non-string elements are skipped so a
// mixed array cannot forge a token out of a number. This preserves the exact
// argv ordering the tool received (bash -c id -> "bash -c id") for the
// capability signal extractor, while remaining deterministic.
func joinArgSlice(v any) string {
	var parts []string
	switch slice := v.(type) {
	case []string:
		for _, s := range slice {
			if s != "" {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
	case []any:
		for _, e := range slice {
			if s, ok := e.(string); ok && s != "" {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
	}
	return strings.Join(parts, " ")
}

// pathArgFromRedacted derives the mediated file-tool path from the REDACTED
// args only (same key set as the proxy's raw extractPath), so a redaction
// replacement is what the evaluator observes and no raw secret can reach
// the step or its receipt through Path.
func pathArgFromRedacted(redactedArgs map[string]any) string {
	for _, key := range []string{"path", "file", "file_path", "uri"} {
		if v, ok := redactedArgs[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// destIPFromArgs derives the structured network destination from a
// redacted IP-literal arg value under the documented destination keys. A
// hostname is NOT resolved here: it stays in Args where the evaluator's own
// args surface handles it deterministically.
func destIPFromArgs(redactedArgs map[string]any) netip.Addr {
	for _, key := range []string{"dest_ip", "ip", "host", "url"} {
		v, ok := redactedArgs[key].(string)
		if !ok || v == "" {
			continue
		}
		if i := strings.Index(v, "://"); i >= 0 {
			v = v[i+3:]
		}
		if i := strings.IndexAny(v, "/?#"); i >= 0 {
			v = v[:i]
		}
		if i := strings.LastIndex(v, ":"); i >= 0 && !strings.Contains(v[:i], ":") {
			v = v[:i]
		}
		if addr, err := netip.ParseAddr(strings.Trim(v, "[]")); err == nil {
			return addr
		}
	}
	return netip.Addr{}
}

// destHostFromArgs derives the structured hostname destination from a
// redacted host/url arg value, lowercased with a trailing dot stripped, so
// non-canonical net tools (web_fetch, browse, fetch_url) that carry a
// hostname in a url/host arg emit a structured egress destination rather
// than falling through with no signal (P2: fail-open). An IP literal is NOT
// returned here — destIPFromArgs owns that and the evaluator treats a
// populated DestHost as a hostname it must canonically validate. Empty or a
// value that still parses as an IP literal returns "" (the IP path owns it).
// This also must not invent a target when the hostname is malformed: it is
// the evaluator's job to reject (fail closed to PAUSE), not the proxy's to
// guess.
func destHostFromArgs(redactedArgs map[string]any) string {
	for _, key := range []string{"host", "url", "dest_host", "uri", "domain"} {
		v, ok := redactedArgs[key].(string)
		if !ok || v == "" {
			continue
		}
		if i := strings.Index(v, "://"); i >= 0 {
			v = v[i+3:]
		}
		if i := strings.IndexAny(v, "/?#"); i >= 0 {
			v = v[:i]
		}
		if i := strings.LastIndex(v, ":"); i >= 0 && !strings.Contains(v[:i], ":") {
			v = v[:i]
		}
		v = strings.Trim(v, "[]")
		// An IP literal is not a hostname; the IP path owns it.
		if _, err := netip.ParseAddr(v); err == nil {
			continue
		}
		if v == "" {
			continue
		}
		return strings.ToLower(strings.TrimSuffix(v, "."))
	}
	return ""
}

// capabilityDeclaredAuthority builds the declared authority for an opted-in
// step from the snapshot policy generation: Target is the logical server
// name, WorkspaceRoot is the server-declared root ONLY. It does NOT fall back
// to the proxy process's working directory: a missing server-declared root
// leaves WorkspaceRoot empty so the capability evaluator fails closed
// (missing workspace root -> evaluator error -> PAUSE) rather than silently
// classifying files beside the visor process as in-envelope (P2: forging the
// root with os.Getwd() was a fail-open that treated any sibling file as
// in-workspace). The optional envelope sets (Network, Host,
// DeclaredExecutables) stay empty on this first wiring: derived host_exec /
// net_egress boundaries then fail closed to PAUSE_REQUIRE_NEW_PROOF.
func capabilityDeclaredAuthority(pol *policy.Policy, serverName string) capability.DeclaredAuthority {
	root := ""
	if srv := findServerByName(pol, serverName); srv != nil {
		root = srv.WorkspaceRoot
	}
	return capability.DeclaredAuthority{
		Target:        serverName,
		WorkspaceRoot: root,
	}
}
