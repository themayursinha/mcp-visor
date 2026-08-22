package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
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
	//
	// Eval is consulted once, on this post-gate pre-forward path. Identity,
	// runtime-limit, sensitive-file, and chain-deny already failed closed
	// above; those terminal denies are not capability-accounted. Post-relay
	// Result Eval is out of scope (a second hash-chain step per tools/call).
	capPauseReason := ""
	var capArtifact any
	if p.capEval != nil {
		step := capability.Step{
			SessionID: p.session.ID,
			Tool:      callReq.Name,
			Args:      stringArgs(redactedArgs),
			Path:      pathArgFromRedacted(redactedArgs),
			DestIP:    destIPFromArgs(callReq.Name, redactedArgs),
			DestHost:  destHostFromArgs(callReq.Name, redactedArgs),
			Declared:  capabilityDeclaredAuthority(snapshot.policy, serverName),
		}
		p.capEvalMu.Lock()
		p.capStepID++
		step.StepID = p.capStepID
		receipt, err := p.capEval.Eval(context.Background(), step, p.capLastHash)
		if err != nil {
			stepID := step.StepID
			prevHash := p.capLastHash
			// Evaluator error: seal the pause-to-proof artifact, make it the
			// predecessor for the next step (so the chain cannot fork around
			// the pause), and route to the approval gate. Do not deny inline.
			if pr, err2 := capability.NewPauseReceipt(p.session.ID, stepID, prevHash, err); err2 == nil {
				capArtifact = pr
				p.capLastHash = pr.Hash
				if adv, ok := p.capEval.(interface{ AdvanceAfterError(int, string) }); ok {
					adv.AdvanceAfterError(stepID, pr.Hash)
				}
			}
			p.capEvalMu.Unlock()
			capPauseReason = "capability boundary: PAUSE_REQUIRE_NEW_PROOF (evaluator error)"
		} else {
			if receipt != nil {
				p.capLastHash = receipt.Hash
				capArtifact = receipt
				if receipt.Decision == capability.DecisionPauseRequireProof {
					// Boundary signal not attributable to the declared envelope (E5):
					// route to the approval gate so an operator can supply fresh proof.
					// Fail closed when approval is unavailable or rejected. Never deny
					// inline and never silently allow.
					capPauseReason = "capability boundary: PAUSE_REQUIRE_NEW_PROOF (effect outside declared envelope)"
				}
			}
			p.capEvalMu.Unlock()
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
		attachCapabilityArtifact(&deniedEvent, capArtifact)
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
		// Persist the capability receipt (ALLOW, E5 pause, or evaluator-error
		// pause) on the terminal event so the accounting trajectory is
		// durable. Dropping a successful Eval receipt would leave only the
		// in-memory hash, which disappears on process exit.
		attachCapabilityArtifact(&approvalEvent, capArtifact)
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
		attachCapabilityArtifact(&allowEvent, capArtifact)
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
		attachCapabilityArtifact(&defaultAllowEvent, capArtifact)
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

// attachCapabilityArtifact writes a sealed capability receipt (Eval Receipt
// or PauseReceipt) onto the terminal audit event. Nil artifacts are a no-op
// so the default no-eval path is unchanged. Uses the existing optional
// approval_receipt fields; it does not add audit schema.
func attachCapabilityArtifact(event *audit.Event, artifact any) {
	if event == nil || artifact == nil {
		return
	}
	data, err := json.Marshal(artifact)
	if err != nil {
		return
	}
	event.ApprovalReceiptHash = sha256Hex(data)
	var recMap map[string]any
	if err := json.Unmarshal(data, &recMap); err == nil {
		event.ApprovalReceipt = recMap
	}
}

// stringArgs converts the redacted args map into the evaluator's typed
// observation surface. Under a command-bearing key, ANY JSON subtree
// (string, argv array, nested object, array of objects) is command surface
// and is flattened recursively so run({"arguments":[{"command":"bash -c id"}]})
// cannot drop the command (fail-open ALLOW). Under a payload key, only
// string scalars and string arrays are kept; nested objects stay dropped
// (Rev 15). Numbers and booleans are omitted. Nested map keys are sorted
// so the joined result is deterministic; array order is preserved.
func stringArgs(redactedArgs map[string]any) map[string]string {
	if len(redactedArgs) == 0 {
		return nil
	}
	out := make(map[string]string, len(redactedArgs))
	for k, v := range redactedArgs {
		if s := flattenArgValue(k, v); s != "" {
			out[k] = s
		}
	}
	return out
}

func flattenArgValue(key string, v any) string {
	if isCommandBearingKey(key) {
		return flattenCommandSurface(v)
	}
	switch tv := v.(type) {
	case string:
		return tv
	case []any, []string:
		return joinStringSlice(tv)
	default:
		return ""
	}
}

func isCommandBearingKey(k string) bool {
	switch k {
	case "command", "cmd", "args", "arguments", "executable", "shell_command":
		return true
	}
	return false
}

// flattenCommandSurface walks a command-bearing JSON value and joins every
// string it finds. Maps are visited in sorted-key order; arrays keep order.
// Non-string scalars are skipped so a number cannot forge a token.
func flattenCommandSurface(v any) string {
	switch tv := v.(type) {
	case string:
		return strings.TrimSpace(tv)
	case []string:
		return joinStringSlice(tv)
	case []any:
		var parts []string
		for _, e := range tv {
			if s := flattenCommandSurface(e); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	case map[string]any:
		if len(tv) == 0 {
			return ""
		}
		keys := make([]string, 0, len(tv))
		for k := range tv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			if s := flattenCommandSurface(tv[k]); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

// joinStringSlice flattens a string argv slice. Non-string elements of a
// mixed []any are skipped (payload arrays are not command objects).
func joinStringSlice(v any) string {
	var parts []string
	switch slice := v.(type) {
	case []string:
		for _, s := range slice {
			if s = strings.TrimSpace(s); s != "" {
				parts = append(parts, s)
			}
		}
	case []any:
		for _, e := range slice {
			if s, ok := e.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					parts = append(parts, s)
				}
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
// redacted IP-literal arg. Explicit dest_ip is always a destination
// surface. url/host/ip are destinations only on a recognized network tool
// (Rev 15: those keys are payload on exec/write_file). A hostname is NOT
// resolved here.
func destIPFromArgs(tool string, redactedArgs map[string]any) netip.Addr {
	keys := []string{"dest_ip"}
	if capability.IsNetworkToolName(tool) {
		keys = []string{"dest_ip", "ip", "host", "url"}
	}
	for _, key := range keys {
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
// redacted arg. Explicit dest_host is always a destination surface.
// url/host/uri/domain are destinations only on a recognized network tool
// so web_fetch({"url":...}) still pauses while exec({"url":...}) keeps
// url as payload (Rev 15). An IP literal is NOT returned here.
func destHostFromArgs(tool string, redactedArgs map[string]any) string {
	keys := []string{"dest_host"}
	if capability.IsNetworkToolName(tool) {
		keys = []string{"host", "url", "dest_host", "uri", "domain"}
	}
	for _, key := range keys {
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
