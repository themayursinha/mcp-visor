package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/ownership"
	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/receipt"
	"github.com/themayursinha/mcp-visor/internal/redaction"
) // Capability ownership gate (card t_02a1bc43, Architect contract). Runs
// after ordinary policy evaluation succeeds or requires approval, before
// egress, chain, capability-accounting, approval, durable commit, or
// relay. Ownership never converts an existing deny to allow. When the
// policy carries no capability_ownership block, every call here is a no-op
// with zero behavioral delta.

// ownershipDeny carries a terminal ownership denial.
type ownershipDeny struct {
	reason  string
	receipt *receipt.CapabilityOwnershipReceipt
}

// ownershipReasonCode renders the stable deny evidence shared by the
// client error, the audit reason, and the proof receipt.
func ownershipReasonCode(reason string) string {
	return "cross-principal authority acquisition: capability ownership proof invalid (" + reason + "); argument class PRINCIPAL; effect class THIRD_PARTY; authority transition USER->OTHER"
}

// checkCapabilityOwnership evaluates the ownership proof for an
// allow-bound call. Returns nil receipt+deny when the endpoint is not
// protected or the proof is valid.
func (p *Proxy) checkCapabilityOwnership(
	serverName string,
	callReq mcp.ToolsCallRequest,
	redactedArgs map[string]any,
	originalRaw []byte,
	pol *policy.Policy,
	now time.Time,
) (*receipt.CapabilityOwnershipReceipt, *ownershipDeny) {
	if pol == nil || pol.CapabilityOwnership == nil {
		return nil, nil
	}
	reg, err := ownershipRegistryFromPolicy(pol)
	if err != nil {
		// Validated at load; a runtime construction failure fails closed.
		return nil, &ownershipDeny{reason: ownershipReasonCode("mismatch")}
	}
	cap, protected := reg.Capability(serverName, callReq.Name)
	if !protected {
		// Fail closed: on a listed endpoint, an undeclared tool (e.g.
		// newly advertised under a permissive default) must not bypass
		// ownership. Unlisted endpoints retain legacy behavior.
		owner, listed := reg.EndpointOwner(serverName)
		if !listed {
			return nil, nil
		}
		return p.renderOwnershipDecision(pol, originalRaw, ownership.Proof{
			Verdict:     ownership.VerdictInvalid,
			Reason:      ownership.ReasonMissing,
			Requester:   p.cfg.ClientID,
			Server:      serverName,
			Tool:        callReq.Name,
			Owner:       owner,
			EvaluatedAt: now.UTC(),
		}, ownership.Capability{Server: serverName, Owner: owner, Tool: callReq.Name}, "", false)
	}
	req := ownership.Request{
		Requester:   p.cfg.ClientID,
		Server:      serverName,
		Tool:        callReq.Name,
		EffectClass: cap.EffectClass,
	}
	scopeValue, hasScope := "", false
	if cap.ScopeArgument != "" {
		if v, ok := redactedArgs[cap.ScopeArgument]; ok {
			if str, ok := v.(string); ok {
				scopeValue, hasScope = str, true
			}
		}
	}
	req.ScopeValue, req.HasScope = scopeValue, hasScope
	proof := reg.Evaluate(req, now)
	return p.renderOwnershipDecision(pol, originalRaw, proof, cap, scopeValue, hasScope)
}

// renderOwnershipDecision signs the proof receipt (when possible) and maps
// the verdict to an allow receipt or a terminal deny. Signing failure on a
// potential allow denies; an already-invalid decision stays denied.
func (p *Proxy) renderOwnershipDecision(
	pol *policy.Policy,
	originalRaw []byte,
	proof ownership.Proof,
	cap ownership.Capability,
	scopeValue string,
	hasScope bool,
) (*receipt.CapabilityOwnershipReceipt, *ownershipDeny) {
	rec := &receipt.CapabilityOwnershipReceipt{
		Schema:         "capability_ownership_v1",
		Requester:      proof.Requester,
		Server:         proof.Server,
		Tool:           proof.Tool,
		Owner:          proof.Owner,
		EffectClass:    cap.EffectClass,
		ScopeArgument:  cap.ScopeArgument,
		DelegationID:   proof.DelegationID,
		DelegationSHA:  proof.DelegationSHA,
		Status:         ownershipStatus(proof),
		GrantIssuedAt:  grantBound(proof, true),
		GrantExpiresAt: grantBound(proof, false),
		RequestHash:    sha256Hex(originalRaw),
		PolicyHash:     sha256Hex([]byte(marshalEvidence(pol))),
		EvaluatedAt:    proof.EvaluatedAt.Unix(),
		ReasonCode:     proof.Reason,
	}
	if hasScope && cap.ScopeArgument != "" {
		sum := sha256.Sum256([]byte(scopeValue))
		rec.ScopeValueSHA = hex.EncodeToString(sum[:])
	}
	if proof.Verdict == ownership.VerdictValidDirect || proof.Verdict == ownership.VerdictValidDelegated {
		rec.Verdict = "allow"
	} else {
		rec.Verdict = "deny"
	}
	signed := true
	if p.approvalSigner == nil {
		signed = false
	} else if err := rec.SignWith(p.approvalSigner); err != nil {
		signed = false
	}
	if proof.Verdict != ownership.VerdictValidDirect && proof.Verdict != ownership.VerdictValidDelegated {
		return recOrNil(rec, signed), &ownershipDeny{reason: ownershipReasonCode(proof.Reason), receipt: recOrNil(rec, signed)}
	}
	if !signed {
		return nil, &ownershipDeny{reason: ownershipReasonCode("mismatch"), receipt: nil}
	}
	return rec, nil
}

// denyOwnership responds to an ownership denial with the full denied
// treatment: metrics, terminal audit event with the proof receipt, SIEM
// forward, observation. Shared by the pre-egress gate and the grant-site
// recheck; release is idempotent across both barrier states.
func (p *Proxy) denyOwnership(
	req mcp.Request,
	raw json.RawMessage,
	respond toolsCallResponder,
	release func(),
	serverName string,
	callReq mcp.ToolsCallRequest,
	redactedArgs map[string]any,
	redactionResult redaction.Result,
	risk policy.RiskLevel,
	snapshot runtimeSnapshot,
	chainTriggered bool,
	started time.Time,
	deny *ownershipDeny,
) (json.RawMessage, string) {
	p.metrics.IncrementDenied()
	respond(req.ID, deny.reason)

	deniedEvent := audit.Event{
		EventType: audit.EventToolDenied,
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
		Server:    serverName,
		Tool:      callReq.Name,
		Arguments: redactedArgs,
		Decision:  string(policy.ActionDeny),
		Reason:    withRedactionNote(deny.reason, redactionResult),
		RiskLevel: string(risk),
	}
	attachOwnershipReceipt(&deniedEvent, deny.receipt)
	p.attachServerIdentity(&deniedEvent, snapshot.identity)
	_ = p.audit.Log(deniedEvent)
	release()
	p.forwardAudit(deniedEvent)
	p.logger.Warn("capability ownership denied",
		"tool", callReq.Name,
		"reason", deny.reason,
		"session", p.session.ID,
	)
	p.observeToolCall("denied", deny.reason, serverName, callReq.Name, string(risk), chainTriggered, started)
	return raw, "denied"
}

// attachOwnershipReceipt binds a signed ownership proof to a terminal
// audit event via dedicated fields (never the approval/capability fields).
func attachOwnershipReceipt(event *audit.Event, rec *receipt.CapabilityOwnershipReceipt) {
	if event == nil || rec == nil {
		return
	}
	data, err := rec.Marshal()
	if err != nil {
		return
	}
	sum := sha256.Sum256(data)
	event.OwnershipReceiptHash = hex.EncodeToString(sum[:])
	var recMap map[string]any
	if err := json.Unmarshal(data, &recMap); err == nil {
		event.OwnershipReceipt = recMap
	}
}

// recOrNil returns the receipt only if it carries a signature.
func recOrNil(rec *receipt.CapabilityOwnershipReceipt, signed bool) *receipt.CapabilityOwnershipReceipt {
	if !signed {
		return nil
	}
	return rec
}

// ownershipStatus maps verifier verdicts to receipt statuses.
func ownershipStatus(proof ownership.Proof) string {
	switch proof.Verdict {
	case ownership.VerdictValidDirect:
		return receipt.OwnershipStatusDirect
	case ownership.VerdictValidDelegated:
		return receipt.OwnershipStatusMatched
	}
	switch proof.Reason {
	case ownership.ReasonExpired:
		return receipt.OwnershipStatusExpired
	case ownership.ReasonAmbiguous:
		return receipt.OwnershipStatusAmbiguous
	case ownership.ReasonMismatch:
		return receipt.OwnershipStatusMismatch
	default:
		return receipt.OwnershipStatusMissing
	}
}

// grantBound renders grant bounds; empty unless the proof carries a grant.
func grantBound(proof ownership.Proof, issued bool) string {
	if !proof.HasGrant {
		return ""
	}
	if issued {
		return proof.GrantIssued.UTC().Format("2006-01-02T15:04:05Z")
	}
	return proof.GrantExpires.UTC().Format("2006-01-02T15:04:05Z")
}

// ownershipRegistryFromPolicy builds the ownership registry from validated
// policy. Post-Validate construction cannot fail on shape; time parsing is
// re-checked defensively and fails closed.
func ownershipRegistryFromPolicy(pol *policy.Policy) (*ownership.Registry, error) {
	oc := pol.CapabilityOwnership
	var caps []ownership.Capability
	for _, ep := range oc.Endpoints {
		for _, c := range ep.Capabilities {
			caps = append(caps, ownership.Capability{
				Server:        ep.Server,
				Owner:         ep.Owner,
				Tool:          c.Tool,
				EffectClass:   c.EffectClass,
				ScopeArgument: c.ScopeArgument,
			})
		}
	}
	reg, err := ownership.NewRegistry(caps)
	if err != nil {
		return nil, err
	}
	for _, ep := range oc.Endpoints {
		if err := reg.RegisterOwner(ep.Server, ep.Owner); err != nil {
			return nil, err
		}
	}
	for _, g := range oc.Delegations {
		issued, err := time.Parse(time.RFC3339, g.IssuedAt)
		if err != nil {
			return nil, err
		}
		expires, err := time.Parse(time.RFC3339, g.ExpiresAt)
		if err != nil {
			return nil, err
		}
		var scopeArg string
		var exact []string
		if g.ResourceScope != nil {
			scopeArg = g.ResourceScope.Argument
			exact = g.ResourceScope.ExactValues
		}
		reg.AddGrant(ownership.Grant{
			ID: g.ID, Owner: g.Owner, Delegate: g.Delegate,
			Server: g.Server, Tool: g.Tool, EffectClass: g.EffectClass,
			ScopeArgument: scopeArg, ExactValues: exact,
			IssuedAt: issued, ExpiresAt: expires,
		})
	}
	return reg, nil
}
