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

// Delegation ceilings (card t_1851c97f): a hard, configurable cap on
// authorized delegation relays per session for tools explicitly marked
// delegates. Generation budget, not call-stack nesting: Visor observes a
// flat authorized-call stream, not spawn returns.
//
// Trust basis: the counter increments only when Visor itself authorizes a
// relay (alongside taint marking, post durable commit). Nothing is
// self-reported. Zero max_spawn_depth (default, never defaulted) disables
// enforcement without changing any other behavior.

// DelegationDepth returns the session's authorized delegation count.
func (s *Session) DelegationDepth() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.SpawnDepth
}

// NoteDelegation records one authorized delegation relay.
func (s *Session) NoteDelegation() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SpawnDepth++
}

// toolDelegates reports whether the policy marks this tool as a delegation
// (spawn) tool. Unknown tools never count: delegation is declared, not
// guessed from names.
func toolDelegates(pol *policy.Policy, serverName, toolName string) bool {
	if pol == nil {
		return false
	}
	for _, srv := range pol.Servers {
		if srv.Name != serverName {
			continue
		}
		for _, tool := range srv.Tools {
			if tool.Name == toolName {
				return tool.Delegates
			}
		}
	}
	return false
}

// ceilingDenyInfo carries a ceiling denial with its evidence inputs.
type ceilingDenyInfo struct {
	reason string
	depth  int
	max    int
}

// checkDelegationCeiling reports whether relaying this allow-bound call
// would exceed settings.max_spawn_depth. Pure check: no state changes.
func checkDelegationCeiling(pol *policy.Policy, session *Session, serverName, toolName string) *ceilingDenyInfo {
	if pol == nil || session == nil {
		return nil
	}
	max := pol.Settings.MaxSpawnDepth
	if max <= 0 {
		return nil
	}
	if !toolDelegates(pol, serverName, toolName) {
		return nil
	}
	depth := session.DelegationDepth()
	if depth+1 > max {
		return &ceilingDenyInfo{
			reason: fmt.Sprintf(
				"delegation ceiling exceeded (depth %d at max %d): argument class DELEGATION, effect class DELEGATION, authority transition PARENT->CHILD",
				depth, max,
			),
			depth: depth,
			max:   max,
		}
	}
	return nil
}

// noteDelegationRelay records an authorized delegation relay. Called
// alongside taint marking on every allow-commit path; denied calls never
// reach it, so denials never consume budget.
func noteDelegationRelay(pol *policy.Policy, session *Session, serverName, toolName string) {
	if pol == nil || session == nil {
		return
	}
	if pol.Settings.MaxSpawnDepth <= 0 {
		return
	}
	if !toolDelegates(pol, serverName, toolName) {
		return
	}
	session.NoteDelegation()
}

// denyDelegationCeiling responds to a ceiling denial with the full denied
// treatment: metrics, terminal audit event carrying the depth fields, SIEM
// forward, observation. release is idempotent, so this is safe both before
// the approval wait (barrier held) and at grant time (already released).
func (p *Proxy) denyDelegationCeiling(
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
	capArtifact any,
	chainTriggered bool,
	started time.Time,
	info *ceilingDenyInfo,
) (json.RawMessage, string) {
	p.metrics.IncrementDenied()
	respond(req.ID, info.reason)

	deniedEvent := audit.Event{
		EventType:       audit.EventToolDenied,
		SessionID:       p.session.ID,
		AgentID:         p.cfg.ClientID,
		Server:          serverName,
		Tool:            callReq.Name,
		Arguments:       redactedArgs,
		Decision:        string(policy.ActionDeny),
		Reason:          withRedactionNote(info.reason, redactionResult),
		RiskLevel:       string(risk),
		DelegationDepth: info.depth,
		MaxSpawnDepth:   info.max,
	}
	p.attachServerIdentity(&deniedEvent, snapshot.identity)
	attachCapabilityArtifact(&deniedEvent, capArtifact)
	_ = p.audit.Log(deniedEvent)
	release()
	p.forwardAudit(deniedEvent)
	p.logger.Warn("delegation ceiling denied",
		"tool", callReq.Name,
		"reason", info.reason,
		"session", p.session.ID,
	)
	p.observeToolCall("denied", info.reason, serverName, callReq.Name, string(risk), chainTriggered, started)
	return raw, "denied"
}
