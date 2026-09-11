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

// AddCheckDelegation records one delegation relay and enforces max in a
// single critical section: increment, limit check, and over-budget
// rollback never separate, so concurrent denials cannot observe phantom
// depths in their evidence. Counting runs whether or not max enforces
// (max<=0 counts without limiting); over=true means the increment was
// rolled back and the call is denied.
func (s *Session) AddCheckDelegation(max int) (depth int, over bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SpawnDepth++
	if max > 0 && s.SpawnDepth > max {
		s.SpawnDepth--
		return s.SpawnDepth, true
	}
	return s.SpawnDepth, false
}

// TryReserveDelegation atomically checks the ceiling and reserves one
// budget unit. Check-and-reserve must be one critical section: separate
// read and increment lets concurrent calls both pass and over-admit past
// a hard cap. Returns the post-reserve depth and whether a unit was taken.
func (s *Session) TryReserveDelegation(max int) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.SpawnDepth+1 > max {
		return s.SpawnDepth, false
	}
	s.SpawnDepth++
	return s.SpawnDepth, true
}

// ReleaseDelegation returns one reserved unit (floor zero). Used only when
// a call reserved budget but then failed to commit its authorization: the
// call never relayed, so the budget must not stay spent.
func (s *Session) ReleaseDelegation() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.SpawnDepth > 0 {
		s.SpawnDepth--
	}
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

// tryReserveDelegation counts one delegation relay and enforces the
// ceiling atomically: increment, then deny-and-roll-back when over budget.
// Counting runs whether or not enforcement is on, so enabling the limit by
// hot reload cannot grant a fresh budget to already-delegating sessions.
// Returns limited info on denial, or reserved=true when a unit is held.
// The caller releases the unit only if the call never relays
// (durable-commit failure). Unmarked tools return neither.
func tryReserveDelegation(pol *policy.Policy, session *Session, serverName, toolName string) (info *ceilingDenyInfo, reserved bool) {
	if pol == nil || session == nil {
		return nil, false
	}
	if !toolDelegates(pol, serverName, toolName) {
		return nil, false
	}
	max := pol.Settings.MaxSpawnDepth
	depth, over := session.AddCheckDelegation(max)
	if over {
		return &ceilingDenyInfo{
			reason: fmt.Sprintf(
				"delegation ceiling exceeded (depth %d at max %d): argument class DELEGATION, effect class DELEGATION, authority transition PARENT->CHILD",
				depth, max,
			),
			depth: depth,
			max:   max,
		}, false
	}
	return nil, true
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
