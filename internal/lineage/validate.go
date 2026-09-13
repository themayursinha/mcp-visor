package lineage

import "time"

// EnvelopeFromArgs reads lineage claims ONLY from the canonical unique-key
// arguments map. ActorAgentID is the proxy ClientID; `_lineage.actor` is ignored.
func EnvelopeFromArgs(actor, server, tool string, args map[string]any) Envelope {
	env := Envelope{ActorAgentID: actor, Server: server, Tool: tool}
	if args == nil {
		return env
	}
	raw, ok := args["_lineage"]
	if !ok {
		return env
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return env
	}
	env.GrantID = stringField(m, "grant_id")
	env.Capability = stringField(m, "capability")
	env.Resource = stringField(m, "resource")
	env.Effect = stringField(m, "effect")
	env.PriorStateHash = stringField(m, "prior_state_hash")
	env.TrajectoryID = stringField(m, "trajectory_id")
	return env
}

func stringField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// Validate calls ValidateAt with the current UTC time.
func Validate(env Envelope, reg *Registry) (Decision, Evidence) {
	return ValidateAt(env, reg, time.Now().UTC())
}

// ValidateAt evaluates R1, then R2, then R3. The first failure denies.
func ValidateAt(env Envelope, reg *Registry, now time.Time) (Decision, Evidence) {
	ev := Evidence{
		ActorAgentID:   env.ActorAgentID,
		GrantID:        env.GrantID,
		Capability:     env.Capability,
		Resource:       env.Resource,
		Effect:         env.Effect,
		TrajectoryID:   env.TrajectoryID,
		PriorStateHash: env.PriorStateHash,
	}
	if reg == nil {
		ev.Rule = ReasonUnregisteredPrincipal
		return Decision{Reason: ReasonUnregisteredPrincipal}, ev
	}
	actor, ok := reg.Agent(env.ActorAgentID)
	if !ok || !inInterval(actor.CreatedAt, actor.Expiry, now) {
		ev.Rule = ReasonUnregisteredPrincipal
		return Decision{Reason: ReasonUnregisteredPrincipal}, ev
	}
	ev.ParentAgentID = actor.ParentAgentID
	ev.HumanPrincipalID = actor.HumanPrincipalID

	grant, ok := reg.Grant(env.GrantID)
	if !ok || !inInterval(grant.IssuedAt, grant.Expiry, now) || grant.SubjectAgentID != env.ActorAgentID {
		return ceiling(ev)
	}
	chain, err := reg.walkToRoot(env.GrantID)
	if err != nil || len(chain) == 0 {
		return ceiling(ev)
	}
	human := actor.HumanPrincipalID
	ids := make([]string, len(chain))
	for i, g := range chain {
		ids[i] = g.GrantID
		if !inInterval(g.IssuedAt, g.Expiry, now) {
			return ceiling(ev)
		}
		subject, ok := reg.Agent(g.SubjectAgentID)
		if !ok || !inInterval(subject.CreatedAt, subject.Expiry, now) || subject.HumanPrincipalID != human {
			return ceiling(ev)
		}
		if i == 0 {
			if g.ParentGrantID != "" || g.Issuer != human {
				return ceiling(ev)
			}
			if _, isAgent := reg.Agent(g.Issuer); isAgent {
				return ceiling(ev)
			}
		} else {
			parent := chain[i-1]
			if g.Issuer != parent.SubjectAgentID {
				return ceiling(ev)
			}
			if !exactSubset(g.Capabilities, parent.Capabilities) || !exactSubset(g.ResourceScope, parent.ResourceScope) {
				return ceiling(ev)
			}
			issuerAgent, ok := reg.Agent(g.Issuer)
			if !ok || !inInterval(issuerAgent.CreatedAt, issuerAgent.Expiry, now) || issuerAgent.HumanPrincipalID != human {
				return ceiling(ev)
			}
			if subject.ParentAgentID != g.Issuer {
				return ceiling(ev)
			}
		}
		if !containsExact(g.Capabilities, env.Capability) || !containsExact(g.ResourceScope, env.Resource) {
			return ceiling(ev)
		}
	}
	ev.GrantChain = ids

	if env.TrajectoryID == "" {
		return mismatch(ev)
	}
	tr, ok := reg.Trajectory(env.TrajectoryID)
	if !ok {
		return mismatch(ev)
	}
	if tr.ActorAgentID != env.ActorAgentID ||
		tr.GrantID != env.GrantID ||
		tr.Capability != env.Capability ||
		tr.Server != env.Server ||
		tr.Tool != env.Tool ||
		tr.Effect != env.Effect ||
		tr.PriorStateHash != env.PriorStateHash ||
		!containsExact(tr.ResourceScope, env.Resource) {
		return mismatch(ev)
	}

	ev.Rule = "lineage_require"
	return Decision{Allow: true}, ev
}

func ceiling(ev Evidence) (Decision, Evidence) {
	ev.Rule = ReasonDelegationCeiling
	return Decision{Reason: ReasonDelegationCeiling}, ev
}

func mismatch(ev Evidence) (Decision, Evidence) {
	ev.Rule = ReasonTrajectoryMismatch
	return Decision{Reason: ReasonTrajectoryMismatch}, ev
}
