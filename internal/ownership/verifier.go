package ownership

import (
	"fmt"
	"time"
)

// Registry holds protected capabilities and exact delegation grants.
type Registry struct {
	capabilities map[string]Capability
	owners       map[string]string
	grants       []Grant
}

func capKey(server, tool string) string { return server + "\x00" + tool }

// NewRegistry indexes capabilities; duplicate server/tool pairs fail.
func NewRegistry(caps []Capability) (*Registry, error) {
	r := &Registry{capabilities: map[string]Capability{}, owners: map[string]string{}}
	for _, c := range caps {
		k := capKey(c.Server, c.Tool)
		if _, dup := r.capabilities[k]; dup {
			return nil, fmt.Errorf("duplicate capability %s/%s", c.Server, c.Tool)
		}
		if prev, ok := r.owners[c.Server]; ok && prev != c.Owner {
			return nil, fmt.Errorf("conflicting owners for %s", c.Server)
		}
		r.owners[c.Server] = c.Owner
		r.capabilities[k] = c
	}
	return r, nil
}

// RegisterOwner records an endpoint owner independently of capabilities,
// so endpoints with zero declarations still fail closed on undeclared
// tools. Conflicting owners fail.
func (r *Registry) RegisterOwner(server, owner string) error {
	if prev, ok := r.owners[server]; ok && prev != owner {
		return fmt.Errorf("conflicting owners for %s", server)
	}
	r.owners[server] = owner
	return nil
}

// AddGrant appends one exact grant.
func (r *Registry) AddGrant(g Grant) {
	r.grants = append(r.grants, g)
}

// Capability returns the protected declaration for server/tool.
func (r *Registry) Capability(server, tool string) (Capability, bool) {
	cap, ok := r.capabilities[capKey(server, tool)]
	return cap, ok
}

// EndpointOwner returns the owner of a listed endpoint. A listed endpoint
// with an undeclared tool fails closed at the gate: under permissive
// defaults an unknown tool would otherwise bypass ownership entirely.
func (r *Registry) EndpointOwner(server string) (string, bool) {
	owner, ok := r.owners[server]
	return owner, ok
}

// Evaluate proves ownership for req at now. Unlisted server/tool pairs are
// outside the ownership system (legacy behavior, not a verdict): callers
// only invoke Evaluate for protected endpoints.
func (r *Registry) Evaluate(req Request, now time.Time) Proof {
	base := Proof{
		Requester:   req.Requester,
		Server:      req.Server,
		Tool:        req.Tool,
		EffectClass: req.EffectClass,
		EvaluatedAt: now.UTC(),
	}
	cap, ok := r.capabilities[capKey(req.Server, req.Tool)]
	if !ok {
		return invalid(base, ReasonNotCovered)
	}
	base.Owner = cap.Owner
	if cap.EffectClass != "" && req.EffectClass != "" && req.EffectClass != cap.EffectClass {
		return invalid(base, ReasonMismatch)
	}
	if req.Requester == cap.Owner {
		base.Verdict = VerdictValidDirect
		return base
	}
	matches := r.matchingGrants(cap, req, now)
	switch len(matches) {
	case 0:
		// Distinguish expiry from absence when exactly one grant matches on
		// every axis except time.
		if r.hasTimeOnlyMismatch(cap, req, now) {
			return invalid(base, ReasonExpired)
		}
		return invalid(base, ReasonMissing)
	case 1:
		g := matches[0]
		base.Verdict = VerdictValidDelegated
		base.DelegationID = g.ID
		base.DelegationSHA = CanonicalGrantSHA(g)
		base.GrantIssued = g.IssuedAt
		base.GrantExpires = g.ExpiresAt
		base.HasGrant = true
		return base
	default:
		return invalid(base, ReasonAmbiguous)
	}
}

// matchingGrants returns unexpired grants agreeing exactly on owner,
// delegate, endpoint, tool, effect class, and scope value.
func (r *Registry) matchingGrants(cap Capability, req Request, now time.Time) []Grant {
	var out []Grant
	for _, g := range r.grants {
		if g.Owner != cap.Owner {
			continue
		}
		if g.Delegate != req.Requester {
			continue
		}
		if g.Server != req.Server || g.Tool != req.Tool {
			continue
		}
		if g.EffectClass != cap.EffectClass {
			continue
		}
		if cap.ScopeArgument == "" {
			if g.ScopeArgument != "" {
				continue
			}
		} else {
			if g.ScopeArgument != cap.ScopeArgument {
				continue
			}
			if !req.HasScope {
				continue
			}
			found := false
			for _, v := range g.ExactValues {
				if v == req.ScopeValue {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if now.Before(g.IssuedAt) || !now.Before(g.ExpiresAt) {
			continue
		}
		out = append(out, g)
	}
	return out
}

// hasTimeOnlyMismatch reports whether some grant matches on every axis but
// time, so the denial reason is expiry rather than absence.
func (r *Registry) hasTimeOnlyMismatch(cap Capability, req Request, now time.Time) bool {
	for _, g := range r.grants {
		if g.Owner != cap.Owner || g.Delegate != req.Requester {
			continue
		}
		if g.Server != req.Server || g.Tool != req.Tool || g.EffectClass != cap.EffectClass {
			continue
		}
		if cap.ScopeArgument != "" {
			if g.ScopeArgument != cap.ScopeArgument || !req.HasScope {
				continue
			}
			found := false
			for _, v := range g.ExactValues {
				if v == req.ScopeValue {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if now.Before(g.IssuedAt) || !now.Before(g.ExpiresAt) {
			return true
		}
	}
	return false
}

func invalid(base Proof, reason string) Proof {
	base.Verdict = VerdictInvalid
	base.Reason = reason
	return base
}
