package policy

import (
	"fmt"
	"time"
)

// Capability ownership bindings (card t_02a1bc43, Architect contract).
// An optional top-level capability_ownership block binds exact logical
// server names to one exact owner principal and enumerates protected tools
// with effect classes. Everything is case-sensitive bytes: no globs,
// aliases, or substring matching. When absent, evaluation, loading,
// linting, receipts, and relay behavior remain unchanged.
type CapabilityOwnership struct {
	Endpoints   []OwnedEndpoint   `yaml:"endpoints"`
	Delegations []DelegationGrant `yaml:"delegations"`
}

// OwnedEndpoint binds one logical server to its owner principal.
type OwnedEndpoint struct {
	Server       string           `yaml:"server"`
	Owner        string           `yaml:"owner"`
	Capabilities []CapabilityDecl `yaml:"capabilities"`
}

// CapabilityDecl declares one protected tool and its effect class, plus an
// optional exact resource argument for scoped tools.
type CapabilityDecl struct {
	Tool          string `yaml:"tool"`
	EffectClass   string `yaml:"effect_class"`
	ScopeArgument string `yaml:"scope_argument,omitempty"`
}

// DelegationGrant is a trusted-policy assertion that owner delegates one
// capability to one delegate. No tenant PKI: the policy file is the trust
// root for grants.
type DelegationGrant struct {
	ID            string         `yaml:"id"`
	Owner         string         `yaml:"owner"`
	Delegate      string         `yaml:"delegate"`
	Server        string         `yaml:"server"`
	Tool          string         `yaml:"tool"`
	EffectClass   string         `yaml:"effect_class"`
	ResourceScope *ResourceScope `yaml:"resource_scope,omitempty"`
	IssuedAt      string         `yaml:"issued_at"`
	ExpiresAt     string         `yaml:"expires_at"`
}

// ResourceScope binds a delegation to exact argument values.
type ResourceScope struct {
	Argument    string   `yaml:"argument"`
	ExactValues []string `yaml:"exact_values"`
}

// Validate enforces the ownership binding rules. Any violation fails
// policy loading: ownership must never silently degrade.
func (c *CapabilityOwnership) Validate(p *Policy) error {
	if c == nil {
		return nil
	}
	seenEndpoints := map[string]bool{}
	decls := map[string]map[string]CapabilityDecl{}
	for i := range c.Endpoints {
		ep := &c.Endpoints[i]
		if ep.Server == "" {
			return fmt.Errorf("capability_ownership endpoint at index %d: server is required", i)
		}
		if ep.Owner == "" {
			return fmt.Errorf("capability_ownership endpoint %s: owner is required", ep.Server)
		}
		if seenEndpoints[ep.Server] {
			return fmt.Errorf("capability_ownership: duplicate endpoint %s", ep.Server)
		}
		seenEndpoints[ep.Server] = true
		// The endpoint must reference a known policy server; otherwise the
		// completeness check below could not bind allowed tools.
		var srv *Server
		for j := range p.Servers {
			if p.Servers[j].Name == ep.Server {
				srv = &p.Servers[j]
				break
			}
		}
		if srv == nil {
			return fmt.Errorf("capability_ownership endpoint %s: unknown server", ep.Server)
		}
		seenTools := map[string]bool{}
		decls[ep.Server] = map[string]CapabilityDecl{}
		for _, cap := range ep.Capabilities {
			if cap.Tool == "" {
				return fmt.Errorf("capability_ownership endpoint %s: tool is required", ep.Server)
			}
			if cap.EffectClass == "" {
				return fmt.Errorf("capability_ownership endpoint %s tool %s: effect_class is required", ep.Server, cap.Tool)
			}
			if seenTools[cap.Tool] {
				return fmt.Errorf("capability_ownership endpoint %s: duplicate tool %s", ep.Server, cap.Tool)
			}
			seenTools[cap.Tool] = true
			decls[ep.Server][cap.Tool] = cap
		}
		// Completeness: every allowed tool on a listed endpoint must have
		// exactly one capability declaration.
		for _, tool := range srv.Tools {
			if !tool.Allowed {
				continue
			}
			if !seenTools[tool.Name] {
				return fmt.Errorf("capability_ownership endpoint %s: allowed tool %s lacks a capability declaration", ep.Server, tool.Name)
			}
		}
	}
	seenGrants := map[string]bool{}
	for i := range c.Delegations {
		g := &c.Delegations[i]
		if g.ID == "" {
			return fmt.Errorf("capability_ownership delegation at index %d: id is required", i)
		}
		if seenGrants[g.ID] {
			return fmt.Errorf("capability_ownership: duplicate delegation id %s", g.ID)
		}
		seenGrants[g.ID] = true
		for _, field := range []struct {
			name, value string
		}{
			{"owner", g.Owner},
			{"delegate", g.Delegate},
			{"server", g.Server},
			{"tool", g.Tool},
			{"effect_class", g.EffectClass},
		} {
			if field.value == "" {
				return fmt.Errorf("capability_ownership delegation %s: %s is required", g.ID, field.name)
			}
		}
		epTools, ok := decls[g.Server]
		if !ok {
			return fmt.Errorf("capability_ownership delegation %s: unknown endpoint %s", g.ID, g.Server)
		}
		decl, ok := epTools[g.Tool]
		if !ok {
			return fmt.Errorf("capability_ownership delegation %s: undeclared tool %s on %s", g.ID, g.Tool, g.Server)
		}
		// Grant owner must equal the endpoint owner, and the grant must
		// agree exactly with the declaration on tool and effect class.
		var epOwner string
		for _, ep := range c.Endpoints {
			if ep.Server == g.Server {
				epOwner = ep.Owner
			}
		}
		if g.Owner != epOwner {
			return fmt.Errorf("capability_ownership delegation %s: owner %q is not the endpoint owner %q", g.ID, g.Owner, epOwner)
		}
		if g.EffectClass != decl.EffectClass {
			return fmt.Errorf("capability_ownership delegation %s: effect_class %q disagrees with declaration %q", g.ID, g.EffectClass, decl.EffectClass)
		}
		if decl.ScopeArgument == "" {
			if g.ResourceScope != nil {
				return fmt.Errorf("capability_ownership delegation %s: tool declares no scope argument", g.ID)
			}
		} else {
			if g.ResourceScope == nil {
				return fmt.Errorf("capability_ownership delegation %s: missing resource_scope for scope argument %q", g.ID, decl.ScopeArgument)
			}
			if g.ResourceScope.Argument != decl.ScopeArgument {
				return fmt.Errorf("capability_ownership delegation %s: scope argument %q disagrees with declaration %q", g.ID, g.ResourceScope.Argument, decl.ScopeArgument)
			}
			if len(g.ResourceScope.ExactValues) == 0 {
				return fmt.Errorf("capability_ownership delegation %s: exact_values is required", g.ID)
			}
		}
		issued, err := time.Parse(time.RFC3339, g.IssuedAt)
		if err != nil {
			return fmt.Errorf("capability_ownership delegation %s: malformed issued_at: %w", g.ID, err)
		}
		expires, err := time.Parse(time.RFC3339, g.ExpiresAt)
		if err != nil {
			return fmt.Errorf("capability_ownership delegation %s: malformed expires_at: %w", g.ID, err)
		}
		if !expires.After(issued) {
			return fmt.Errorf("capability_ownership delegation %s: expires_at must be after issued_at", g.ID)
		}
	}
	return nil
}
