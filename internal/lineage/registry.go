package lineage

import (
	"fmt"
	"strings"
	"time"
)

const maxGrantDepth = 32

// NewRegistry indexes and schema-validates agents, grants, and trajectories.
// Past-dated expiry is allowed (runtime R1/R2 deny). Unparseable times,
// inverted intervals, missing refs, self-parents, and cycles fail closed.
func NewRegistry(agents []AgentIdentity, grants []AuthorityGrant, trajectories []Trajectory) (*Registry, error) {
	r := &Registry{
		agents:       make(map[string]AgentIdentity, len(agents)),
		grants:       make(map[string]AuthorityGrant, len(grants)),
		trajectories: make(map[string]Trajectory, len(trajectories)),
	}
	humans := map[string]struct{}{}
	for i, a := range agents {
		if strings.TrimSpace(a.InstanceID) == "" {
			return nil, fmt.Errorf("lineage: agent at index %d: instance_id is required", i)
		}
		if _, dup := r.agents[a.InstanceID]; dup {
			return nil, fmt.Errorf("lineage: duplicate agent instance_id %s", a.InstanceID)
		}
		if strings.TrimSpace(a.HumanPrincipalID) == "" {
			return nil, fmt.Errorf("lineage: agent %s: human_principal_id is required", a.InstanceID)
		}
		if err := validInterval(a.CreatedAt, a.Expiry); err != nil {
			return nil, fmt.Errorf("lineage: agent %s: %w", a.InstanceID, err)
		}
		if a.ParentAgentID == a.InstanceID {
			return nil, fmt.Errorf("lineage: agent %s: self-parenting agent", a.InstanceID)
		}
		r.agents[a.InstanceID] = a
		humans[a.HumanPrincipalID] = struct{}{}
	}
	for id, a := range r.agents {
		if a.ParentAgentID == "" {
			continue
		}
		if _, ok := r.agents[a.ParentAgentID]; !ok {
			return nil, fmt.Errorf("lineage: agent %s: parent_agent_id %s is not registered", id, a.ParentAgentID)
		}
	}
	if err := detectAgentCycles(r.agents); err != nil {
		return nil, err
	}
	for i, g := range grants {
		if strings.TrimSpace(g.GrantID) == "" {
			return nil, fmt.Errorf("lineage: grant at index %d: grant_id is required", i)
		}
		if _, dup := r.grants[g.GrantID]; dup {
			return nil, fmt.Errorf("lineage: duplicate grant_id %s", g.GrantID)
		}
		if strings.TrimSpace(g.Issuer) == "" {
			return nil, fmt.Errorf("lineage: grant %s: issuer is required", g.GrantID)
		}
		if strings.TrimSpace(g.SubjectAgentID) == "" {
			return nil, fmt.Errorf("lineage: grant %s: subject_agent_id is required", g.GrantID)
		}
		if _, ok := r.agents[g.SubjectAgentID]; !ok {
			return nil, fmt.Errorf("lineage: grant %s: subject_agent_id %s is not registered", g.GrantID, g.SubjectAgentID)
		}
		if len(g.Capabilities) == 0 {
			return nil, fmt.Errorf("lineage: grant %s: capabilities is required", g.GrantID)
		}
		if len(g.ResourceScope) == 0 {
			return nil, fmt.Errorf("lineage: grant %s: resource_scope is required", g.GrantID)
		}
		for _, cap := range g.Capabilities {
			if strings.TrimSpace(cap) == "" {
				return nil, fmt.Errorf("lineage: grant %s: empty capability", g.GrantID)
			}
		}
		for _, res := range g.ResourceScope {
			if strings.TrimSpace(res) == "" {
				return nil, fmt.Errorf("lineage: grant %s: empty resource_scope", g.GrantID)
			}
		}
		if err := validInterval(g.IssuedAt, g.Expiry); err != nil {
			return nil, fmt.Errorf("lineage: grant %s: %w", g.GrantID, err)
		}
		if g.ParentGrantID == g.GrantID {
			return nil, fmt.Errorf("lineage: grant %s: self-parenting grant", g.GrantID)
		}
		r.grants[g.GrantID] = g
	}
	for id, g := range r.grants {
		if g.ParentGrantID == "" {
			if _, isAgent := r.agents[g.Issuer]; isAgent {
				return nil, fmt.Errorf("lineage: grant %s: root grant issuer must be the human principal, not an agent", id)
			}
			if _, ok := humans[g.Issuer]; !ok {
				return nil, fmt.Errorf("lineage: grant %s: root issuer %s is not a registered human principal", id, g.Issuer)
			}
			if r.agents[g.SubjectAgentID].ParentAgentID != "" {
				return nil, fmt.Errorf("lineage: grant %s: root grant subject %s is not a root agent", id, g.SubjectAgentID)
			}
			continue
		}
		parent, ok := r.grants[g.ParentGrantID]
		if !ok {
			return nil, fmt.Errorf("lineage: grant %s: parent_grant_id %s is not registered", id, g.ParentGrantID)
		}
		if _, ok := r.agents[g.Issuer]; !ok {
			return nil, fmt.Errorf("lineage: grant %s: issuer %s is not a registered agent", id, g.Issuer)
		}
		if g.Issuer != parent.SubjectAgentID {
			return nil, fmt.Errorf("lineage: grant %s: issuer %s is not the parent grant subject", id, g.Issuer)
		}
	}
	for id := range r.grants {
		if _, err := r.walkToRoot(id); err != nil {
			return nil, err
		}
	}
	for i, tr := range trajectories {
		if strings.TrimSpace(tr.TrajectoryID) == "" {
			return nil, fmt.Errorf("lineage: trajectory at index %d: trajectory_id is required", i)
		}
		if _, dup := r.trajectories[tr.TrajectoryID]; dup {
			return nil, fmt.Errorf("lineage: duplicate trajectory_id %s", tr.TrajectoryID)
		}
		if _, ok := r.agents[tr.ActorAgentID]; !ok {
			return nil, fmt.Errorf("lineage: trajectory %s: actor_agent_id %s is not registered", tr.TrajectoryID, tr.ActorAgentID)
		}
		grant, ok := r.grants[tr.GrantID]
		if !ok {
			return nil, fmt.Errorf("lineage: trajectory %s: grant_id %s is not registered", tr.TrajectoryID, tr.GrantID)
		}
		if grant.SubjectAgentID != tr.ActorAgentID {
			return nil, fmt.Errorf("lineage: trajectory %s: grant subject is not actor", tr.TrajectoryID)
		}
		if strings.TrimSpace(tr.Capability) == "" || strings.TrimSpace(tr.Server) == "" || strings.TrimSpace(tr.Tool) == "" {
			return nil, fmt.Errorf("lineage: trajectory %s: capability, server, and tool are required", tr.TrajectoryID)
		}
		if len(tr.ResourceScope) == 0 {
			return nil, fmt.Errorf("lineage: trajectory %s: resource_scope is required", tr.TrajectoryID)
		}
		if strings.TrimSpace(tr.Effect) == "" || strings.TrimSpace(tr.PriorStateHash) == "" {
			return nil, fmt.Errorf("lineage: trajectory %s: effect and prior_state_hash are required", tr.TrajectoryID)
		}
		chain, err := r.walkToRoot(tr.GrantID)
		if err != nil {
			return nil, err
		}
		if !coveredByChain(chain, tr.Capability, tr.ResourceScope) {
			return nil, fmt.Errorf("lineage: trajectory %s: capability or resource not covered by grant chain", tr.TrajectoryID)
		}
		r.trajectories[tr.TrajectoryID] = tr
	}
	return r, nil
}

func detectAgentCycles(agents map[string]AgentIdentity) error {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(agents))
	var visit func(id string) error
	visit = func(id string) error {
		switch color[id] {
		case gray:
			return fmt.Errorf("lineage: agent %s: cycle in parent_agent_id graph", id)
		case black:
			return nil
		}
		color[id] = gray
		a := agents[id]
		if a.ParentAgentID != "" {
			if err := visit(a.ParentAgentID); err != nil {
				return err
			}
		}
		color[id] = black
		return nil
	}
	for id := range agents {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) Agent(id string) (AgentIdentity, bool) {
	a, ok := r.agents[id]
	return a, ok
}

func (r *Registry) Grant(id string) (AuthorityGrant, bool) {
	g, ok := r.grants[id]
	return g, ok
}

func (r *Registry) Trajectory(id string) (Trajectory, bool) {
	tr, ok := r.trajectories[id]
	return tr, ok
}

func (r *Registry) walkToRoot(grantID string) ([]AuthorityGrant, error) {
	var leafToRoot []AuthorityGrant
	seen := make(map[string]struct{})
	cur := grantID
	for i := 0; i < maxGrantDepth; i++ {
		if cur == "" {
			break
		}
		if _, ok := seen[cur]; ok {
			return nil, fmt.Errorf("lineage: grant %s: cycle in parent_grant_id chain", grantID)
		}
		g, ok := r.grants[cur]
		if !ok {
			return nil, fmt.Errorf("lineage: grant %s: missing ancestor %s", grantID, cur)
		}
		seen[cur] = struct{}{}
		leafToRoot = append(leafToRoot, g)
		if g.ParentGrantID == "" {
			chain := make([]AuthorityGrant, len(leafToRoot))
			for i, g := range leafToRoot {
				chain[len(leafToRoot)-1-i] = g
			}
			return chain, nil
		}
		cur = g.ParentGrantID
	}
	return nil, fmt.Errorf("lineage: grant %s: parent_grant_id chain exceeded depth", grantID)
}

func parseTime(s string) (time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t, nil
	}
	t, err2 := time.Parse(time.RFC3339Nano, s)
	if err2 == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unparseable time %q", s)
}

func validInterval(start, expiry string) error {
	s, err := parseTime(start)
	if err != nil {
		return err
	}
	e, err := parseTime(expiry)
	if err != nil {
		return err
	}
	if !s.Before(e) {
		return fmt.Errorf("start >= expiry")
	}
	return nil
}

func inInterval(start, expiry string, now time.Time) bool {
	s, err1 := parseTime(start)
	e, err2 := parseTime(expiry)
	if err1 != nil || err2 != nil {
		return false
	}
	return !now.Before(s) && now.Before(e)
}

func exactSubset(need, have []string) bool {
	if len(need) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(have))
	for _, h := range have {
		if h != "" {
			set[h] = struct{}{}
		}
	}
	for _, n := range need {
		if n == "" {
			return false
		}
		if _, ok := set[n]; !ok {
			return false
		}
	}
	return true
}

func containsExact(have []string, need string) bool {
	if need == "" {
		return false
	}
	for _, h := range have {
		if h == need {
			return true
		}
	}
	return false
}

func coveredByChain(chain []AuthorityGrant, cap string, resources []string) bool {
	if cap == "" || len(resources) == 0 {
		return false
	}
	for _, g := range chain {
		if !containsExact(g.Capabilities, cap) {
			return false
		}
		for _, res := range resources {
			if !containsExact(g.ResourceScope, res) {
				return false
			}
		}
	}
	return true
}
