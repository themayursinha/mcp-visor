package contextprovenance

import "strings"

func trustRank(t string) (int, bool) {
	switch t {
	case TrustUntrusted:
		return 0, true
	case TrustUser:
		return 1, true
	case TrustDeveloper:
		return 2, true
	case TrustSystem:
		return 3, true
	default:
		return 0, false
	}
}

func minTrust(a, b string) string {
	ra, _ := trustRank(a)
	rb, _ := trustRank(b)
	if rb < ra {
		return b
	}
	return a
}

func dominates(have, need string) bool {
	h, okh := trustRank(have)
	n, okn := trustRank(need)
	return okh && okn && h >= n
}

func indexFragments(frags []ContextFragment) (map[string]ContextFragment, bool) {
	out := make(map[string]ContextFragment, len(frags))
	for _, f := range frags {
		if f.FragmentID == "" || f.Origin == "" || f.Principal == "" || f.Scope == "" {
			return nil, false
		}
		if _, ok := trustRank(f.Trust); !ok {
			return nil, false
		}
		if _, dup := out[f.FragmentID]; dup {
			return nil, false
		}
		out[f.FragmentID] = f
	}
	return out, true
}

func structuralOK(root EvaluationRoot, g map[string]ContextFragment) bool {
	if root.SchemaVersion != SchemaVersion {
		return false
	}
	for _, f := range g {
		if f.IntroducedAt < 0 || f.IntroducedAt > root.CurrentTick {
			return false
		}
		for _, p := range f.DerivedFrom {
			parent, ok := g[p]
			if !ok {
				return false
			}
			if parent.IntroducedAt > f.IntroducedAt {
				return false
			}
		}
	}
	return !cyclic(g)
}

func cyclic(g map[string]ContextFragment) bool {
	const white, gray, black = 0, 1, 2
	color := make(map[string]int, len(g))
	var dfs func(string) bool
	dfs = func(id string) bool {
		color[id] = gray
		for _, p := range g[id].DerivedFrom {
			switch color[p] {
			case gray:
				return true
			case white:
				if dfs(p) {
					return true
				}
			}
		}
		color[id] = black
		return false
	}
	for id := range g {
		if color[id] == white && dfs(id) {
			return true
		}
	}
	return false
}

func ceilings(g map[string]ContextFragment) map[string]string {
	out := make(map[string]string, len(g))
	var ceil func(string) string
	ceil = func(id string) string {
		if v, ok := out[id]; ok {
			return v
		}
		f := g[id]
		c := f.Trust
		for _, p := range f.DerivedFrom {
			c = minTrust(c, ceil(p))
		}
		out[id] = c
		return c
	}
	for id := range g {
		ceil(id)
	}
	return out
}

func ancestryIDs(g map[string]ContextFragment, id string) []string {
	var ids []string
	seen := map[string]bool{}
	var walk func(string)
	walk = func(cur string) {
		if seen[cur] {
			return
		}
		seen[cur] = true
		for _, p := range g[cur].DerivedFrom {
			walk(p)
		}
		ids = append(ids, cur)
	}
	walk(id)
	return ids
}

func ancestryBreach(g map[string]ContextFragment, ceil map[string]string, target string) bool {
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(id string) bool {
		if seen[id] {
			return false
		}
		seen[id] = true
		f := g[id]
		if len(f.DerivedFrom) > 0 {
			parentMin := ceil[f.DerivedFrom[0]]
			for _, p := range f.DerivedFrom[1:] {
				parentMin = minTrust(parentMin, ceil[p])
			}
			fr, _ := trustRank(f.Trust)
			pr, _ := trustRank(parentMin)
			if fr > pr {
				return true
			}
		}
		for _, p := range f.DerivedFrom {
			if walk(p) {
				return true
			}
		}
		return false
	}
	return walk(target)
}

func evidence(c CandidateMessage, origin, principal, scope, path, declared, effective, ceiling, required, proof, escalation, authority string) [8]string {
	return [8]string{
		"Context route Agent A -> MCP web tool -> Agent B",
		"Visible role " + c.Claims.VisibleRole + " reconstructed_from " + c.Claims.ReconstructedFromRole,
		"Original origin " + origin + " principal " + principal + " scope " + scope,
		"Derived path " + path,
		"Declared trust " + declared + " effective trust " + effective,
		"Trust ceiling " + ceiling + " required " + required,
		"Context Provenance Proof " + proof,
		"Context Authority Escalation " + escalation + "; Instruction " + authority,
	}
}

func closed(reason string) Decision {
	return Decision{Proof: ProofInvalid, Escalation: EscalationFound, InstructionAuthority: NonAuthoritative, Reason: reason}
}

func Authorize(root EvaluationRoot, candidate CandidateMessage) Decision {
	d := closed("invalid evaluation root")
	fill := func() {
		d.Evidence = evidence(candidate, "", "", "", "", "", d.EffectiveTrust, "", root.RequiredInstructionTrust, d.Proof, d.Escalation, d.InstructionAuthority)
	}
	g, ok := indexFragments(root.Fragments)
	if !ok || !structuralOK(root, g) {
		fill()
		return d
	}
	if _, ok := trustRank(root.RequiredInstructionTrust); !ok {
		d.Reason = "unknown required trust"
		fill()
		return d
	}
	target, found := g[candidate.FragmentID]
	if !found {
		d.Reason = "target fragment missing"
		fill()
		return d
	}
	ceil := ceilings(g)
	eff := ceil[candidate.FragmentID]
	ids := ancestryIDs(g, candidate.FragmentID)
	path := strings.Join(ids, "->")
	origin, principal, scope := "", "", ""
	if len(ids) > 0 {
		src := g[ids[0]]
		origin, principal, scope = src.Origin, src.Principal, src.Scope
	}
	d.EffectiveTrust = eff
	switch {
	case ancestryBreach(g, ceil, candidate.FragmentID):
		d.Reason = "context authority escalation"
	case !dominates(eff, root.RequiredInstructionTrust):
		d.Proof, d.Escalation, d.Reason = ProofValid, EscalationNone, "insufficient instruction trust"
	default:
		d.Proof, d.Escalation, d.InstructionAuthority, d.Reason = ProofValid, EscalationNone, Authoritative, "authorized"
	}
	d.Evidence = evidence(candidate, origin, principal, scope, path, target.Trust, eff, eff, root.RequiredInstructionTrust, d.Proof, d.Escalation, d.InstructionAuthority)
	return d
}
