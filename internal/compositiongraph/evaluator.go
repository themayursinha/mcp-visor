package compositiongraph

import "strconv"

func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func uniq(xs []string) bool {
	seen := map[string]struct{}{}
	for _, x := range xs {
		if x == "" {
			return false
		}
		if _, ok := seen[x]; ok {
			return false
		}
		seen[x] = struct{}{}
	}
	return len(xs) > 0
}
func okEff(e string) bool { return e == EffectRead || e == EffectTransform || e == EffectSend }
func structuralOK(r EvaluationRoot) bool {
	if r.SchemaVersion != SchemaVersion || r.Mandate.MandateID == "" || !uniq(r.Mandate.AllowedEffects) || !uniq(r.Mandate.AllowedDestinations) || !uniq(r.Mandate.AllowedArtifactClasses) || len(r.InstalledSkills) == 0 {
		return false
	}
	for _, e := range r.Mandate.AllowedEffects {
		if !okEff(e) {
			return false
		}
	}
	sids, eids := map[string]struct{}{}, map[string]struct{}{}
	for _, s := range r.InstalledSkills {
		if s.SkillID == "" || len(s.Edges) == 0 {
			return false
		}
		if _, ok := sids[s.SkillID]; ok {
			return false
		}
		sids[s.SkillID] = struct{}{}
		for _, e := range s.Edges {
			if e.EdgeID == "" || e.FromArtifactClass == "" || e.ToArtifactClass == "" || !okEff(e.EffectClass) || (e.EffectClass == EffectSend) != (e.Destination != "") {
				return false
			}
			if _, ok := eids[e.EdgeID]; ok {
				return false
			}
			eids[e.EdgeID] = struct{}{}
		}
	}
	return true
}
func resolve(skills []InstalledSkill, steps []StepReference) ([]CapabilityEdge, bool, bool) {
	var edges []CapabilityEdge
	for _, st := range steps {
		sk := false
		for _, s := range skills {
			if s.SkillID != st.SkillID {
				continue
			}
			sk = true
			ed := false
			for _, e := range s.Edges {
				if e.EdgeID == st.EdgeID {
					edges, ed = append(edges, e), true
					break
				}
			}
			if !ed {
				return edges, false, true
			}
			break
		}
		if !sk {
			return edges, true, false
		}
	}
	return edges, false, false
}
func inspect(start, final, dest string, allowedE, allowedA []string, edges []CapabilityEdge) (c9, c10, c11, c12 bool) {
	if len(edges) == 0 {
		return
	}
	c9, c11, c12, early := edges[0].FromArtifactClass == start, has(allowedE, edges[0].EffectClass), has(allowedA, edges[0].FromArtifactClass) && has(allowedA, edges[0].ToArtifactClass), false
	for i := 1; i < len(edges); i++ {
		c9 = c9 && edges[i-1].ToArtifactClass == edges[i].FromArtifactClass
		c11 = c11 && has(allowedE, edges[i].EffectClass)
		c12 = c12 && has(allowedA, edges[i].ToArtifactClass)
		early = early || edges[i-1].Destination != ""
	}
	last := edges[len(edges)-1]
	c10 = last.ToArtifactClass == final && last.Destination == dest && !early
	return
}
func pathStr(steps []StepReference) string {
	s := ""
	for i, st := range steps {
		if i > 0 {
			s += ">"
		}
		s += st.SkillID + "/" + st.EdgeID
	}
	return s
}
func Authorize(root EvaluationRoot, action ProposedAction) Decision {
	ed := 0
	for _, s := range root.InstalledSkills {
		ed += len(s.Edges)
	}
	d := Decision{ActionID: action.ActionID, MandateID: root.Mandate.MandateID, StartArtifactClass: action.StartArtifactClass, FinalArtifactClass: action.FinalArtifactClass, Destination: action.Destination, StepCount: len(action.Steps), SkillCount: len(root.InstalledSkills), EdgeCount: ed, Verdict: VerdictDeny, Proof: ProofInvalid, Reason: "invalid evaluation root", GraphStatus: GraphInvalid, PathContinuity: ContinuityInvalid, EffectAuthority: AuthorityInvalid, DestinationAuthority: AuthorityInvalid, ArtifactAuthority: AuthorityInvalid, CompositionStatus: CompositionInvalid}
	switch {
	case !structuralOK(root):
	case action.ActionID == "":
		d.Reason = "action identifier absent"
	case action.StartArtifactClass == "":
		d.Reason = "start artifact class absent"
	case action.FinalArtifactClass == "":
		d.Reason = "final artifact class absent"
	case action.Destination == "":
		d.Reason = "destination absent"
	case len(action.Steps) == 0:
		d.Reason = "capability path absent"
	case !root.CompositionEnabled:
		d.Proof, d.Reason, d.GraphStatus, d.PathContinuity, d.EffectAuthority, d.DestinationAuthority, d.ArtifactAuthority, d.CompositionStatus = ProofDisabled, "capability composition disabled", GraphDisabled, ContinuityDisabled, AuthorityDisabled, AuthorityDisabled, AuthorityDisabled, CompositionDisabled
	default:
		edges, missSk, missEd := resolve(root.InstalledSkills, action.Steps)
		resolved := !missSk && !missEd && len(edges) == len(action.Steps)
		c9, c10, c11, c12 := inspect(action.StartArtifactClass, action.FinalArtifactClass, action.Destination, root.Mandate.AllowedEffects, root.Mandate.AllowedArtifactClasses, edges)
		c13 := has(root.Mandate.AllowedDestinations, action.Destination)
		d.DestinationAuthority = map[bool]string{true: AuthorityPresent, false: AuthorityAbsent}[c13]
		if resolved {
			d.GraphStatus = GraphPresent
			d.EffectAuthority = map[bool]string{true: AuthorityPresent, false: AuthorityAbsent}[c11]
			d.ArtifactAuthority = map[bool]string{true: AuthorityPresent, false: AuthorityAbsent}[c12]
			if c9 && c10 {
				d.PathContinuity = ContinuityValid
			}
		} else {
			d.GraphStatus, c9, c10, c11, c12 = GraphAbsent, false, false, false, false
		}
		if resolved && c9 && c10 && c11 && c12 && c13 {
			d.Verdict, d.Proof, d.Reason, d.CompositionStatus = VerdictAllow, ProofValid, "authorized", CompositionValid
		} else if missSk {
			d.Reason = "referenced skill absent"
		} else if missEd {
			d.Reason = "declared capability edge absent"
		} else if !c9 {
			d.Reason = "capability path not contiguous"
		} else if !c10 {
			d.Reason = "capability path endpoint mismatch"
		} else if !c11 {
			d.Reason = "composed effect outside mandate"
		} else if !c12 {
			d.Reason = "composed artifact trajectory outside mandate"
		} else {
			d.Reason = "composition destination outside mandate"
		}
	}
	bf := strconv.FormatBool
	d.Evidence = [8]string{"Composition root mandate=" + d.MandateID + " skills=" + strconv.Itoa(d.SkillCount) + " edges=" + strconv.Itoa(d.EdgeCount), "Requested flow " + d.StartArtifactClass + "|" + d.FinalArtifactClass + " destination=" + d.Destination, "Declared path " + pathStr(action.Steps), "Claims signatures=" + bf(action.ClaimedSignaturesValid) + " individual_allow=" + bf(action.ClaimedIndividualAllow) + " composition_valid=" + bf(action.ClaimedCompositionValid) + " authorized=" + bf(action.ClaimedAuthorized), "Authority graph=" + d.GraphStatus + " continuity=" + d.PathContinuity + " effects=" + d.EffectAuthority + " destination=" + d.DestinationAuthority + " artifacts=" + d.ArtifactAuthority + " composition=" + d.CompositionStatus, "Capability Composition Proof " + d.Proof, "reason " + d.Reason, map[bool]string{true: "ACTION ALLOWED", false: "ACTION DENIED"}[d.Verdict == VerdictAllow]}
	return d
}
