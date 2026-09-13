package toolcorrelation

import "strconv"

func structuralOK(r EvaluationRoot) bool {
	if r.SchemaVersion != SchemaVersion || len(r.CapabilityCeilings) == 0 || len(r.ResourceUses) == 0 || len(r.CorrelationEdges) == 0 {
		return false
	}
	cids, uids, epairs := map[string]struct{}{}, map[string]struct{}{}, map[[2]string]struct{}{}
	for _, c := range r.CapabilityCeilings {
		if c.CapabilityID == "" || c.MaxUnits <= 0 {
			return false
		}
		if _, ok := cids[c.CapabilityID]; ok {
			return false
		}
		cids[c.CapabilityID] = struct{}{}
	}
	for _, u := range r.ResourceUses {
		if u.UseID == "" || u.ServerID == "" || u.ToolName == "" || u.CapabilityID == "" || u.Units <= 0 {
			return false
		}
		if _, ok := uids[u.UseID]; ok {
			return false
		}
		uids[u.UseID] = struct{}{}
	}
	for _, e := range r.CorrelationEdges {
		if e.FromUseID == "" || e.ToUseID == "" || e.FromUseID == e.ToUseID {
			return false
		}
		if _, ok := uids[e.FromUseID]; !ok {
			return false
		}
		if _, ok := uids[e.ToUseID]; !ok {
			return false
		}
		k := [2]string{e.FromUseID, e.ToUseID}
		if _, ok := epairs[k]; ok {
			return false
		}
		epairs[k] = struct{}{}
	}
	return true
}
func pathStr(uses []UseReference) string {
	s := ""
	for i, u := range uses {
		if i > 0 {
			s += ">"
		}
		s += u.UseID + "@" + u.ServerID + "/" + u.ToolName
	}
	return s
}

func Authorize(root EvaluationRoot, action ProposedAction) Decision {
	d := Decision{ActionID: action.ActionID, CapabilityID: action.CapabilityID, UseCount: len(action.Uses), Verdict: VerdictDeny, Proof: ProofInvalid, Reason: "invalid evaluation root", GraphStatus: GraphInvalid, TrajectoryStatus: TrajectoryInvalid, CapabilityStatus: CapabilityInvalid, CeilingStatus: CeilingInvalid, UsageStatus: UsageInvalid, CorrelationStatus: CorrelationInvalid}
	switch {
	case !structuralOK(root):
	case action.ActionID == "":
		d.Reason = "action identifier absent"
	case action.CapabilityID == "":
		d.Reason = "capability identifier absent"
	case len(action.Uses) == 0:
		d.Reason = "resource-use trajectory absent"
	case !root.CorrelationEnabled:
		d.Proof, d.Reason, d.GraphStatus, d.TrajectoryStatus, d.CapabilityStatus, d.CeilingStatus, d.UsageStatus, d.CorrelationStatus = ProofDisabled, "tool correlation disabled", GraphDisabled, TrajectoryDisabled, CapabilityDisabled, CeilingDisabled, UsageDisabled, CorrelationDisabled
	default:
		var resolved []ResourceUse
		c5, c6, c7, over := true, true, true, false
		for i, ref := range action.Uses {
			found := false
			for _, u := range root.ResourceUses {
				if ref.UseID != u.UseID || ref.ServerID != u.ServerID || ref.ToolName != u.ToolName {
					continue
				}
				resolved, found = append(resolved, u), true
				if u.CapabilityID != action.CapabilityID {
					c7 = false
				}
				break
			}
			if !found {
				c5, c6, c7 = false, false, false
				break
			}
			if i > 0 {
				ok := false
				for _, e := range root.CorrelationEdges {
					if e.FromUseID == resolved[i-1].UseID && e.ToUseID == resolved[i].UseID {
						ok = true
						break
					}
				}
				c6 = c6 && ok
			}
		}
		ceil, c8 := 0, false
		for _, c := range root.CapabilityCeilings {
			if c.CapabilityID == action.CapabilityID {
				ceil, c8, d.CeilingUnits = c.MaxUnits, true, c.MaxUnits
				break
			}
		}
		if c5 {
			ss, ts, sum, max := map[string]struct{}{}, map[[2]string]struct{}{}, 0, int(^uint(0)>>1)
			for _, u := range resolved {
				ss[u.ServerID], ts[[2]string{u.ServerID, u.ToolName}] = struct{}{}, struct{}{}
				if u.Units > 0 && sum > max-u.Units {
					over = true
					break
				}
				sum += u.Units
			}
			d.ServerCount, d.ToolCount, d.TotalUnits = len(ss), len(ts), sum
		}
		if c5 && c6 {
			d.GraphStatus, d.TrajectoryStatus = GraphPresent, TrajectoryValid
		} else {
			d.GraphStatus = GraphAbsent
		}
		if c5 {
			d.CapabilityStatus = map[bool]string{true: CapabilityPresent, false: CapabilityAbsent}[c7]
		}
		if c5 && c6 && c7 {
			d.CeilingStatus = map[bool]string{true: CeilingPresent, false: CeilingAbsent}[c8]
			if c8 {
				d.UsageStatus = map[bool]string{true: UsageWithin, false: UsageExceeded}[!over && d.TotalUnits <= ceil]
			}
		}
		if c5 && c6 && c7 && c8 && !over && d.TotalUnits <= ceil {
			d.Verdict, d.Proof, d.Reason, d.CorrelationStatus = VerdictAllow, ProofValid, "authorized", CorrelationValid
		} else if !c5 {
			d.Reason = "referenced resource use absent"
		} else if !c6 {
			d.Reason = "correlation edge absent"
		} else if !c7 {
			d.Reason = "trajectory capability mismatch"
		} else if !c8 {
			d.Reason = "capability ceiling absent"
		} else {
			d.Reason = "correlated capability ceiling exceeded"
		}
	}
	bf := strconv.FormatBool
	d.Evidence = [8]string{"Correlation root ceilings=" + strconv.Itoa(len(root.CapabilityCeilings)) + " uses=" + strconv.Itoa(len(root.ResourceUses)) + " edges=" + strconv.Itoa(len(root.CorrelationEdges)), "Requested capability " + d.CapabilityID + " total_units=" + strconv.Itoa(d.TotalUnits) + " ceiling_units=" + strconv.Itoa(d.CeilingUnits), "Requested uses " + pathStr(action.Uses), "Claims per_tool_allow=" + bf(action.ClaimedPerToolAllow) + " server_hop_innocent=" + bf(action.ClaimedServerHopInnocent) + " remaining_quota=" + strconv.Itoa(action.ClaimedRemainingQuota) + " authorized=" + bf(action.ClaimedAuthorized), "Authority graph=" + d.GraphStatus + " trajectory=" + d.TrajectoryStatus + " capability=" + d.CapabilityStatus + " ceiling=" + d.CeilingStatus + " usage=" + d.UsageStatus + " correlation=" + d.CorrelationStatus, "Cross-Tool Correlation Proof " + d.Proof, "reason " + d.Reason, map[bool]string{true: "ACTION ALLOWED", false: "ACTION DENIED"}[d.Verdict == VerdictAllow]}
	return d
}
