package selfescalation

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
func structuralOK(r EvaluationRoot) bool {
	d := r.ParentDelegation
	if r.SchemaVersion != SchemaVersion || d.DelegationID == "" || d.ChildPrincipal == "" || !uniq(d.AllowedAuthorities) || !uniq(r.ManagementSurfaces) {
		return false
	}
	gids := map[string]struct{}{}
	for _, g := range r.MetaAuthorityGrants {
		if g.GrantID == "" || g.GranteePrincipal == "" || g.Authority == "" || g.ProofType != ProofTypeMetaAuthority && g.ProofType != ProofTypeOrdinaryAction {
			return false
		}
		if _, ok := gids[g.GrantID]; ok {
			return false
		}
		gids[g.GrantID] = struct{}{}
	}
	return true
}
func metaOK(r EvaluationRoot, actor, auth string) bool {
	for _, g := range r.MetaAuthorityGrants {
		if g.GranteePrincipal == actor && g.Authority == auth && g.ProofType == ProofTypeMetaAuthority {
			return true
		}
	}
	return false
}
func none(s string) string {
	if s == "" {
		return "<none>"
	}
	return s
}
func proofLine(p, auth string) string {
	switch p {
	case ProofMissing:
		return "Missing proof " + auth
	case ProofValid:
		return "Authority Proof VALID " + auth
	case ProofDisabled:
		return "Self-Escalation Proof DISABLED " + auth
	default:
		return "Authority Proof INVALID " + auth
	}
}
func reach(ok bool) string {
	return map[bool]string{true: ReachabilityPresent, false: ReachabilityAbsent}[ok]
}

func Authorize(root EvaluationRoot, action ProposedAction) Decision {
	d := Decision{ActionID: action.ActionID, DelegationID: root.ParentDelegation.DelegationID, ActorPrincipal: action.ActorPrincipal, RequestedAuthority: action.RequestedAuthority, ManagementSurface: action.ManagementSurface, Verdict: VerdictDeny, Proof: ProofInvalid, Reason: "invalid evaluation root", DelegationAuthority: DelegationInvalid, MetaAuthority: MetaInvalid, SurfaceReachability: ReachabilityInvalid, Attribution: AttributionInvalid}
	self := action.RequestedAuthority == AuthorityModifySelf
	c1, c2, c3 := action.ActionID != "", action.ActorPrincipal != "", action.RequestedAuthority != ""
	c4 := action.ActorPrincipal == root.ParentDelegation.ChildPrincipal
	c5 := has(root.ParentDelegation.AllowedAuthorities, action.RequestedAuthority)
	granted := metaOK(root, action.ActorPrincipal, action.RequestedAuthority)
	surf := action.ManagementSurface != "" && has(root.ManagementSurfaces, action.ManagementSurface)
	switch {
	case !structuralOK(root):
	case !c1:
		d.Reason = "action identifier absent"
	case !c2:
		d.Reason = "actor principal absent"
	case !c3:
		d.Reason = "requested authority absent"
	case !c4:
		d.Reason = "actor outside parent delegation"
		d.MetaAuthority = map[bool]string{true: MetaMissing, false: MetaNotRequired}[self && root.MetaAuthorityEnabled]
		d.SurfaceReachability = reach(surf)
	case self && !root.MetaAuthorityEnabled:
		d.Proof, d.Reason, d.DelegationAuthority, d.MetaAuthority, d.SurfaceReachability, d.Attribution = ProofDisabled, "meta-authority enforcement disabled", map[bool]string{true: DelegationPresent, false: DelegationAbsent}[c5], MetaDisabled, ReachabilityDisabled, AttributionDisabled
	case self && !granted:
		d.Proof, d.Reason, d.DelegationAuthority, d.MetaAuthority, d.SurfaceReachability, d.Attribution = ProofMissing, "meta-authority proof missing", map[bool]string{true: DelegationPresent, false: DelegationAbsent}[c5], MetaMissing, reach(surf), AttributionAgent
	case !c5:
		d.Reason, d.DelegationAuthority, d.MetaAuthority, d.SurfaceReachability, d.Attribution = "requested authority outside parent delegation", DelegationAbsent, MetaNotRequired, reach(surf), AttributionAgent
	default:
		d.Verdict, d.Proof, d.Reason, d.DelegationAuthority, d.Attribution = VerdictAllow, ProofValid, "authorized", DelegationPresent, AttributionAgent
		d.MetaAuthority, d.SurfaceReachability = map[bool]string{true: MetaPresent, false: MetaNotRequired}[self], reach(surf)
	}
	bf := strconv.FormatBool
	d.Evidence = [8]string{
		"Authority root delegation=" + root.ParentDelegation.DelegationID + " child=" + root.ParentDelegation.ChildPrincipal + " allowed=" + strconv.Itoa(len(root.ParentDelegation.AllowedAuthorities)) + " meta_grants=" + strconv.Itoa(len(root.MetaAuthorityGrants)) + " surfaces=" + strconv.Itoa(len(root.ManagementSurfaces)),
		"Requested action " + action.ActionID + " actor=" + action.ActorPrincipal + " authority=" + action.RequestedAuthority,
		"Management surface " + none(action.ManagementSurface) + " reachability=" + d.SurfaceReachability,
		"Claims host=" + none(action.ClaimedHostHeader) + " attribution=" + none(action.ClaimedUserAttribution) + " danger_full_access=" + bf(action.ClaimedDangerFullAccess) + " policy_rewrite=" + bf(action.ClaimedPolicyRewrite) + " authorized=" + bf(action.ClaimedAuthorized),
		"Authority delegation=" + d.DelegationAuthority + " meta=" + d.MetaAuthority + " attribution=" + d.Attribution,
		proofLine(d.Proof, action.RequestedAuthority),
		"reason " + d.Reason,
		map[bool]string{true: "ACTION ALLOWED", false: "ACTION DENIED"}[d.Verdict == VerdictAllow],
	}
	return d
}
