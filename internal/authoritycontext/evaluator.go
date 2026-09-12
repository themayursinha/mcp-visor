package authoritycontext

const (
	reasonInvalidRoot     = "invalid evaluation root"
	reasonActionAbsent    = "action identifier absent"
	reasonUnsupported     = "unsupported effect class"
	reasonReqPrincipal    = "requested principal absent"
	reasonReqDomain       = "requested domain absent"
	reasonObsPrincipal    = "observed principal absent"
	reasonObsDomain       = "observed domain absent"
	reasonDisabled        = "authority context disabled"
	reasonHeldPrincipal   = "requested principal does not match held principal"
	reasonObsReqPrincipal = "observed principal does not match requested principal"
	reasonObsReqDomain    = "observed domain does not match requested domain"
	reasonOutsideMandate  = "observed domain outside mandate"
	reasonHeldContext     = "observed domain does not match held execution context"
	reasonAuthorized      = "authorized"
)

func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func uniqueFilled(xs []string) bool {
	if len(xs) == 0 {
		return false
	}
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
	return true
}
func pick(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func structuralOK(r EvaluationRoot) bool {
	m := r.Mandate
	return r.SchemaVersion == SchemaVersion && r.HeldPrincipalID != "" && r.HeldExecutionDomain != "" &&
		m.MandateID != "" && m.PrincipalID != "" && m.PrincipalID == r.HeldPrincipalID && uniqueFilled(m.AuthorizedDomains)
}

func EvaluateAuthorityContextIntegrity(root EvaluationRoot, action ProposedAction) Decision {
	d := Decision{
		ActionID: action.ActionID, EffectClass: action.EffectClass, MandateID: root.Mandate.MandateID,
		HeldPrincipalID: root.HeldPrincipalID, RequestedPrincipalID: action.RequestedPrincipalID, RequestedDomain: action.RequestedDomain,
		ObservedPrincipalID: action.ObservedPrincipalID, ObservedDomain: action.ObservedDomain,
		Verdict: VerdictDeny, Proof: ProofInvalid, Reason: reasonInvalidRoot,
		PrincipalBinding: BindingInvalid, DomainAuthority: AuthorityInvalid, ContextBinding: BindingInvalid,
	}
	c1, c2, c3, c4 := action.ActionID != "", action.EffectClass == EffectExecute, action.RequestedPrincipalID != "", action.RequestedDomain != ""
	c5, c6 := action.ObservedPrincipalID != "", action.ObservedDomain != ""
	switch {
	case !structuralOK(root):
	case !c1:
		d.Reason = reasonActionAbsent
	case !c2:
		d.Reason = reasonUnsupported
	case !c3:
		d.Reason = reasonReqPrincipal
	case !c4:
		d.Reason = reasonReqDomain
	case !c5:
		d.Reason = reasonObsPrincipal
	case !c6:
		d.Reason = reasonObsDomain
	case !root.AuthorityContextEnabled:
		d.Verdict, d.Proof, d.Reason = VerdictDeny, ProofDisabled, reasonDisabled
		d.PrincipalBinding, d.DomainAuthority, d.ContextBinding = BindingDisabled, AuthorityDisabled, BindingDisabled
	default:
		c8 := action.RequestedPrincipalID == root.HeldPrincipalID
		c9 := action.ObservedPrincipalID == action.RequestedPrincipalID
		c10 := action.ObservedDomain == action.RequestedDomain
		c11 := has(root.Mandate.AuthorizedDomains, action.ObservedDomain)
		c12 := action.ObservedDomain == root.HeldExecutionDomain
		d.PrincipalBinding = pick(c8 && c9, BindingValid, BindingInvalid)
		d.DomainAuthority = pick(c11, AuthorityPresent, AuthorityAbsent)
		d.ContextBinding = pick(c10 && c12, BindingValid, BindingInvalid)
		switch {
		case !c8:
			d.Reason = reasonHeldPrincipal
		case !c9:
			d.Reason = reasonObsReqPrincipal
		case !c10:
			d.Reason = reasonObsReqDomain
		case !c11:
			d.Reason = reasonOutsideMandate
		case !c12:
			d.Reason = reasonHeldContext
		default:
			d.Verdict, d.Proof, d.Reason = VerdictAllow, ProofValid, reasonAuthorized
		}
	}
	effect := "CONTEXT EFFECT DENIED"
	if d.Verdict == VerdictAllow {
		effect = "CONTEXT EFFECT ALLOWED"
	}
	d.Evidence = [8]string{
		"Mandate " + d.MandateID, "Held principal " + d.HeldPrincipalID,
		"Requested context " + d.RequestedPrincipalID + "@" + d.RequestedDomain,
		"Observed context " + d.ObservedPrincipalID + "@" + d.ObservedDomain,
		"Principal binding " + d.PrincipalBinding, "Observed-domain authority " + d.DomainAuthority,
		"Authority-Context Integrity Proof " + d.Proof, effect,
	}
	return d
}

func Authorize(root EvaluationRoot, action ProposedAction) Decision {
	return EvaluateAuthorityContextIntegrity(root, action)
}
