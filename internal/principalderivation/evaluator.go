package principalderivation

const (
	reasonInvalidRoot         = "invalid evaluation root"
	reasonTransportUnattested = "transport identity unattested"
	reasonTransportAbsent     = "transport principal absent"
	reasonSessionUnbound      = "session identity unbound"
	reasonTransportSession    = "transport and session principals differ"
	reasonUnauthenticated     = "MCP principal unauthenticated"
	reasonSessionAgent        = "session and agent principals differ"
	reasonNoDelegation        = "delegation from user absent"
	reasonMandatingAbsent     = "mandating principal absent"
	reasonMandatingLacks      = "mandating principal lacks authority"
	reasonMandateTarget       = "mandate targets another principal"
	reasonToolUnavailable     = "tool capability unavailable"
	reasonAuthorized          = "authorized"
)

func authorityForTrust(class string) (string, bool) {
	switch class {
	case TrustUntrustedExternal:
		return AuthorityZero, true
	case TrustTrustedUser:
		return AuthorityUser, true
	case TrustTrustedDeveloper:
		return AuthorityDeveloper, true
	case TrustTrustedSystem:
		return AuthoritySystem, true
	default:
		return "", false
	}
}

func atLeastUser(a string) bool {
	return a == AuthorityUser || a == AuthorityDeveloper || a == AuthoritySystem
}

func EvaluatePrincipalDerivationProof(root EvaluationRoot) Decision {
	d := Decision{Verdict: VerdictDeny, Proof: ProofInvalid, CallerAuthority: AuthorityZero, Reason: reasonInvalidRoot}
	if root.SchemaVersion != SchemaVersion || (root.TransportTrustClass != TransportUnattested && root.TransportTrustClass != TransportAttested) {
		return finish(root, d, false, false)
	}
	mandAuth, mandOK := authorityForTrust(root.MandatingTrustClass)
	if !mandOK {
		return finish(root, d, false, false)
	}
	c1 := root.TransportTrustClass == TransportAttested
	c2 := root.TransportPrincipal != ""
	c3 := root.SessionIdentityBound
	c4 := root.SessionPrincipal != "" && root.SessionPrincipal == root.TransportPrincipal
	c5 := root.AgentAuthenticated
	c6 := root.AgentPrincipal != "" && root.AgentPrincipal == root.SessionPrincipal
	c7 := root.DelegationFromUser
	c8 := root.MandatingPrincipal != ""
	c9 := atLeastUser(mandAuth)
	c10 := root.MandatedAgentPrincipal != "" && root.MandatedAgentPrincipal == root.AgentPrincipal
	proofValid := c1 && c2 && c3 && c4 && c5 && c6 && c7 && c8 && c9 && c10
	if proofValid {
		d.Proof = ProofValid
		d.CallerAuthority = mandAuth
	}
	switch {
	case !c1:
		d.Reason = reasonTransportUnattested
	case !c2:
		d.Reason = reasonTransportAbsent
	case !c3:
		d.Reason = reasonSessionUnbound
	case !c4:
		d.Reason = reasonTransportSession
	case !c5:
		d.Reason = reasonUnauthenticated
	case !c6:
		d.Reason = reasonSessionAgent
	case !c7:
		d.Reason = reasonNoDelegation
	case !c8:
		d.Reason = reasonMandatingAbsent
	case !c9:
		d.Reason = reasonMandatingLacks
	case !c10:
		d.Reason = reasonMandateTarget
	case !root.ToolCapabilityAvailable:
		d.Reason = reasonToolUnavailable
	default:
		d.Verdict = VerdictAllow
		d.Reason = reasonAuthorized
	}
	return finish(root, d, true, proofValid)
}

func Authorize(root EvaluationRoot, _ ObservedArtifact) Decision {
	return EvaluatePrincipalDerivationProof(root)
}

func finish(root EvaluationRoot, d Decision, structuralOK, proofValid bool) Decision {
	d.Evidence = evidence(root, structuralOK, proofValid, d)
	return d
}

func evidence(root EvaluationRoot, structuralOK, proofValid bool, d Decision) [8]string {
	t := "Transport identity UNATTESTED"
	if structuralOK && root.TransportTrustClass == TransportAttested {
		t = "Transport identity ATTESTED"
		if root.TransportPrincipal != "" {
			t += " " + root.TransportPrincipal
		}
	}
	sess := "Transport identity -> session identity DENIED (session identity ABSENT)"
	sessionOK := structuralOK && root.TransportTrustClass == TransportAttested && root.SessionIdentityBound &&
		root.SessionPrincipal != "" && root.SessionPrincipal == root.TransportPrincipal
	if sessionOK {
		sess = "Transport identity -> session identity JUSTIFIED " + root.SessionPrincipal
	}
	agent := "Session identity -> agent identity DENIED (authenticated MCP principal ABSENT)"
	if sessionOK && root.AgentAuthenticated && root.AgentPrincipal != "" && root.AgentPrincipal == root.SessionPrincipal {
		agent = "Session identity -> agent identity JUSTIFIED " + root.AgentPrincipal
	}
	mand := "Agent identity -> mandate DENIED (delegation from user ABSENT)"
	if proofValid {
		mand = "Agent identity -> mandate JUSTIFIED " + root.MandatingPrincipal + "=>" + root.AgentPrincipal
	}
	tool := "Tool capability UNAVAILABLE"
	if root.ToolCapabilityAvailable {
		tool = "Tool capability AVAILABLE"
	}
	auth := "Caller authority " + d.CallerAuthority
	proof := "Principal Derivation Proof " + d.Proof
	req := "Request " + d.Verdict
	if !structuralOK {
		auth, proof, req = "Caller authority ZERO", "Principal Derivation Proof INVALID", "Request DENY"
	}
	return [8]string{t, sess, agent, mand, tool, auth, proof, req}
}
