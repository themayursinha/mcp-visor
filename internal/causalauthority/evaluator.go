package causalauthority

const (
	reasonInvalidRoot     = "invalid evaluation root"
	reasonUnauthenticated = "agent unauthenticated"
	reasonToolPermission  = "tool permission invalid"
	reasonCommandSyntax   = "command syntax invalid"
	reasonCausalInvalid   = "causal authority proof invalid"
	reasonAuthorized      = "authorized"
)

func authorityForTrust(class string) (string, bool) {
	switch class {
	case TrustUntrustedExternalContent:
		return AuthorityDataOnly, true
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

func atLeastUser(authority string) bool {
	switch authority {
	case AuthorityUser, AuthorityDeveloper, AuthoritySystem:
		return true
	default:
		return false
	}
}

func EvaluateCausalProof(root EvaluationRoot) Decision {
	d := Decision{Verdict: VerdictDeny, Proof: ProofInvalid, Reason: reasonInvalidRoot}
	if root.SchemaVersion != SchemaVersion ||
		root.MandateText == "" || root.MandatingPrincipal == "" || root.ImmediateSourcePrincipal == "" {
		return finish(root, d, false, false)
	}
	if root.MandatedEffect == "" || root.RequestedEffect == "" {
		return finish(root, d, false, false)
	}
	mandAuth, mandOK := authorityForTrust(root.MandatingTrustClass)
	srcAuth, srcOK := authorityForTrust(root.ImmediateSourceTrustClass)
	if !mandOK || !srcOK {
		return finish(root, d, false, false)
	}
	causalValid := atLeastUser(mandAuth) &&
		root.MandatedEffect == EffectShellExecution &&
		root.RequestedEffect == root.MandatedEffect &&
		root.ImmediateSourcePrincipal == root.MandatingPrincipal &&
		atLeastUser(srcAuth)
	if causalValid {
		d.Proof = ProofValid
	}
	if !root.AgentAuthenticated {
		d.Reason = reasonUnauthenticated
		return finish(root, d, true, causalValid)
	}
	if !root.ToolPermissionValid {
		d.Reason = reasonToolPermission
		return finish(root, d, true, causalValid)
	}
	if !root.CommandSyntacticallyValid {
		d.Reason = reasonCommandSyntax
		return finish(root, d, true, causalValid)
	}
	if !causalValid {
		d.Reason = reasonCausalInvalid
		return finish(root, d, true, false)
	}
	d.Verdict = VerdictAllow
	d.Reason = reasonAuthorized
	return finish(root, d, true, true)
}

// Authorize returns EvaluateCausalProof(root) and ignores the artifact.
func Authorize(root EvaluationRoot, _ ObservedArtifact) Decision {
	return EvaluateCausalProof(root)
}

func finish(root EvaluationRoot, d Decision, structuralOK, causalValid bool) Decision {
	d.Evidence = evidence(root, structuralOK, causalValid, d.Verdict, d.Proof)
	return d
}

func evidence(root EvaluationRoot, structuralOK, causalValid bool, verdict, proof string) [8]string {
	tool, syntax, authn := "INVALID", "NO", "NO"
	if root.ToolPermissionValid {
		tool = "VALID"
	}
	if root.CommandSyntacticallyValid {
		syntax = "YES"
	}
	if root.AgentAuthenticated {
		authn = "YES"
	}
	shell, derived := "NO", "ABSENT"
	if causalValid {
		shell, derived = "YES", "PRESENT"
	}
	if !structuralOK {
		proof, verdict, shell, derived = ProofInvalid, VerdictDeny, "NO", "ABSENT"
	}
	return [8]string{
		"Tool permission " + tool,
		"Command syntactically valid " + syntax,
		"Agent authenticated " + authn,
		"Instruction source " + instructionSource(root, structuralOK),
		"Source authorized to invoke shell " + shell,
		"Mandate-derived reason for shell execution " + derived,
		"Causal Authority Proof " + proof,
		"Execution " + verdict,
	}
}

func instructionSource(root EvaluationRoot, structuralOK bool) string {
	if !structuralOK {
		return "untrusted external content"
	}
	switch root.ImmediateSourceTrustClass {
	case TrustUntrustedExternalContent:
		return "untrusted external content"
	case TrustTrustedUser:
		return "trusted user mandate"
	case TrustTrustedDeveloper:
		return "trusted developer mandate"
	case TrustTrustedSystem:
		return "trusted system mandate"
	default:
		return "untrusted external content"
	}
}
