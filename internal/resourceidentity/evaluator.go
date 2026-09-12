package resourceidentity

const (
	reasonInvalidRoot      = "invalid evaluation root"
	reasonAuthorizedAbsent = "authorized resource identity absent"
	reasonEffectAbsent     = "effect-time resource identity absent"
	reasonContinuity       = "identity continuity failed"
	reasonMandatingAbsent  = "mandating principal absent"
	reasonMandatedAbsent   = "mandated resource identity absent"
	reasonMandatingLacks   = "mandating principal lacks authority"
	reasonMandateMissing   = "mandate for effect-time identity absent"
	reasonPathPermission   = "path permission invalid"
	reasonNotWrite         = "effect class is not WRITE"
	reasonAuthorized       = "authorized"
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

func EvaluateResourceIdentityProof(root EvaluationRoot) Decision {
	d := Decision{Verdict: VerdictDeny, Proof: ProofInvalid, Reason: reasonInvalidRoot}
	if root.SchemaVersion != SchemaVersion {
		return finish(root, d, false, false)
	}
	mandAuth, mandOK := authorityForTrust(root.MandatingTrustClass)
	if !mandOK {
		return finish(root, d, false, false)
	}
	c1 := root.IdentityAuthorized != ""
	c2 := root.IdentityAtEffect != ""
	c3 := root.IdentityAuthorized == root.IdentityAtEffect
	c4 := root.MandatingPrincipal != ""
	c5 := root.MandatedIdentity != ""
	c6 := atLeastUser(mandAuth)
	c7 := root.MandatedIdentity == root.IdentityAtEffect
	proofValid := c1 && c2 && c3 && c4 && c5 && c6 && c7
	if proofValid {
		d.Proof = ProofValid
	}
	switch {
	case !c1:
		d.Reason = reasonAuthorizedAbsent
	case !c2:
		d.Reason = reasonEffectAbsent
	case !c3:
		d.Reason = reasonContinuity
	case !c4:
		d.Reason = reasonMandatingAbsent
	case !c5:
		d.Reason = reasonMandatedAbsent
	case !c6:
		d.Reason = reasonMandatingLacks
	case !c7:
		d.Reason = reasonMandateMissing
	case !root.PathPermissionValid:
		d.Reason = reasonPathPermission
	case !root.EffectClassWrite:
		d.Reason = reasonNotWrite
	default:
		d.Verdict = VerdictAllow
		d.Reason = reasonAuthorized
	}
	return finish(root, d, true, proofValid)
}

func Authorize(root EvaluationRoot, _ ObservedArtifact) Decision {
	return EvaluateResourceIdentityProof(root)
}

func finish(root EvaluationRoot, d Decision, structuralOK, proofValid bool) Decision {
	d.Evidence = evidence(root, structuralOK, proofValid, d)
	return d
}

func evidence(root EvaluationRoot, structuralOK, proofValid bool, d Decision) [8]string {
	path := "Path permission INVALID"
	if root.PathPermissionValid {
		path = "Path permission VALID"
	}
	effect := "Effect class NOT WRITE"
	if root.EffectClassWrite {
		effect = "Effect class WRITE"
	}
	cont := "Identity continuity FAILED"
	if structuralOK && root.IdentityAuthorized != "" && root.IdentityAuthorized == root.IdentityAtEffect {
		cont = "Identity continuity PRESERVED"
	}
	mand := "Mandate for effect-time identity ABSENT"
	if structuralOK && root.MandatedIdentity != "" && root.MandatedIdentity == root.IdentityAtEffect {
		mand = "Mandate for effect-time identity PRESENT"
	}
	verdict := "WRITE DENIED"
	if d.Verdict == VerdictAllow {
		verdict = "WRITE ALLOWED"
	}
	proof := "Resource Identity Proof " + d.Proof
	if !structuralOK {
		proof, verdict = "Resource Identity Proof INVALID", "WRITE DENIED"
	}
	return [8]string{
		path, effect,
		"Authorized resource identity " + root.IdentityAuthorized,
		"Effect-time resource identity " + root.IdentityAtEffect,
		cont, mand, proof, verdict,
	}
}
