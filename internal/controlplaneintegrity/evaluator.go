package controlplaneintegrity

const (
	reasonInvalidRoot      = "invalid evaluation root"
	reasonIdentityInvalid  = "identity-store integrity invalid"
	reasonIdentityUnproven = "identity-store integrity unproven"
	reasonPolicyInvalid    = "policy-store integrity invalid"
	reasonPolicyUnproven   = "policy-store integrity unproven"
	reasonRuntimeInvalid   = "execution-runtime integrity invalid"
	reasonRuntimeUnproven  = "execution-runtime integrity unproven"
	reasonRegistryInvalid  = "resource-registry integrity invalid"
	reasonRegistryUnproven = "resource-registry integrity unproven"
	reasonMandateInvalid   = "mandate structurally invalid"
	reasonPolicyDenied     = "conventional policy denied"
	reasonAuthorized       = "authorized"
)

func (a Attestation) tuple() CatalogTuple { return CatalogTuple(a) }

func filled(t CatalogTuple) bool {
	return t.Kind != "" && t.Product != "" && t.Build != "" && t.Measurement != ""
}

func catalogOK(c Catalog) bool {
	trusted, critical := map[CatalogTuple]struct{}{}, map[CatalogTuple]struct{}{}
	for _, t := range c.TrustedBuilds {
		if !filled(t) {
			return false
		}
		if _, dup := trusted[t]; dup {
			return false
		}
		trusted[t] = struct{}{}
	}
	for _, t := range c.KnownCriticalBuilds {
		if !filled(t) {
			return false
		}
		if _, dup := critical[t]; dup {
			return false
		}
		if _, both := trusted[t]; both {
			return false
		}
		critical[t] = struct{}{}
	}
	return true
}

func classify(a Attestation, want string, c Catalog) string {
	if !filled(a.tuple()) || a.Kind != want {
		return IntegrityInvalid
	}
	t := a.tuple()
	for _, k := range c.KnownCriticalBuilds {
		if k == t {
			return IntegrityUnproven
		}
	}
	for _, k := range c.TrustedBuilds {
		if k == t {
			return IntegrityValid
		}
	}
	return IntegrityUnproven
}

func EvaluateControlPlaneIntegrityProof(root EvaluationRoot) Decision {
	d := Decision{
		Verdict: VerdictDeny, ControlPlane: ControlPlaneInvalid, Proof: ProofInvalid,
		Reason: reasonInvalidRoot, IdentityIntegrity: IntegrityInvalid,
		PolicyIntegrity: IntegrityInvalid, RuntimeIntegrity: IntegrityInvalid,
		RegistryIntegrity: IntegrityInvalid,
	}
	if root.SchemaVersion != SchemaVersion || !catalogOK(root.Catalog) {
		return finish(root, d)
	}
	id := classify(root.IdentityStore, KindIdentityStore, root.Catalog)
	pol := classify(root.PolicyStore, KindPolicyStore, root.Catalog)
	rt := classify(root.ExecutionRuntime, KindExecutionRuntime, root.Catalog)
	reg := classify(root.ResourceRegistry, KindResourceRegistry, root.Catalog)
	d.IdentityIntegrity, d.PolicyIntegrity, d.RuntimeIntegrity, d.RegistryIntegrity = id, pol, rt, reg
	if id == IntegrityValid && pol == IntegrityValid && rt == IntegrityValid && reg == IntegrityValid {
		d.ControlPlane, d.Proof = ControlPlaneValid, ProofValid
	}
	switch {
	case id == IntegrityInvalid:
		d.Reason = reasonIdentityInvalid
	case id == IntegrityUnproven:
		d.Reason = reasonIdentityUnproven
	case pol == IntegrityInvalid:
		d.Reason = reasonPolicyInvalid
	case pol == IntegrityUnproven:
		d.Reason = reasonPolicyUnproven
	case rt == IntegrityInvalid:
		d.Reason = reasonRuntimeInvalid
	case rt == IntegrityUnproven:
		d.Reason = reasonRuntimeUnproven
	case reg == IntegrityInvalid:
		d.Reason = reasonRegistryInvalid
	case reg == IntegrityUnproven:
		d.Reason = reasonRegistryUnproven
	case !root.MandateStructurallyValid:
		d.Reason = reasonMandateInvalid
	case !root.PolicyEngineAllow:
		d.Reason = reasonPolicyDenied
	default:
		d.Verdict, d.Reason = VerdictAllow, reasonAuthorized
	}
	return finish(root, d)
}

func Authorize(root EvaluationRoot, _ ObservedArtifact) Decision {
	return EvaluateControlPlaneIntegrityProof(root)
}

func finish(root EvaluationRoot, d Decision) Decision {
	d.Evidence = evidence(root, d)
	return d
}

func evidence(root EvaluationRoot, d Decision) [8]string {
	mandate, policy := "Mandate structurally INVALID", "Conventional policy result DENY"
	if root.MandateStructurallyValid {
		mandate = "Mandate structurally VALID"
	}
	if root.PolicyEngineAllow {
		policy = "Conventional policy result ALLOW"
	}
	effect := "CONTROL-PLANE EFFECT DENIED"
	if d.Verdict == VerdictAllow {
		effect = "CONTROL-PLANE EFFECT ALLOWED"
	}
	return [8]string{
		mandate, policy,
		"identity-store integrity " + d.IdentityIntegrity,
		"policy-store integrity " + d.PolicyIntegrity,
		"execution-runtime integrity " + d.RuntimeIntegrity,
		"resource-registry integrity " + d.RegistryIntegrity,
		"Control-Plane Integrity Proof " + d.Proof, effect,
	}
}
