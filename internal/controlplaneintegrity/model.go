// Package controlplaneintegrity implements Control-Plane Integrity
// Proofs (card t_aed734fb): a structurally valid mandate and
// conventional policy ALLOW are not authority when any caller-held
// control-plane attestation is unproven or invalid. Stdlib-only;
// independent of proxy/policy/audit/receipt and of sibling packages.
package controlplaneintegrity

const SchemaVersion = 1

const (
	KindIdentityStore    = "identity-store"
	KindPolicyStore      = "policy-store"
	KindExecutionRuntime = "execution-runtime"
	KindResourceRegistry = "resource-registry"
	IntegrityValid       = "VALID"
	IntegrityUnproven    = "UNPROVEN"
	IntegrityInvalid     = "INVALID"
	ProofValid           = "VALID"
	ProofInvalid         = "INVALID"
	ControlPlaneValid    = "VALID"
	ControlPlaneInvalid  = "INVALID"
	VerdictAllow         = "ALLOW"
	VerdictDeny          = "DENY"
)

type CatalogTuple struct{ Kind, Product, Build, Measurement string }

type Catalog struct {
	TrustedBuilds       []CatalogTuple
	KnownCriticalBuilds []CatalogTuple
}

type Attestation struct{ Kind, Product, Build, Measurement string }

type EvaluationRoot struct {
	SchemaVersion            int
	MandateStructurallyValid bool
	PolicyEngineAllow        bool
	IdentityStore            Attestation
	PolicyStore              Attestation
	ExecutionRuntime         Attestation
	ResourceRegistry         Attestation
	Catalog                  Catalog
}

type ClaimedProof struct{ Verdict, Proof, Reason, ControlPlane string }

type ObservedArtifact struct {
	ClaimedPolicyBytes              []byte
	ClaimedPolicyAllow              bool
	ClaimedIdentity, ClaimedPolicy  Attestation
	ClaimedRuntime, ClaimedRegistry Attestation
	VisibleRole                     string
	ClaimedProof                    ClaimedProof
}

type Decision struct {
	Verdict, ControlPlane, Proof, Reason string
	IdentityIntegrity, PolicyIntegrity   string
	RuntimeIntegrity, RegistryIntegrity  string
	Evidence                             [8]string
}

func attest(t CatalogTuple) Attestation {
	return Attestation{Kind: t.Kind, Product: t.Product, Build: t.Build, Measurement: t.Measurement}
}
