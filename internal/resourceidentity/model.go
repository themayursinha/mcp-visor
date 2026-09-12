// Package resourceidentity implements Resource Identity Continuity
// Proofs (card t_fc04e92b): a WRITE allows only when the held
// authorized identity equals the held effect-time identity and that
// identity is named by a USER-or-higher mandate. Paths and symlink
// claims are ignored. Stdlib-only; independent of proxy/policy/audit
// and of sibling proof packages.
package resourceidentity

const SchemaVersion = 1

const (
	TrustUntrustedExternal = "UNTRUSTED_EXTERNAL"
	TrustTrustedUser       = "TRUSTED_USER"
	TrustTrustedDeveloper  = "TRUSTED_DEVELOPER"
	TrustTrustedSystem     = "TRUSTED_SYSTEM"
)

const (
	AuthorityZero      = "ZERO"
	AuthorityUser      = "USER"
	AuthorityDeveloper = "DEVELOPER"
	AuthoritySystem    = "SYSTEM"
)

const (
	ProofValid   = "VALID"
	ProofInvalid = "INVALID"
	VerdictAllow = "ALLOW"
	VerdictDeny  = "DENY"
)

const (
	IdentityA = "object:workspace-output-result-A"
	IdentityB = "object:outside-mandate-B"
)

// EvaluationRoot is the only authorization trust root.
type EvaluationRoot struct {
	SchemaVersion       int
	IdentityAuthorized  string
	IdentityAtEffect    string
	MandatingPrincipal  string
	MandatingTrustClass string
	MandatedIdentity    string
	PathPermissionValid bool
	EffectClassWrite    bool
}

// ClaimedProof is untrusted.
type ClaimedProof struct {
	Verdict            string
	Proof              string
	Reason             string
	IdentityAuthorized string
	IdentityAtEffect   string
	MandatedIdentity   string
}

// ObservedArtifact is untrusted path and symlink presentation.
type ObservedArtifact struct {
	RequestedPath    string
	ResolvedPath     string
	PresentationName string
	SymlinkTarget    string
	IsSymlink        bool
	VisibleRole      string
	ClaimedProof     ClaimedProof
}

// Decision is the single authorization result.
type Decision struct {
	Verdict  string
	Proof    string
	Reason   string
	Evidence [8]string
}
