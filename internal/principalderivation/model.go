// Package principalderivation implements Principal Derivation Proofs
// (card t_f219c128): localhost, sockets, DNS, and forwarded headers
// do not confer principal authority. Stdlib-only; independent of
// proxy/policy/audit and of sibling proof packages.
package principalderivation

const SchemaVersion = 1

const (
	TransportUnattested = "UNATTESTED"
	TransportAttested   = "ATTESTED"
)

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

// EvaluationRoot is the only authorization trust root.
type EvaluationRoot struct {
	SchemaVersion           int
	TransportTrustClass     string
	TransportPrincipal      string
	SessionIdentityBound    bool
	SessionPrincipal        string
	AgentAuthenticated      bool
	AgentPrincipal          string
	DelegationFromUser      bool
	MandatingPrincipal      string
	MandatingTrustClass     string
	MandatedAgentPrincipal  string
	ToolCapabilityAvailable bool
}

// ClaimedProof is untrusted.
type ClaimedProof struct {
	Verdict         string
	Proof           string
	CallerAuthority string
	Principal       string
	Reason          string
}

// ObservedArtifact is untrusted protocol metadata and claimed identity.
type ObservedArtifact struct {
	Destination      string
	Host             string
	Origin           string
	XForwardedProto  string
	XForwardedHost   string
	DNSAnswer        string
	SocketLocality   string
	TransportKind    string
	ClaimedPrincipal string
	VisibleRole      string
	WebpageBytes     string
	ClaimedProof     ClaimedProof
}

// Decision is the single authorization result. Evidence is generated
// in the same calculation; there is no separate evidence API.
type Decision struct {
	Verdict         string
	Proof           string
	Reason          string
	CallerAuthority string
	Evidence        [8]string
}
