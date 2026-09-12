// Package authoritycontext implements Authority-Context Integrity
// Proofs (card t_92d4ec67 / H38): one principal's execution context
// is not inherited by another. Stdlib-only; independent of
// proxy/policy/audit/receipt and sibling packages.
package authoritycontext

const SchemaVersion = 1

const (
	EffectExecute     = "EXECUTE"
	BindingValid      = "VALID"
	BindingInvalid    = "INVALID"
	BindingDisabled   = "DISABLED"
	AuthorityPresent  = "PRESENT"
	AuthorityAbsent   = "ABSENT"
	AuthorityInvalid  = "INVALID"
	AuthorityDisabled = "DISABLED"
	ProofValid        = "VALID"
	ProofInvalid      = "INVALID"
	ProofDisabled     = "DISABLED"
	VerdictAllow      = "ALLOW"
	VerdictDeny       = "DENY"
	AdminPrincipalID  = "admin-agent"
	CoderPrincipalID  = "coder-agent"
	WebPrincipalID    = "web-agent"
	AdminDomain       = "host"
	CoderDomain       = "docker-coder"
	WebDomain         = "workspace-web"
	AdminMandateID    = "mandate:admin-agent"
	CoderMandateID    = "mandate:coder-agent"
	WebMandateID      = "mandate:web-agent"
)

type AuthorityMandate struct {
	MandateID, PrincipalID string
	AuthorizedDomains      []string
}

type EvaluationRoot struct {
	SchemaVersion                        int
	HeldPrincipalID, HeldExecutionDomain string
	Mandate                              AuthorityMandate
	AuthorityContextEnabled              bool
}

type ProposedAction struct {
	ActionID, EffectClass                               string
	RequestedPrincipalID, RequestedDomain               string
	ObservedPrincipalID, ObservedDomain                 string
	ClaimedPrincipalID, ClaimedDomain                   string
	ClaimedInheritedPrincipalID, ClaimedInheritedDomain string
	ClaimedContextValid, ClaimedProofValid              bool
	ClaimedAuthorized, ClaimedCachedInitialization      bool
}

type Decision struct {
	ActionID, EffectClass, MandateID, HeldPrincipalID string
	RequestedPrincipalID, RequestedDomain             string
	ObservedPrincipalID, ObservedDomain               string
	Verdict, Proof, Reason                            string
	PrincipalBinding, DomainAuthority, ContextBinding string
	Evidence                                          [8]string
}
