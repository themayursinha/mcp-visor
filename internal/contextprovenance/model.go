// Package contextprovenance implements Context Provenance Proofs (H47).
package contextprovenance

const SchemaVersion = 1

const (
	TrustUntrusted = "UNTRUSTED"
	TrustUser      = "USER_TRUSTED"
	TrustDeveloper = "DEVELOPER_TRUSTED"
	TrustSystem    = "SYSTEM_TRUSTED"

	ProofValid       = "VALID"
	ProofInvalid     = "INVALID"
	EscalationNone   = "NONE"
	EscalationFound  = "DETECTED"
	Authoritative    = "AUTHORITATIVE"
	NonAuthoritative = "NON-AUTHORITATIVE"
)

type ContextFragment struct {
	FragmentID   string   `json:"fragment_id"`
	Origin       string   `json:"origin"`
	Principal    string   `json:"principal"`
	Trust        string   `json:"trust"`
	Scope        string   `json:"scope"`
	IntroducedAt int64    `json:"introduced_at"`
	DerivedFrom  []string `json:"derived_from"`
}

type EvaluationRoot struct {
	SchemaVersion            int
	CurrentTick              int64
	RequiredInstructionTrust string
	Fragments                []ContextFragment
}

type MessageClaims struct {
	VisibleRole           string
	ReconstructedFromRole string
	ClaimedOrigin         string
	ClaimedPrincipal      string
	ClaimedTrust          string
	ClaimedAuthoritative  bool
}

type CandidateMessage struct {
	FragmentID string
	Content    string
	Claims     MessageClaims
}

type Decision struct {
	Proof                string
	Escalation           string
	InstructionAuthority string
	EffectiveTrust       string
	Reason               string
	Evidence             [8]string
}
