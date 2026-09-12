// Package causalauthority implements Causal Authority Proofs (card
// t_a06e3d7d): a shell effect allows only when the held immediate
// source is the same authorized principal and exact effect as the
// mandate. Untrusted content stays DATA_ONLY. Stdlib-only; independent
// of proxy/policy/audit and of instructionauthority.
package causalauthority

// SchemaVersion is the evaluation-root schema implemented here.
const SchemaVersion = 1

// Authority levels. Roles, claimed proofs, and tool permissions are not authority.
const (
	AuthorityDataOnly  = "DATA_ONLY"
	AuthorityUser      = "USER"
	AuthorityDeveloper = "DEVELOPER"
	AuthoritySystem    = "SYSTEM"
)

// Trust classes. Unknown values are invalid input and DENY, not DATA_ONLY.
const (
	TrustUntrustedExternalContent = "UNTRUSTED_EXTERNAL_CONTENT"
	TrustTrustedUser              = "TRUSTED_USER"
	TrustTrustedDeveloper         = "TRUSTED_DEVELOPER"
	TrustTrustedSystem            = "TRUSTED_SYSTEM"
)

// EffectShellExecution is the only consequential effect this slice authorizes.
const EffectShellExecution = "SHELL_EXECUTION"

const (
	VerdictAllow = "ALLOW"
	VerdictDeny  = "DENY"
)

const (
	ProofValid   = "VALID"
	ProofInvalid = "INVALID"
)

// EvaluationRoot is the only authorization trust root.
type EvaluationRoot struct {
	SchemaVersion             int
	MandateText               string
	MandatingPrincipal        string
	MandatingTrustClass       string
	MandatedEffect            string
	ImmediateSourcePrincipal  string
	ImmediateSourceTrustClass string
	RequestedEffect           string
	ToolPermissionValid       bool
	CommandSyntacticallyValid bool
	AgentAuthenticated        bool
}

// ClaimedProof is untrusted; Authorize must not read it.
type ClaimedProof struct {
	Verdict           string
	Proof             string
	Reason            string
	Authority         string
	MandateDerivation string
	Principal         string
	TrustClass        string
	InstructionSource string
}

// ObservedArtifact is untrusted bytes. Authorize must ignore every field.
type ObservedArtifact struct {
	Content      string
	VisibleRole  string
	ClaimedProof ClaimedProof
}

// Decision is the single authorization result. Evidence is generated
// during the same calculation; there is no separate evidence API.
type Decision struct {
	Verdict  string
	Proof    string
	Reason   string
	Evidence [8]string
}
