// Package aoepstate is a deterministic in-memory conformance harness for
// AOEP-style persistent-state trajectories. It is not a production
// authorizer, persistence layer, proxy gate, or a claim about deployed
// MCP behavior.
package aoepstate

const SchemaVersion = 1

const (
	KindSensitiveRead    = "SENSITIVE_READ"
	KindEgressSend       = "EGRESS_SEND"
	KindPrivilegedAction = "PRIVILEGED_ACTION"
	KindSideEffect       = "SIDE_EFFECT"
	KindAuthoritySink    = "AUTHORITY_SINK"

	VerdictAllow = "ALLOW"
	VerdictDeny  = "DENY"

	DispositionObserve = "OBSERVE"
	DispositionExecute = "EXECUTE"
	DispositionReplay  = "REPLAY"
	DispositionBlock   = "BLOCK"

	ProofValid    = "VALID"
	ProofInvalid  = "INVALID"
	ProofDisabled = "DISABLED"

	AuthorityDataOnly = "DATA_ONLY"
	AuthorityUser     = "USER"

	ReasonSensitiveSourceObserved              = "sensitive source observed"
	ReasonSensitiveTaintBlocksEgress           = "sensitive taint blocks egress"
	ReasonPermissionEpochCurrent               = "permission epoch current"
	ReasonPermissionEpochStale                 = "permission epoch stale"
	ReasonFirstSideEffectAuthorized            = "first side effect authorized"
	ReasonCompletedResultReplayed              = "completed result replayed"
	ReasonIdempotencyKeyRequired               = "idempotency key required"
	ReasonIdempotencyKeyCollision              = "idempotency key collision"
	ReasonFragmentAuthoritySufficient          = "fragment authority sufficient"
	ReasonUntrustedFragmentCannotAuthorizeSink = "untrusted fragment cannot authorize sink"
	ReasonEnforcementDisabled                  = "enforcement disabled"
	ReasonInvalidRoot                          = "invalid evaluation root"
	ReasonInvalidAction                        = "invalid proposed action"
)

// EvaluationRoot is caller-held fixture state. Authorize does not mutate it.
type EvaluationRoot struct {
	SchemaVersion          int
	EnforcementEnabled     bool
	Taints                 []string
	CurrentPermissionEpoch int
	Completed              []CompletedRecord
	Fragments              []FragmentRecord
}

// CompletedRecord is one caller-held side-effect completion.
type CompletedRecord struct {
	Key           string
	Operation     string
	RequestDigest string
	ResultDigest  string
}

// FragmentRecord is one caller-held fragment-authority registration.
type FragmentRecord struct {
	FragmentID string
	Authority  string
}

// ProposedAction is the normalized request. Claim fields are untrusted.
type ProposedAction struct {
	ActionID          string
	Kind              string
	TaintID           string
	PermissionEpoch   int
	Operation         string
	RequestDigest     string
	IdempotencyKey    string
	RequiredAuthority string
	FragmentIDs       []string

	ClaimedAuthorization string
	ClaimedAuthority     string
	ClaimedCurrentEpoch  int
	ClaimedReplay        bool
	ClaimedResultDigest  string
}

// Decision is the pure evaluation result. Evidence is always eight lines.
type Decision struct {
	ActionID               string
	Kind                   string
	Verdict                string
	Disposition            string
	Proof                  string
	Reason                 string
	MatchedTaint           string
	ActionPermissionEpoch  int
	CurrentPermissionEpoch int
	IdempotencyKey         string
	RecordedOperation      string
	RecordedRequestDigest  string
	ResultDigest           string
	RequiredAuthority      string
	EffectiveAuthority     string
	Evidence               [8]string
}
