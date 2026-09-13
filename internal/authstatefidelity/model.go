// Package authstatefidelity implements Authorization-State Fidelity Proofs (H40).
package authstatefidelity

const SchemaVersion = 1

const (
	EventGrant, EventRevoke, SourceValid, SourceRevoked, SourceAbsent, SourceInvalid = "GRANT", "REVOKE", "VALID", "REVOKED", "ABSENT", "INVALID"
	SourceNotYetEffective, SourceDisabled, PrincipalPresent, PrincipalAbsent         = "NOT_YET_EFFECTIVE", "DISABLED", "PRESENT", "ABSENT"
	PrincipalInvalid, PrincipalDisabled, StateAuthorized, StateUnauthorized          = "INVALID", "DISABLED", "AUTHORIZED", "UNAUTHORIZED"
	StateInvalid, StateDisabled, ProofValid, ProofInvalid, ProofDisabled             = "INVALID", "DISABLED", "VALID", "INVALID", "DISABLED"
	VerdictAllow, VerdictDeny, CanonicalSubjectID, CanonicalPermission               = "ALLOW", "DENY", "agent:worker", "deploy:production"
	CanonicalActionID, CanonicalGrantPrincipal, CanonicalGrantEventID                = "action:deploy-production", "operator:alice", "event:grant-production"
	CanonicalRevokeEventID, LegitimateReadPermission, StagingPermission              = "event:revoke-production", "reports:read", "deploy:staging"
	FixtureSampleSize, FixtureSeed                                                   = 8, 40040
)

type GrantPrincipal struct {
	PrincipalID          string
	GrantablePermissions []string
}
type AuthorizationEvent struct {
	EventID, Kind, PrincipalID, SubjectID, Permission, GrantEventID string
	Tick                                                            int
}
type EvaluationRoot struct {
	SchemaVersion             int
	EventLog                  []AuthorizationEvent
	GrantPrincipals           []GrantPrincipal
	CurrentTick               int
	AuthorizationStateEnabled bool
}
type ProposedAction struct {
	ActionID, SubjectID, Permission, CitedGrantEventID string
	ClaimedMemoryPermission                            bool
	ClaimedGrantPrincipalID                            string
	ClaimedGrantValid, ClaimedProofValid               bool
	ClaimedExactStateValid, ClaimedAuthorized          bool
}
type AuthorizationBinding struct {
	SubjectID, Permission, SourceEventID, PrincipalID string
	GrantTick                                         int
}
type Decision struct {
	ActionID, SubjectID, Permission, CitedGrantEventID, SourcePrincipalID     string
	CurrentTick, EventCount                                                   int
	Verdict, Proof, Reason, SourceEventStatus, PrincipalAuthority, ExactState string
	Evidence                                                                  [8]string
}
