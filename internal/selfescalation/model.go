// Package selfescalation implements Self-Escalation Invariant proofs (H43).
package selfescalation

const SchemaVersion = 1

const (
	AuthorityWorkspaceWrite, AuthorityModifySelf                                              = "workspace.write", "authority.modify(self)"
	ProofTypeMetaAuthority, ProofTypeOrdinaryAction                                           = "META_AUTHORITY", "ORDINARY_ACTION"
	DelegationPresent, DelegationAbsent, DelegationInvalid, DelegationDisabled                = "PRESENT", "ABSENT", "INVALID", "DISABLED"
	MetaPresent, MetaMissing, MetaInvalid, MetaDisabled, MetaNotRequired                      = "PRESENT", "MISSING", "INVALID", "DISABLED", "NOT_REQUIRED"
	ReachabilityPresent, ReachabilityAbsent, ReachabilityInvalid, ReachabilityDisabled        = "PRESENT", "ABSENT", "INVALID", "DISABLED"
	AttributionAgent, AttributionInvalid, AttributionDisabled                                 = "AGENT", "INVALID", "DISABLED"
	ProofValid, ProofMissing, ProofInvalid, ProofDisabled                                     = "VALID", "MISSING", "INVALID", "DISABLED"
	VerdictAllow, VerdictDeny                                                                 = "ALLOW", "DENY"
	CanonicalDelegationID, CanonicalChild                                                     = "delegation:confined-agent", "agent:confined"
	SurfaceLoopbackPolicyAPI, SurfaceEnvironment, SurfaceSharedPolicyFile, SurfaceSpoofedHost = "surface:loopback-policy-api", "surface:environment", "surface:shared-policy-file", "surface:spoofed-host"
	CanonicalAttackActionID, LegitimateActionID                                               = "action:self-authority-modification", "action:workspace-write"
	FixtureSampleSize, FixtureSeed                                                            = 8, 43043
)

type ParentDelegation struct {
	DelegationID, ChildPrincipal string
	AllowedAuthorities           []string
}
type MetaAuthorityGrant struct {
	GrantID, GranteePrincipal, Authority, ProofType string
}
type EvaluationRoot struct {
	SchemaVersion        int
	ParentDelegation     ParentDelegation
	MetaAuthorityGrants  []MetaAuthorityGrant
	MetaAuthorityEnabled bool
	ManagementSurfaces   []string
}
type ProposedAction struct {
	ActionID, ActorPrincipal, RequestedAuthority, ManagementSurface  string
	ClaimedHostHeader, ClaimedUserAttribution                        string
	ClaimedDangerFullAccess, ClaimedPolicyRewrite, ClaimedAuthorized bool
}
type Decision struct {
	ActionID, DelegationID, ActorPrincipal, RequestedAuthority, ManagementSurface string
	Verdict, Proof, Reason                                                        string
	DelegationAuthority, MetaAuthority, SurfaceReachability, Attribution          string
	Evidence                                                                      [8]string
}
