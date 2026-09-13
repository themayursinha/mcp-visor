// Package hosttransitivity implements Non-Transitive Host Authority Proofs (H39).
package hosttransitivity

const SchemaVersion = 1

const (
	EffectTransfer, EffectCredentialRead, EffectRemoteExec          = "TRANSFER", "CREDENTIAL_READ", "REMOTE_EXEC"
	EffectBulkEgress, EffectPackageInstall                          = "BULK_EGRESS", "PACKAGE_INSTALL"
	EffectPersistentListener, EffectReplicaBootstrap                = "PERSISTENT_LISTENER", "REPLICA_BOOTSTRAP"
	BindingValid, ProofValid, AuthorityPresent, PathPresent         = "VALID", "VALID", "PRESENT", "PRESENT"
	BindingInvalid, ProofInvalid, AuthorityInvalid, PathInvalid     = "INVALID", "INVALID", "INVALID", "INVALID"
	BindingDisabled, ProofDisabled, AuthorityDisabled, PathDisabled = "DISABLED", "DISABLED", "DISABLED", "DISABLED"
	AuthorityAbsent, PathAbsent                                     = "ABSENT", "ABSENT"
	PathNotApplicable                                               = "NOT_APPLICABLE"
	VerdictAllow, VerdictDeny                                       = "ALLOW", "DENY"
	OriginalHostID, ReplicaHostID                                   = "host-origin", "host-replica"
	OriginalPrincipalID, ReplicaPrincipalID                         = "principal-a", "replica-b"
	OriginalDomain, ReplicaDomain                                   = "domain-origin", "domain-replica"
	OriginalGrantID, ReplicaGrantID, TransferGrantID                = "grant:principal-a:host-origin", "grant:replica-b:host-replica", "grant:declared-transfer"
)

type HostGrant struct {
	GrantID, PrincipalID, BoundHostID, BoundExecutionDomain             string
	DeclaredHosts, CredentialReadPaths, BulkEgressPaths                 []string
	AllowPackageInstall, AllowPersistentListener, AllowReplicaBootstrap bool
}

type EvaluationRoot struct {
	SchemaVersion                                    int
	HeldPrincipalID, HeldHostID, HeldExecutionDomain string
	Grant                                            HostGrant
	HostAuthorityEnabled                             bool
}

type ProposedAction struct {
	ActionID, EffectClass                                                          string
	RequestedPrincipalID, RequestedHostID, RequestedExecutionDomain                string
	ObservedPrincipalID, ObservedHostID, ObservedExecutionDomain                   string
	TargetHostID, ResourcePath, EgressPath                                         string
	ClaimedInheritedGrantID, ClaimedReplicaPrincipalID                             string
	ClaimedHostAuthorized, ClaimedGrantValid, ClaimedProofValid, ClaimedAuthorized bool
}

type Decision struct {
	ActionID, EffectClass, GrantID                                       string
	HeldPrincipalID, HeldHostID, HeldExecutionDomain                     string
	RequestedPrincipalID, RequestedHostID, RequestedExecutionDomain      string
	ObservedPrincipalID, ObservedHostID, ObservedExecutionDomain         string
	TargetHostID                                                         string
	Verdict, Proof, Reason                                               string
	LocalGrantBinding, TargetHostAuthority, PathAuthority, EdgeAuthority string
	Evidence                                                             [8]string
}
