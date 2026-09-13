// Package swarmbudget implements Swarm Authority Budget Proofs
// (card t_1a10b32c, extension t_01b96769): swarm intent is not
// authority. Stdlib-only; independent of proxy/policy/audit/receipt
// and sibling packages.
package swarmbudget

const SchemaVersion = 2

const (
	EffectTargetAccess       = "TARGET_ACCESS"
	EffectCredentialDiscover = "CREDENTIAL_DISCOVER"
	EffectCredentialHarvest  = "CREDENTIAL_HARVEST" // legacy alias; evaluated as DISCOVER
	EffectCredentialUse      = "CREDENTIAL_USE"
	EffectDomainEscalation   = "DOMAIN_ESCALATION"
	AuthorityPresent         = "PRESENT"
	AuthorityAbsent          = "ABSENT"
	BudgetWithin             = "WITHIN"
	BudgetExhausted          = "EXHAUSTED"
	BudgetNA                 = "NOT_APPLICABLE"
	BudgetDisabled           = "DISABLED"
	BudgetInvalid            = "INVALID"
	ProofValid               = "VALID"
	ProofInvalid             = "INVALID"
	ProofDisabled            = "DISABLED"
	VerdictAllow             = "ALLOW"
	VerdictDeny              = "DENY"
	CampaignID               = "campaign:swarm-budget-demo"
	OriginCampaignControl    = "campaign-control-plane"
	OriginVictimCloud        = "victim-cloud-network"
)

type CampaignBudget struct {
	MaxTargets, MaxConcurrentPrincipals, CredentialDiscoveryLimit, CredentialUseLimit, NewTargetAuthorizationLimit int
	DomainEscalationRequiresApproval                                                                               bool
	AuthorizedTargets, ApprovedOrigins                                                                             []string
	BudgetEnabled                                                                                                  bool
}

type CampaignState struct {
	AdmittedTargets, InFlightPrincipals, DiscoveredCredentialIDs, UsedCredentialIDs, DomainEscalationApprovedTargets []string
	Tick, AuthorizationWindowTick, NewTargetAuthorizationsInWindow                                                   int
}

type EvaluationRoot struct {
	SchemaVersion int
	CampaignID    string
	Budget        CampaignBudget
	State         CampaignState
}

type ProposedAction struct {
	WorkerID, Origin, TargetID, EffectClass, CredentialID, ClaimedInstruction string
	ClaimedIgnoreBudget, ClaimedHostAuthorized                                bool
	ClaimedConcurrentOK, ClaimedExternalApproval                              bool
}

type Decision struct {
	CampaignID, WorkerID, Origin, TargetID, EffectClass, CredentialID string
	Verdict, Proof, Reason                                            string
	OriginAuthority, TargetAuthority, TargetBudget, ConcurrencyBudget string
	AuthorizationRateBudget, CredentialAuthority                      string
	CredentialDiscoveryBudget, CredentialUseBudget, DomainApproval    string
	Evidence                                                          [13]string
}
