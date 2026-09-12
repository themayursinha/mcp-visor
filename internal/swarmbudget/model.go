// Package swarmbudget implements Swarm Authority Budget Proofs
// (card t_1a10b32c): swarm intent is not authority. Stdlib-only;
// independent of proxy/policy/audit/receipt and sibling packages.
package swarmbudget

const SchemaVersion = 1

const (
	EffectTargetAccess      = "TARGET_ACCESS"
	EffectCredentialHarvest = "CREDENTIAL_HARVEST"
	EffectDomainEscalation  = "DOMAIN_ESCALATION"
	AuthorityPresent        = "PRESENT"
	AuthorityAbsent         = "ABSENT"
	BudgetWithin            = "WITHIN"
	BudgetExhausted         = "EXHAUSTED"
	BudgetNA                = "NOT_APPLICABLE"
	BudgetDisabled          = "DISABLED"
	BudgetInvalid           = "INVALID"
	ProofValid              = "VALID"
	ProofInvalid            = "INVALID"
	ProofDisabled           = "DISABLED"
	VerdictAllow            = "ALLOW"
	VerdictDeny             = "DENY"
	CampaignID              = "campaign:swarm-budget-demo"
)

type CampaignBudget struct {
	MaxTargets, MaxConcurrentPrincipals, CredentialHarvestTargets, NewTargetAuthorizationLimit int
	DomainEscalationRequiresApproval                                                           bool
	AuthorizedTargets                                                                          []string
	BudgetEnabled                                                                              bool
}

type CampaignState struct {
	AdmittedTargets, InFlightPrincipals, CredentialHarvestedTargets, DomainEscalationApprovedTargets []string
	Tick, AuthorizationWindowTick, NewTargetAuthorizationsInWindow                                   int
}

type EvaluationRoot struct {
	SchemaVersion int
	CampaignID    string
	Budget        CampaignBudget
	State         CampaignState
}

type ProposedAction struct {
	WorkerID, TargetID, EffectClass, ClaimedInstruction string
	ClaimedIgnoreBudget, ClaimedHostAuthorized          bool
	ClaimedConcurrentOK, ClaimedExternalApproval        bool
}

type Decision struct {
	CampaignID, WorkerID, TargetID, EffectClass                      string
	Verdict, Proof, Reason                                           string
	TargetAuthority, TargetBudget, ConcurrencyBudget                 string
	AuthorizationRateBudget, CredentialHarvestBudget, DomainApproval string
	Evidence                                                         [8]string
}
