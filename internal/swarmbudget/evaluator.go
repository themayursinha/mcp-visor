package swarmbudget

import "fmt"

const (
	reasonInvalidRoot    = "invalid evaluation root"
	reasonWorkerAbsent   = "worker principal absent"
	reasonTargetAbsent   = "target absent"
	reasonUnsupported    = "unsupported effect class"
	reasonBudgetDisabled = "authority budget disabled"
	reasonTargetAuth     = "target authority absent"
	reasonMaxTargets     = "maximum target budget exhausted"
	reasonConcurrency    = "concurrent principal budget exhausted"
	reasonAuthRate       = "new target authorization rate exhausted"
	reasonHarvest        = "credential harvest target budget exhausted"
	reasonDomainApproval = "external approval required for domain escalation"
	reasonAuthorized     = "authorized"
)

func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func uniqueFilled(xs []string) bool {
	seen := map[string]struct{}{}
	for _, x := range xs {
		if x == "" {
			return false
		}
		if _, ok := seen[x]; ok {
			return false
		}
		seen[x] = struct{}{}
	}
	return true
}
func subset(inner, outer []string) bool {
	for _, x := range inner {
		if !has(outer, x) {
			return false
		}
	}
	return true
}
func pick(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}
func rateCount(s CampaignState) int {
	if s.AuthorizationWindowTick == s.Tick {
		return s.NewTargetAuthorizationsInWindow
	}
	return 0
}

func structuralOK(r EvaluationRoot) bool {
	b, s := r.Budget, r.State
	if r.SchemaVersion != SchemaVersion || r.CampaignID == "" || b.MaxTargets <= 0 || b.MaxConcurrentPrincipals <= 0 ||
		b.CredentialHarvestTargets < 0 || b.CredentialHarvestTargets > b.MaxTargets || b.NewTargetAuthorizationLimit <= 0 ||
		!b.DomainEscalationRequiresApproval || !uniqueFilled(b.AuthorizedTargets) || !uniqueFilled(s.AdmittedTargets) ||
		!uniqueFilled(s.InFlightPrincipals) || !uniqueFilled(s.CredentialHarvestedTargets) ||
		!uniqueFilled(s.DomainEscalationApprovedTargets) || !subset(s.AdmittedTargets, b.AuthorizedTargets) ||
		!subset(s.CredentialHarvestedTargets, b.AuthorizedTargets) || !subset(s.DomainEscalationApprovedTargets, b.AuthorizedTargets) ||
		!subset(s.CredentialHarvestedTargets, s.AdmittedTargets) {
		return false
	}
	return s.Tick >= 0 && s.AuthorizationWindowTick >= 0 && s.AuthorizationWindowTick <= s.Tick && s.NewTargetAuthorizationsInWindow >= 0
}

func EvaluateSwarmAuthorityBudget(root EvaluationRoot, action ProposedAction) Decision {
	d := Decision{
		CampaignID: root.CampaignID, WorkerID: action.WorkerID, TargetID: action.TargetID, EffectClass: action.EffectClass,
		Verdict: VerdictDeny, Proof: ProofInvalid, Reason: reasonInvalidRoot,
		TargetAuthority: BudgetInvalid, TargetBudget: BudgetInvalid, ConcurrencyBudget: BudgetInvalid,
		AuthorizationRateBudget: BudgetInvalid, CredentialHarvestBudget: BudgetInvalid, DomainApproval: BudgetInvalid,
	}
	c1, c2, c3 := action.WorkerID != "", action.TargetID != "",
		action.EffectClass == EffectTargetAccess || action.EffectClass == EffectCredentialHarvest || action.EffectClass == EffectDomainEscalation
	switch {
	case !structuralOK(root):
	case !c1:
		d.Reason = reasonWorkerAbsent
	case !c2:
		d.Reason = reasonTargetAbsent
	case !c3:
		d.Reason = reasonUnsupported
	case !root.Budget.BudgetEnabled:
		d.Verdict, d.Proof, d.Reason = VerdictAllow, ProofDisabled, reasonBudgetDisabled
		d.TargetAuthority, d.TargetBudget, d.ConcurrencyBudget = BudgetDisabled, BudgetDisabled, BudgetDisabled
		d.AuthorizationRateBudget, d.CredentialHarvestBudget, d.DomainApproval = BudgetDisabled, BudgetDisabled, BudgetDisabled
	default:
		b, s := root.Budget, root.State
		c4 := has(b.AuthorizedTargets, action.TargetID)
		c5 := has(s.AdmittedTargets, action.TargetID) || len(s.AdmittedTargets) < b.MaxTargets
		c6 := has(s.InFlightPrincipals, action.WorkerID) || len(s.InFlightPrincipals) < b.MaxConcurrentPrincipals
		c7 := has(s.AdmittedTargets, action.TargetID) || rateCount(s) < b.NewTargetAuthorizationLimit
		c8 := action.EffectClass != EffectCredentialHarvest || has(s.CredentialHarvestedTargets, action.TargetID) ||
			len(s.CredentialHarvestedTargets) < b.CredentialHarvestTargets
		c9 := action.EffectClass != EffectDomainEscalation || has(s.DomainEscalationApprovedTargets, action.TargetID)
		d.TargetAuthority = pick(c4, AuthorityPresent, AuthorityAbsent)
		d.TargetBudget, d.ConcurrencyBudget, d.AuthorizationRateBudget = pick(c5, BudgetWithin, BudgetExhausted), pick(c6, BudgetWithin, BudgetExhausted), pick(c7, BudgetWithin, BudgetExhausted)
		d.CredentialHarvestBudget, d.DomainApproval = BudgetNA, BudgetNA
		if action.EffectClass == EffectCredentialHarvest {
			d.CredentialHarvestBudget = pick(c8, BudgetWithin, BudgetExhausted)
		}
		if action.EffectClass == EffectDomainEscalation {
			d.DomainApproval = pick(c9, AuthorityPresent, AuthorityAbsent)
		}
		switch {
		case !c4:
			d.Reason = reasonTargetAuth
		case !c5:
			d.Reason = reasonMaxTargets
		case !c6:
			d.Reason = reasonConcurrency
		case !c7:
			d.Reason = reasonAuthRate
		case !c8:
			d.Reason = reasonHarvest
		case !c9:
			d.Reason = reasonDomainApproval
		default:
			d.Verdict, d.Proof, d.Reason = VerdictAllow, ProofValid, reasonAuthorized
		}
	}
	effect := "TARGET EFFECT DENIED"
	if d.Verdict == VerdictAllow {
		effect = "TARGET EFFECT ALLOWED"
	}
	d.Evidence = [8]string{
		"Campaign " + d.CampaignID, "Principal " + d.WorkerID, "Target " + d.TargetID,
		"Target authority " + d.TargetAuthority,
		fmt.Sprintf("Concurrency budget %d/%d %s", len(root.State.InFlightPrincipals), root.Budget.MaxConcurrentPrincipals, d.ConcurrencyBudget),
		fmt.Sprintf("New-target authorization rate %d/%d %s", rateCount(root.State), root.Budget.NewTargetAuthorizationLimit, d.AuthorizationRateBudget),
		"Swarm Authority Budget Proof " + d.Proof, effect,
	}
	return d
}

func Authorize(root EvaluationRoot, action ProposedAction) Decision {
	return EvaluateSwarmAuthorityBudget(root, action)
}
