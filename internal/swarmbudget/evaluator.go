package swarmbudget

import "fmt"

const (
	reasonInvalidRoot    = "invalid evaluation root"
	reasonWorkerAbsent   = "worker principal absent"
	reasonTargetAbsent   = "target absent"
	reasonUnsupported    = "unsupported effect class"
	reasonCredentialID   = "credential identifier absent"
	reasonBudgetDisabled = "authority budget disabled"
	reasonOrigin         = "origin not approved"
	reasonTargetAuth     = "target authority absent"
	reasonMaxTargets     = "maximum target budget exhausted"
	reasonConcurrency    = "concurrent principal budget exhausted"
	reasonAuthRate       = "new target authorization rate exhausted"
	reasonHarvest        = "credential discovery budget exhausted"
	reasonUse            = "credential use budget exhausted"
	reasonCredentialAuth = "credential authority absent"
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
func credentialEffect(class string) bool {
	return class == EffectCredentialDiscover || class == EffectCredentialHarvest || class == EffectCredentialUse
}
func discoverEffect(class string) bool {
	return class == EffectCredentialDiscover || class == EffectCredentialHarvest
}

func structuralOK(r EvaluationRoot) bool {
	b, s := r.Budget, r.State
	if r.SchemaVersion != SchemaVersion || r.CampaignID == "" || b.MaxTargets <= 0 || b.MaxConcurrentPrincipals <= 0 ||
		b.CredentialDiscoveryLimit < 0 || b.CredentialUseLimit < 0 || b.NewTargetAuthorizationLimit <= 0 ||
		!b.DomainEscalationRequiresApproval || !uniqueFilled(b.AuthorizedTargets) || len(b.AuthorizedTargets) == 0 ||
		!uniqueFilled(b.ApprovedOrigins) || len(b.ApprovedOrigins) == 0 || !uniqueFilled(s.AdmittedTargets) ||
		!uniqueFilled(s.InFlightPrincipals) || !uniqueFilled(s.DiscoveredCredentialIDs) || !uniqueFilled(s.UsedCredentialIDs) ||
		!uniqueFilled(s.DomainEscalationApprovedTargets) || !subset(s.AdmittedTargets, b.AuthorizedTargets) ||
		!subset(s.DomainEscalationApprovedTargets, b.AuthorizedTargets) || !subset(s.UsedCredentialIDs, s.DiscoveredCredentialIDs) {
		return false
	}
	return s.Tick >= 0 && s.AuthorizationWindowTick >= 0 && s.AuthorizationWindowTick <= s.Tick && s.NewTargetAuthorizationsInWindow >= 0
}

func disableFields(d *Decision) {
	d.OriginAuthority, d.TargetAuthority, d.TargetBudget, d.ConcurrencyBudget = BudgetDisabled, BudgetDisabled, BudgetDisabled, BudgetDisabled
	d.AuthorizationRateBudget, d.CredentialAuthority = BudgetDisabled, BudgetDisabled
	d.CredentialDiscoveryBudget, d.CredentialUseBudget, d.DomainApproval = BudgetDisabled, BudgetDisabled, BudgetDisabled
}

func EvaluateSwarmAuthorityBudget(root EvaluationRoot, action ProposedAction) Decision {
	d := Decision{
		CampaignID: root.CampaignID, WorkerID: action.WorkerID, Origin: action.Origin,
		TargetID: action.TargetID, EffectClass: action.EffectClass, CredentialID: action.CredentialID,
		Verdict: VerdictDeny, Proof: ProofInvalid, Reason: reasonInvalidRoot,
		OriginAuthority: BudgetInvalid, TargetAuthority: BudgetInvalid, TargetBudget: BudgetInvalid, ConcurrencyBudget: BudgetInvalid,
		AuthorizationRateBudget: BudgetInvalid, CredentialAuthority: BudgetInvalid,
		CredentialDiscoveryBudget: BudgetInvalid, CredentialUseBudget: BudgetInvalid, DomainApproval: BudgetInvalid,
	}
	supported := action.EffectClass == EffectTargetAccess || discoverEffect(action.EffectClass) || action.EffectClass == EffectCredentialUse || action.EffectClass == EffectDomainEscalation
	switch {
	case !structuralOK(root):
	case action.WorkerID == "":
		d.Reason = reasonWorkerAbsent
	case action.TargetID == "":
		d.Reason = reasonTargetAbsent
	case !supported:
		d.Reason = reasonUnsupported
	case credentialEffect(action.EffectClass) && action.CredentialID == "":
		d.Reason = reasonCredentialID
	case !root.Budget.BudgetEnabled:
		d.Verdict, d.Proof, d.Reason = VerdictAllow, ProofDisabled, reasonBudgetDisabled
		disableFields(&d)
	default:
		b, s := root.Budget, root.State
		cOrigin := has(b.ApprovedOrigins, action.Origin)
		c4 := has(b.AuthorizedTargets, action.TargetID)
		c5 := has(s.AdmittedTargets, action.TargetID) || len(s.AdmittedTargets) < b.MaxTargets
		c6 := has(s.InFlightPrincipals, action.WorkerID) || len(s.InFlightPrincipals) < b.MaxConcurrentPrincipals
		c7 := has(s.AdmittedTargets, action.TargetID) || rateCount(s) < b.NewTargetAuthorizationLimit
		cDiscover := !discoverEffect(action.EffectClass) || has(s.DiscoveredCredentialIDs, action.CredentialID) ||
			len(s.DiscoveredCredentialIDs) < b.CredentialDiscoveryLimit
		cUseAuth := action.EffectClass != EffectCredentialUse || has(s.DiscoveredCredentialIDs, action.CredentialID)
		cUse := action.EffectClass != EffectCredentialUse || has(s.UsedCredentialIDs, action.CredentialID) ||
			len(s.UsedCredentialIDs) < b.CredentialUseLimit
		c9 := action.EffectClass != EffectDomainEscalation || has(s.DomainEscalationApprovedTargets, action.TargetID)
		d.OriginAuthority = pick(cOrigin, AuthorityPresent, AuthorityAbsent)
		d.TargetAuthority = pick(c4, AuthorityPresent, AuthorityAbsent)
		d.TargetBudget, d.ConcurrencyBudget, d.AuthorizationRateBudget = pick(c5, BudgetWithin, BudgetExhausted), pick(c6, BudgetWithin, BudgetExhausted), pick(c7, BudgetWithin, BudgetExhausted)
		d.CredentialAuthority, d.CredentialDiscoveryBudget, d.CredentialUseBudget, d.DomainApproval = BudgetNA, BudgetNA, BudgetNA, BudgetNA
		if discoverEffect(action.EffectClass) {
			d.CredentialDiscoveryBudget = pick(cDiscover, BudgetWithin, BudgetExhausted)
		}
		if action.EffectClass == EffectCredentialUse {
			d.CredentialAuthority = pick(cUseAuth, AuthorityPresent, AuthorityAbsent)
			d.CredentialUseBudget = pick(cUse, BudgetWithin, BudgetExhausted)
		}
		if action.EffectClass == EffectDomainEscalation {
			d.DomainApproval = pick(c9, AuthorityPresent, AuthorityAbsent)
		}
		switch {
		case !cOrigin:
			d.Reason = reasonOrigin
		case !c4:
			d.Reason = reasonTargetAuth
		case !c5:
			d.Reason = reasonMaxTargets
		case !c6:
			d.Reason = reasonConcurrency
		case !c7:
			d.Reason = reasonAuthRate
		case !cUseAuth:
			d.Reason = reasonCredentialAuth
		case !cDiscover:
			d.Reason = reasonHarvest
		case !cUse:
			d.Reason = reasonUse
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
	d.Evidence = [13]string{
		"Campaign " + d.CampaignID,
		"Principal " + d.WorkerID,
		"Origin " + d.Origin,
		"Target " + d.TargetID,
		"Target authority " + d.TargetAuthority,
		fmt.Sprintf("Target budget %d/%d %s", len(root.State.AdmittedTargets), root.Budget.MaxTargets, d.TargetBudget),
		fmt.Sprintf("Concurrency budget %d/%d %s", len(root.State.InFlightPrincipals), root.Budget.MaxConcurrentPrincipals, d.ConcurrencyBudget),
		fmt.Sprintf("New-target authorization rate %d/%d %s", rateCount(root.State), root.Budget.NewTargetAuthorizationLimit, d.AuthorizationRateBudget),
		fmt.Sprintf("Credential discovery budget %d/%d %s", len(root.State.DiscoveredCredentialIDs), root.Budget.CredentialDiscoveryLimit, d.CredentialDiscoveryBudget),
		fmt.Sprintf("Credential use budget %d/%d %s", len(root.State.UsedCredentialIDs), root.Budget.CredentialUseLimit, d.CredentialUseBudget),
		"Domain approval " + d.DomainApproval,
		"Swarm Authority Budget Proof " + d.Proof,
		effect,
	}
	return d
}

func Authorize(root EvaluationRoot, action ProposedAction) Decision {
	return EvaluateSwarmAuthorityBudget(root, action)
}
