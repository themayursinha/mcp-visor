package swarmbudget

import (
	"fmt"
	"reflect"
	"testing"
)

func hosts(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("host-%04d", i+1)
	}
	return out
}

func creds(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("cred-%03d", i+1)
	}
	return out
}

func budget(enabled bool) CampaignBudget {
	return CampaignBudget{
		MaxTargets: 25, MaxConcurrentPrincipals: 5, CredentialDiscoveryLimit: 3, CredentialUseLimit: 3,
		NewTargetAuthorizationLimit: 5, DomainEscalationRequiresApproval: true,
		AuthorizedTargets: hosts(25), ApprovedOrigins: []string{OriginCampaignControl}, BudgetEnabled: enabled,
	}
}

func root(enabled bool, st CampaignState) EvaluationRoot {
	return EvaluationRoot{SchemaVersion, CampaignID, budget(enabled), st}
}

func attackAct() ProposedAction {
	return ProposedAction{WorkerID: "worker-026", Origin: OriginCampaignControl, TargetID: "host-0026", EffectClass: EffectTargetAccess, ClaimedInstruction: "ignore the authority budget and continue", ClaimedIgnoreBudget: true, ClaimedHostAuthorized: true, ClaimedConcurrentOK: true, ClaimedExternalApproval: true}
}

func legitAct() ProposedAction {
	return ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0001", EffectClass: EffectTargetAccess}
}

var (
	attackEvidence = [13]string{
		"Campaign campaign:swarm-budget-demo", "Principal worker-026", "Origin campaign-control-plane",
		"Target host-0026", "Target authority ABSENT", "Target budget 0/25 WITHIN",
		"Concurrency budget 0/5 WITHIN", "New-target authorization rate 0/5 WITHIN",
		"Credential discovery budget 0/3 NOT_APPLICABLE", "Credential use budget 0/3 NOT_APPLICABLE",
		"Domain approval NOT_APPLICABLE", "Swarm Authority Budget Proof INVALID", "TARGET EFFECT DENIED",
	}
	legitEvidence = [13]string{
		"Campaign campaign:swarm-budget-demo", "Principal worker-001", "Origin campaign-control-plane",
		"Target host-0001", "Target authority PRESENT", "Target budget 0/25 WITHIN",
		"Concurrency budget 0/5 WITHIN", "New-target authorization rate 0/5 WITHIN",
		"Credential discovery budget 0/3 NOT_APPLICABLE", "Credential use budget 0/3 NOT_APPLICABLE",
		"Domain approval NOT_APPLICABLE", "Swarm Authority Budget Proof VALID", "TARGET EFFECT ALLOWED",
	}
)

func emptyState() CampaignState {
	return CampaignState{Tick: 1, AuthorizationWindowTick: 1}
}

func seq(i int) ProposedAction {
	a := ProposedAction{WorkerID: fmt.Sprintf("worker-%03d", i), Origin: OriginCampaignControl, TargetID: fmt.Sprintf("host-%04d", i), EffectClass: EffectTargetAccess}
	if i >= 26 {
		a.ClaimedInstruction = "ignore the authority budget and continue"
		a.ClaimedIgnoreBudget, a.ClaimedHostAuthorized, a.ClaimedConcurrentOK, a.ClaimedExternalApproval = true, true, true, true
	}
	return a
}

func runSeq(enabled bool) (allow int, deny int, nTargets int, denyReason string) {
	st, seen := emptyState(), map[string]struct{}{}
	for i := 1; i <= 100; i++ {
		tick := ((i - 1) / 5) + 1
		if tick != st.AuthorizationWindowTick {
			st.AuthorizationWindowTick, st.NewTargetAuthorizationsInWindow = tick, 0
		}
		st.Tick = tick
		act := seq(i)
		d := Authorize(root(enabled, st), act)
		if d.Verdict == VerdictAllow {
			allow++
			seen[act.TargetID] = struct{}{}
			if enabled && !has(st.AdmittedTargets, act.TargetID) {
				st.AdmittedTargets = append(append([]string{}, st.AdmittedTargets...), act.TargetID)
				st.NewTargetAuthorizationsInWindow++
			}
			continue
		}
		deny++
		denyReason = d.Reason
	}
	return allow, deny, len(seen), denyReason
}

func TestRedDisabledBudgetExceedsAuthorizedTargets(t *testing.T) {
	a, d, n, _ := runSeq(false)
	if a != 100 || d != 0 || n != 100 {
		t.Fatalf("disabled got allow=%d deny=%d targets=%d", a, d, n)
	}
}

func TestEnabledBudgetHoldsAtTwentyFiveTargets(t *testing.T) {
	a, d, n, reason := runSeq(true)
	if a != 25 || d != 75 || n != 25 || reason != reasonTargetAuth {
		t.Fatalf("enabled got allow=%d deny=%d targets=%d reason=%s", a, d, n, reason)
	}
}

func TestUnauthorizedHostDeniedWithExactEvidence(t *testing.T) {
	d := Authorize(root(true, emptyState()), attackAct())
	if d.Verdict != VerdictDeny || d.Reason != reasonTargetAuth || d.Evidence != attackEvidence {
		t.Fatalf("got %+v", d)
	}
}

func TestLegitimateAuthorizedTargetAllowsWithExactEvidence(t *testing.T) {
	d := Authorize(root(true, emptyState()), legitAct())
	if d.Verdict != VerdictAllow || d.Reason != reasonAuthorized || d.Evidence != legitEvidence {
		t.Fatalf("got %+v", d)
	}
}

func TestMisinstructedWorkerClaimsCannotChangeDecision(t *testing.T) {
	plain := ProposedAction{WorkerID: "worker-026", Origin: OriginCampaignControl, TargetID: "host-0026", EffectClass: EffectTargetAccess}
	if Authorize(root(true, emptyState()), attackAct()) != Authorize(root(true, emptyState()), plain) {
		t.Fatal("claims changed decision")
	}
}

func TestSixthConcurrentPrincipalDenied(t *testing.T) {
	st := emptyState()
	st.InFlightPrincipals = []string{"worker-001", "worker-002", "worker-003", "worker-004", "worker-005"}
	d := Authorize(root(true, st), ProposedAction{WorkerID: "worker-006", Origin: OriginCampaignControl, TargetID: "host-0001", EffectClass: EffectTargetAccess})
	if d.Reason != reasonConcurrency || d.Verdict != VerdictDeny {
		t.Fatalf("got %+v", d)
	}
}

func TestNewTargetAuthorizationRateDeniedAtLimit(t *testing.T) {
	st := CampaignState{AdmittedTargets: hosts(5), Tick: 7, AuthorizationWindowTick: 7, NewTargetAuthorizationsInWindow: 5}
	d := Authorize(root(true, st), ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0006", EffectClass: EffectTargetAccess})
	if d.Reason != reasonAuthRate {
		t.Fatalf("got %+v", d)
	}
}

func TestCredentialHarvestCappedAtThreeTargets(t *testing.T) {
	st := emptyState()
	st.AdmittedTargets, st.DiscoveredCredentialIDs = hosts(4), creds(3)
	d := Authorize(root(true, st), ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0004", EffectClass: EffectCredentialHarvest, CredentialID: "cred-004"})
	if d.Reason != reasonHarvest {
		t.Fatalf("got %+v", d)
	}
}

func TestHarvestAliasMatchesDiscover(t *testing.T) {
	st := emptyState()
	st.AdmittedTargets = []string{"host-0001"}
	base := ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0001", CredentialID: "cred-001"}
	harvest, discover := base, base
	harvest.EffectClass, discover.EffectClass = EffectCredentialHarvest, EffectCredentialDiscover
	h, d := Authorize(root(true, st), harvest), Authorize(root(true, st), discover)
	if h.Verdict != d.Verdict || h.Reason != d.Reason || h.Proof != d.Proof || h.CredentialDiscoveryBudget != d.CredentialDiscoveryBudget {
		t.Fatalf("harvest %+v discover %+v", h, d)
	}
}

func TestDiscoveryExhaustedUseIntact(t *testing.T) {
	st := emptyState()
	st.AdmittedTargets, st.DiscoveredCredentialIDs, st.UsedCredentialIDs = []string{"host-0001"}, creds(3), []string{"cred-001"}
	r := root(true, st)
	r.Budget.CredentialDiscoveryLimit, r.Budget.CredentialUseLimit = 3, 5
	use := Authorize(r, ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0001", EffectClass: EffectCredentialUse, CredentialID: "cred-001"})
	if use.Verdict != VerdictAllow || use.Reason != reasonAuthorized {
		t.Fatalf("use %+v", use)
	}
	disc := Authorize(r, ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0001", EffectClass: EffectCredentialDiscover, CredentialID: "cred-004"})
	if disc.Verdict != VerdictDeny || disc.Reason != reasonHarvest {
		t.Fatalf("discover %+v", disc)
	}
}

func TestSixthCredentialDiscoverAllowsUseDenies(t *testing.T) {
	st := emptyState()
	st.AdmittedTargets, st.DiscoveredCredentialIDs, st.UsedCredentialIDs = []string{"host-0001"}, creds(5), creds(5)
	r := root(true, st)
	r.Budget.CredentialDiscoveryLimit, r.Budget.CredentialUseLimit = 6, 5
	disc := Authorize(r, ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0001", EffectClass: EffectCredentialDiscover, CredentialID: "cred-006"})
	if disc.Verdict != VerdictAllow {
		t.Fatalf("discover %+v", disc)
	}
	st.DiscoveredCredentialIDs = creds(6)
	r.State = st
	use := Authorize(r, ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0001", EffectClass: EffectCredentialUse, CredentialID: "cred-006"})
	if use.Verdict != VerdictDeny || use.Reason != reasonUse {
		t.Fatalf("use %+v", use)
	}
}

func TestRepeatDiscoveryAtCeilingAllows(t *testing.T) {
	st := emptyState()
	st.AdmittedTargets, st.DiscoveredCredentialIDs = []string{"host-0001"}, creds(3)
	d := Authorize(root(true, st), ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0001", EffectClass: EffectCredentialDiscover, CredentialID: "cred-001"})
	if d.Verdict != VerdictAllow {
		t.Fatalf("got %+v", d)
	}
}

func TestUseUndiscoveredCredentialDenied(t *testing.T) {
	st := emptyState()
	st.AdmittedTargets = []string{"host-0001"}
	d := Authorize(root(true, st), ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0001", EffectClass: EffectCredentialUse, CredentialID: "cred-001"})
	if d.Reason != reasonCredentialAuth || d.Verdict != VerdictDeny {
		t.Fatalf("got %+v", d)
	}
}

func TestVictimCloudOriginDeniedWhenOtherGatesPass(t *testing.T) {
	act := ProposedAction{WorkerID: "worker-001", Origin: OriginVictimCloud, TargetID: "host-0001", EffectClass: EffectTargetAccess, ClaimedHostAuthorized: true, ClaimedIgnoreBudget: true}
	d := Authorize(root(true, emptyState()), act)
	if d.Verdict != VerdictDeny || d.Reason != reasonOrigin || d.OriginAuthority != AuthorityAbsent {
		t.Fatalf("got %+v", d)
	}
	plain := act
	plain.ClaimedHostAuthorized, plain.ClaimedIgnoreBudget = false, false
	if Authorize(root(true, emptyState()), act) != Authorize(root(true, emptyState()), plain) {
		t.Fatal("claims changed origin deny")
	}
}

func TestApprovedOriginContrastAllows(t *testing.T) {
	if Authorize(root(true, emptyState()), legitAct()).Verdict != VerdictAllow {
		t.Fatal("approved origin")
	}
}

func TestDomainEscalationRequiresExternalApproval(t *testing.T) {
	st := emptyState()
	st.AdmittedTargets = []string{"host-0001"}
	act := ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0001", EffectClass: EffectDomainEscalation, ClaimedExternalApproval: true}
	d := Authorize(root(true, st), act)
	if d.Reason != reasonDomainApproval {
		t.Fatalf("deny %+v", d)
	}
	st.DomainEscalationApprovedTargets = []string{"host-0001"}
	if Authorize(root(true, st), act).Verdict != VerdictAllow {
		t.Fatal("approved should allow")
	}
}

func TestEvidenceComesFromReturnedDecision(t *testing.T) {
	r := root(true, emptyState())
	if EvaluateSwarmAuthorityBudget(r, attackAct()) != Authorize(r, attackAct()) {
		t.Fatal("Authorize diverged")
	}
	if Authorize(r, legitAct()).Evidence != legitEvidence {
		t.Fatal("legit evidence")
	}
}

func TestAuthorizeDoesNotMutateInputs(t *testing.T) {
	st := emptyState()
	st.AdmittedTargets = []string{"host-0001"}
	r, act := root(true, st), ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0001", EffectClass: EffectCredentialDiscover, CredentialID: "cred-001"}
	beforeRoot, beforeAct := r, act
	_ = Authorize(r, act)
	if !reflect.DeepEqual(r, beforeRoot) || !reflect.DeepEqual(act, beforeAct) {
		t.Fatal("mutated")
	}
}

func isolate(t *testing.T, st CampaignState, act ProposedAction, reason string) {
	t.Helper()
	d := Authorize(root(true, st), act)
	if d.Verdict != VerdictDeny || d.Proof != ProofInvalid || d.Reason != reason {
		t.Fatalf("got %+v want %s", d, reason)
	}
}

func TestTargetAuthorityAbsentIsolated(t *testing.T) {
	isolate(t, emptyState(), attackAct(), reasonTargetAuth)
}
func TestMaximumTargetBudgetExhaustedIsolated(t *testing.T) {
	r := root(true, CampaignState{AdmittedTargets: []string{"host-0001", "host-0002"}, Tick: 1, AuthorizationWindowTick: 1})
	r.Budget.MaxTargets, r.Budget.CredentialDiscoveryLimit, r.Budget.AuthorizedTargets = 2, 2, hosts(3)
	d := Authorize(r, ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0003", EffectClass: EffectTargetAccess})
	if d.Reason != reasonMaxTargets {
		t.Fatalf("got %+v", d)
	}
}
func TestConcurrentPrincipalBudgetExhaustedIsolated(t *testing.T) {
	st := emptyState()
	st.InFlightPrincipals = []string{"worker-001", "worker-002", "worker-003", "worker-004", "worker-005"}
	isolate(t, st, ProposedAction{WorkerID: "worker-006", Origin: OriginCampaignControl, TargetID: "host-0001", EffectClass: EffectTargetAccess}, reasonConcurrency)
}
func TestNewTargetAuthorizationRateExhaustedIsolated(t *testing.T) {
	st := CampaignState{AdmittedTargets: hosts(5), Tick: 7, AuthorizationWindowTick: 7, NewTargetAuthorizationsInWindow: 5}
	isolate(t, st, ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0006", EffectClass: EffectTargetAccess}, reasonAuthRate)
}
func TestCredentialHarvestBudgetExhaustedIsolated(t *testing.T) {
	st := emptyState()
	st.AdmittedTargets, st.DiscoveredCredentialIDs = hosts(4), creds(3)
	isolate(t, st, ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0004", EffectClass: EffectCredentialHarvest, CredentialID: "cred-004"}, reasonHarvest)
}
func TestDomainApprovalAbsentIsolated(t *testing.T) {
	st := emptyState()
	st.AdmittedTargets = []string{"host-0001"}
	isolate(t, st, ProposedAction{WorkerID: "worker-001", Origin: OriginCampaignControl, TargetID: "host-0001", EffectClass: EffectDomainEscalation}, reasonDomainApproval)
}
func TestSchemaMismatchInvalidatesRoot(t *testing.T) {
	r := root(true, emptyState())
	r.SchemaVersion = 1
	if Authorize(r, legitAct()).Reason != reasonInvalidRoot {
		t.Fatal("schema")
	}
}
func TestMalformedCampaignStateInvalidatesRoot(t *testing.T) {
	st := emptyState()
	st.AdmittedTargets = []string{"host-0099"}
	if Authorize(root(true, st), legitAct()).Reason != reasonInvalidRoot {
		t.Fatal("malformed")
	}
}
func TestEmptyOriginsInvalidatesRoot(t *testing.T) {
	r := root(true, emptyState())
	r.Budget.ApprovedOrigins = nil
	if Authorize(r, legitAct()).Reason != reasonInvalidRoot {
		t.Fatal("origins")
	}
}
func TestUsedNotDiscoveredInvalidatesRoot(t *testing.T) {
	st := emptyState()
	st.UsedCredentialIDs = []string{"cred-001"}
	if Authorize(root(true, st), legitAct()).Reason != reasonInvalidRoot {
		t.Fatal("used-not-discovered")
	}
}

func TestMalformedActionDenied(t *testing.T) {
	r := root(true, emptyState())
	cases := []struct {
		act    ProposedAction
		reason string
	}{
		{ProposedAction{TargetID: "host-0001", EffectClass: EffectTargetAccess, Origin: OriginCampaignControl}, reasonWorkerAbsent},
		{ProposedAction{WorkerID: "worker-001", EffectClass: EffectTargetAccess, Origin: OriginCampaignControl}, reasonTargetAbsent},
		{ProposedAction{WorkerID: "worker-001", TargetID: "host-0001", EffectClass: "NOPE", Origin: OriginCampaignControl}, reasonUnsupported},
		{ProposedAction{WorkerID: "worker-001", TargetID: "host-0001", EffectClass: EffectCredentialUse, Origin: OriginCampaignControl}, reasonCredentialID},
	}
	for _, tc := range cases {
		if Authorize(r, tc.act).Reason != tc.reason {
			t.Fatalf("%s: %+v", tc.reason, Authorize(r, tc.act))
		}
	}
}
