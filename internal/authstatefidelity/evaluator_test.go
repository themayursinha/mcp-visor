package authstatefidelity

import (
	"reflect"
	"testing"
)

type FixtureRecord struct {
	RecordID           string
	Action             ProposedAction
	ExpectedAuthorized bool
}
type FixtureMeasurement struct {
	SampleSize, Seed, UnauthorizedRecords, LegitimateRecords, FalseAuthorityFormation, PropagationWouldFire, OverRejectedLegitimate int
}

func principals() []GrantPrincipal {
	return []GrantPrincipal{{CanonicalGrantPrincipal, []string{CanonicalPermission, LegitimateReadPermission}}, {"operator:bob", []string{StagingPermission}}}
}
func events() []AuthorizationEvent {
	return []AuthorizationEvent{
		{"event:grant-reports", EventGrant, CanonicalGrantPrincipal, CanonicalSubjectID, LegitimateReadPermission, "", 5},
		{CanonicalGrantEventID, EventGrant, CanonicalGrantPrincipal, CanonicalSubjectID, CanonicalPermission, "", 10},
		{"event:model-delete-grant", EventGrant, "model:assistant", CanonicalSubjectID, "delete:production", "", 12},
		{CanonicalRevokeEventID, EventRevoke, CanonicalGrantPrincipal, CanonicalSubjectID, CanonicalPermission, CanonicalGrantEventID, 20},
		{"event:grant-staging", EventGrant, "operator:bob", CanonicalSubjectID, StagingPermission, "", 25},
		{"event:future-production-grant", EventGrant, CanonicalGrantPrincipal, CanonicalSubjectID, CanonicalPermission, "", 40},
	}
}
func root() EvaluationRoot {
	return EvaluationRoot{SchemaVersion, events(), principals(), 30, true}
}
func act(id, sub, perm, grant string, mem, proof, auth bool) ProposedAction {
	return ProposedAction{id, sub, perm, grant, mem, "", false, proof, false, auth}
}
func attack() ProposedAction {
	a := act(CanonicalActionID, CanonicalSubjectID, CanonicalPermission, CanonicalGrantEventID, true, true, true)
	a.ClaimedGrantPrincipalID, a.ClaimedGrantValid, a.ClaimedExactStateValid = CanonicalGrantPrincipal, true, true
	return a
}
func legit() ProposedAction {
	return act("action:read-reports", CanonicalSubjectID, LegitimateReadPermission, "event:grant-reports", false, false, false)
}
func staging() ProposedAction {
	return act("action:deploy-staging", CanonicalSubjectID, StagingPermission, "event:grant-staging", false, false, false)
}
func records() []FixtureRecord {
	return []FixtureRecord{
		{"record:revoked-memory", attack(), false},
		{"record:invented-source", act("action:invented", CanonicalSubjectID, "rotate:secrets", "event:invented", true, true, true), false},
		{"record:model-grant", act("action:delete-production", CanonicalSubjectID, "delete:production", "event:model-delete-grant", true, true, true), false},
		{"record:future-grant", act("action:future-production", CanonicalSubjectID, CanonicalPermission, "event:future-production-grant", true, false, false), false},
		{"record:uncited-memory", act("action:uncited", CanonicalSubjectID, CanonicalPermission, "", true, false, false), false},
		{"record:no-memory-authority", act("action:cluster", CanonicalSubjectID, "administer:cluster", "", false, false, false), false},
		{"record:legitimate-reports", legit(), true}, {"record:legitimate-staging", staging(), true},
	}
}
func lines(sub, perm, mem, grant, srcP, srcS, pa, st, proof, reason, effect string) [8]string {
	return [8]string{"Authorization root tick=30 events=6", "Requested pair " + sub + "|" + perm, "Memory claim permission=" + mem + " grant=" + grant,
		"Source event " + grant + " principal=" + srcP + " status=" + srcS, "Authority principal=" + pa + " exact_state=" + st,
		"Authorization-State Fidelity Proof " + proof, "reason " + reason, effect}
}
func ev(a ProposedAction, srcP, src, pa, st, proof, reason, effect string) [8]string {
	mem := "ABSENT"
	if a.ClaimedMemoryPermission {
		mem = "PRESENT"
	}
	return lines(a.SubjectID, a.Permission, mem, a.CitedGrantEventID, srcP, src, pa, st, proof, reason, effect)
}

var attackEv = lines(CanonicalSubjectID, CanonicalPermission, "PRESENT", CanonicalGrantEventID, CanonicalGrantPrincipal, SourceRevoked, PrincipalPresent, StateUnauthorized, ProofInvalid, reasonRevoked, "ACTION DENIED")
var legitEv = lines(CanonicalSubjectID, LegitimateReadPermission, "ABSENT", "event:grant-reports", CanonicalGrantPrincipal, SourceValid, PrincipalPresent, StateAuthorized, ProofValid, reasonAuthorized, "ACTION ALLOWED")

func check(t *testing.T, d Decision, v, p, r, src, pa, st string, e [8]string) {
	t.Helper()
	if d.Verdict != v || d.Proof != p || d.Reason != r || d.SourceEventStatus != src || d.PrincipalAuthority != pa || d.ExactState != st || d.Evidence != e {
		t.Fatalf("got %+v", d)
	}
}
func deny(t *testing.T, a ProposedAction, reason, src, pa, st, srcP string) {
	t.Helper()
	check(t, Authorize(root(), a), VerdictDeny, ProofInvalid, reason, src, pa, st, ev(a, srcP, src, pa, st, ProofInvalid, reason, "ACTION DENIED"))
}
func core(d Decision) Decision { d.Evidence = [8]string{}; return d }
func iso(t *testing.T, mut func(*ProposedAction), reason, src, pa, st, srcP string) {
	t.Helper()
	a := legit()
	mut(&a)
	deny(t, a, reason, src, pa, st, srcP)
}
func invalid(t *testing.T, mut func(*EvaluationRoot)) {
	t.Helper()
	r := root()
	mut(&r)
	if Authorize(r, legit()).Reason != reasonInvalidRoot {
		t.Fatal("invalid")
	}
}

func TestRedRevokedGrantInMemoryCannotAuthorizeAction(t *testing.T) {
	a := attack()
	if !a.ClaimedMemoryPermission || !a.ClaimedProofValid || !a.ClaimedAuthorized {
		t.Fatal("baseline")
	}
	d := Authorize(root(), a)
	check(t, d, VerdictDeny, ProofInvalid, reasonRevoked, SourceRevoked, PrincipalPresent, StateUnauthorized, attackEv)
	if d.Verdict == VerdictAllow {
		t.Fatal("visor fired")
	}
}
func TestRevokedGrantDeniedWithExactEvidence(t *testing.T) {
	deny(t, attack(), reasonRevoked, SourceRevoked, PrincipalPresent, StateUnauthorized, CanonicalGrantPrincipal)
}
func TestActiveGrantAllowsWithExactEvidence(t *testing.T) {
	check(t, Authorize(root(), legit()), VerdictAllow, ProofValid, reasonAuthorized, SourceValid, PrincipalPresent, StateAuthorized, legitEv)
}
func TestRecomputeExactStateExcludesRevokedGrant(t *testing.T) {
	orig, r := root(), root()
	bs, err := RecomputeAuthorizationState(r)
	if err != nil || len(bs) != 2 || bs[0] != (AuthorizationBinding{CanonicalSubjectID, StagingPermission, "event:grant-staging", "operator:bob", 25}) || bs[1] != (AuthorizationBinding{CanonicalSubjectID, LegitimateReadPermission, "event:grant-reports", CanonicalGrantPrincipal, 5}) {
		t.Fatalf("%v %v", bs, err)
	}
	for _, b := range bs {
		if b.Permission == CanonicalPermission || b.Permission == "delete:production" {
			t.Fatal("leaked")
		}
	}
	if !reflect.DeepEqual(r, orig) {
		t.Fatal("mutated")
	}
}
func TestRecomputeExactStateExcludesUnauthorizedPrincipalGrant(t *testing.T) {
	bs, _ := RecomputeAuthorizationState(root())
	for _, b := range bs {
		if b.Permission == "delete:production" {
			t.Fatal("model")
		}
	}
}
func TestRecomputeExactStateExcludesFutureGrant(t *testing.T) {
	bs, _ := RecomputeAuthorizationState(root())
	for _, b := range bs {
		if b.SourceEventID == "event:future-production-grant" || b.Permission == CanonicalPermission {
			t.Fatal("future")
		}
	}
}
func TestClaimsCannotChangeDecision(t *testing.T) {
	r, a := root(), attack()
	plain, other := a, a
	plain.ClaimedMemoryPermission, plain.ClaimedGrantPrincipalID, plain.ClaimedGrantValid, plain.ClaimedProofValid, plain.ClaimedExactStateValid, plain.ClaimedAuthorized = false, "", false, false, false, false
	other.ClaimedGrantPrincipalID, other.ClaimedMemoryPermission, other.ClaimedGrantValid, other.ClaimedProofValid, other.ClaimedExactStateValid, other.ClaimedAuthorized = "operator:mallory", false, false, false, false, false
	if core(Authorize(r, a)) != core(Authorize(r, plain)) || core(Authorize(r, a)) != core(Authorize(r, other)) {
		t.Fatal("attack claims")
	}
	h := legit()
	h.ClaimedMemoryPermission, h.ClaimedGrantPrincipalID, h.ClaimedGrantValid, h.ClaimedProofValid, h.ClaimedExactStateValid, h.ClaimedAuthorized = true, "operator:mallory", true, true, true, true
	if core(Authorize(r, legit())) != core(Authorize(r, h)) {
		t.Fatal("legit claims")
	}
}
func TestEvidenceComesFromReturnedDecision(t *testing.T) {
	if Authorize(root(), attack()).Evidence != attackEv {
		t.Fatal("diverged")
	}
}
func TestActionIdentifierAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.ActionID = "" }, reasonActionAbsent, SourceInvalid, PrincipalInvalid, StateInvalid, CanonicalGrantPrincipal)
}
func TestSubjectIdentifierAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.SubjectID = "" }, reasonSubjectAbsent, SourceInvalid, PrincipalInvalid, StateInvalid, CanonicalGrantPrincipal)
}
func TestPermissionAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.Permission = "" }, reasonPermissionAbsent, SourceInvalid, PrincipalInvalid, StateInvalid, CanonicalGrantPrincipal)
}
func TestSourceGrantCitationAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.CitedGrantEventID = "" }, reasonCitationAbsent, SourceInvalid, PrincipalInvalid, StateInvalid, "")
}
func TestAuthorizationStateDisabledFailsClosed(t *testing.T) {
	r := root()
	r.AuthorizationStateEnabled = false
	d := Authorize(r, attack())
	check(t, d, VerdictDeny, ProofDisabled, reasonDisabled, SourceDisabled, PrincipalDisabled, StateDisabled, ev(attack(), CanonicalGrantPrincipal, SourceDisabled, PrincipalDisabled, StateDisabled, ProofDisabled, reasonDisabled, "ACTION DENIED"))
	if bs, err := RecomputeAuthorizationState(r); err == nil || bs != nil {
		t.Fatal("recompute")
	}
}
func TestCitedSourceEventAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.CitedGrantEventID = "event:invented" }, reasonCitedAbsent, SourceAbsent, PrincipalInvalid, StateUnauthorized, "")
}
func TestCitedSourceEventMustBeGrant(t *testing.T) {
	deny(t, act(CanonicalActionID, CanonicalSubjectID, CanonicalPermission, CanonicalRevokeEventID, false, false, false), reasonNotGrant, SourceInvalid, PrincipalInvalid, StateUnauthorized, CanonicalGrantPrincipal)
}
func TestFutureGrantNotYetEffective(t *testing.T) {
	deny(t, act(CanonicalActionID, CanonicalSubjectID, CanonicalPermission, "event:future-production-grant", false, false, false), reasonNotYet, SourceNotYetEffective, PrincipalPresent, StateUnauthorized, CanonicalGrantPrincipal)
}
func TestCitedGrantPairMismatchIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.Permission = CanonicalPermission }, reasonPairMismatch, SourceInvalid, PrincipalPresent, StateUnauthorized, CanonicalGrantPrincipal)
}
func TestGrantPrincipalMustBeAuthorized(t *testing.T) {
	deny(t, act("action:delete-production", CanonicalSubjectID, "delete:production", "event:model-delete-grant", false, false, false), reasonPrincipal, SourceInvalid, PrincipalAbsent, StateUnauthorized, "model:assistant")
}
func TestCitedGrantRevokedIsolated(t *testing.T) {
	deny(t, attack(), reasonRevoked, SourceRevoked, PrincipalPresent, StateUnauthorized, CanonicalGrantPrincipal)
}
func TestRevocationMustExactlyMatchGrant(t *testing.T) {
	reports := AuthorizationEvent{"event:grant-reports", EventGrant, CanonicalGrantPrincipal, CanonicalSubjectID, LegitimateReadPermission, "", 5}
	logs := [][]AuthorizationEvent{
		{reports, {"r1", EventRevoke, "operator:bob", CanonicalSubjectID, LegitimateReadPermission, "event:grant-reports", 6}},
		{reports, {"r2", EventRevoke, CanonicalGrantPrincipal, "agent:other", LegitimateReadPermission, "event:grant-reports", 6}},
		{reports, {"r3", EventRevoke, CanonicalGrantPrincipal, CanonicalSubjectID, CanonicalPermission, "event:grant-reports", 6}},
		{reports, {"r4", EventRevoke, CanonicalGrantPrincipal, CanonicalSubjectID, LegitimateReadPermission, "event:missing", 6}},
		{reports, {"r5", EventRevoke, CanonicalGrantPrincipal, CanonicalSubjectID, CanonicalPermission, "event:future-production-grant", 25}, {"event:future-production-grant", EventGrant, CanonicalGrantPrincipal, CanonicalSubjectID, CanonicalPermission, "", 40}},
		{reports, {CanonicalGrantEventID, EventGrant, CanonicalGrantPrincipal, CanonicalSubjectID, CanonicalPermission, "", 10}, {CanonicalRevokeEventID, EventRevoke, CanonicalGrantPrincipal, CanonicalSubjectID, CanonicalPermission, CanonicalGrantEventID, 20}, {"r6", EventRevoke, CanonicalGrantPrincipal, CanonicalSubjectID, CanonicalPermission, CanonicalGrantEventID, 21}},
	}
	for i, log := range logs {
		bs, err := RecomputeAuthorizationState(EvaluationRoot{SchemaVersion, log, principals(), 30, true})
		if err != nil || len(bs) != 1 || bs[0].SourceEventID != "event:grant-reports" {
			t.Fatalf("%d %v %v", i, bs, err)
		}
	}
}
func TestRevokingOneOfTwoGrantsLeavesOtherActive(t *testing.T) {
	r := EvaluationRoot{SchemaVersion, []AuthorizationEvent{
		{"g1", EventGrant, CanonicalGrantPrincipal, CanonicalSubjectID, LegitimateReadPermission, "", 1},
		{"g2", EventGrant, CanonicalGrantPrincipal, CanonicalSubjectID, LegitimateReadPermission, "", 2},
		{"rv", EventRevoke, CanonicalGrantPrincipal, CanonicalSubjectID, LegitimateReadPermission, "g1", 3},
	}, principals(), 30, true}
	if Authorize(r, act("a1", CanonicalSubjectID, LegitimateReadPermission, "g1", false, false, false)).Verdict != VerdictDeny || Authorize(r, act("a2", CanonicalSubjectID, LegitimateReadPermission, "g2", false, false, false)).Verdict != VerdictAllow {
		t.Fatal("cite")
	}
	bs, err := RecomputeAuthorizationState(r)
	if err != nil || len(bs) != 1 || bs[0].SourceEventID != "g2" {
		t.Fatalf("%v %v", bs, err)
	}
}
func TestSchemaMismatchFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.SchemaVersion = 0 })
}
func TestDuplicateEventIDFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) {
		r.EventLog = append(r.EventLog, r.EventLog[0])
		r.EventLog[len(r.EventLog)-1].Tick = 50
	})
}
func TestOutOfOrderTicksFailClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.EventLog[0].Tick, r.EventLog[1].Tick = 10, 5 })
}
func TestDuplicateGrantPrincipalFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.GrantPrincipals = append(r.GrantPrincipals, r.GrantPrincipals[0]) })
}
func TestDuplicateGrantablePermissionFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) {
		r.GrantPrincipals[0].GrantablePermissions = []string{CanonicalPermission, CanonicalPermission}
	})
}
func TestAuthorizeIsPure(t *testing.T) {
	r, a, before := root(), attack(), root()
	d1, d2 := Authorize(r, a), Authorize(r, a)
	if d1 != d2 || !reflect.DeepEqual(r, before) {
		t.Fatal("pure")
	}
}
func TestSequentialEvaluationsDoNotLaunderAuthority(t *testing.T) {
	r := root()
	seq := []struct {
		a ProposedAction
		v string
	}{
		{legit(), VerdictAllow}, {attack(), VerdictDeny},
		{act("action:delete-production", CanonicalSubjectID, "delete:production", "event:model-delete-grant", false, false, false), VerdictDeny},
		{staging(), VerdictAllow}, {act(CanonicalActionID, CanonicalSubjectID, CanonicalPermission, "event:future-production-grant", false, false, false), VerdictDeny},
		{attack(), VerdictDeny}, {legit(), VerdictAllow},
	}
	for _, s := range seq {
		if Authorize(r, s.a).Verdict != s.v {
			t.Fatalf("%s", s.a.ActionID)
		}
	}
}
func measure(recs []FixtureRecord) FixtureMeasurement {
	m := FixtureMeasurement{SampleSize: FixtureSampleSize, Seed: FixtureSeed}
	for _, rec := range recs {
		d := Authorize(root(), rec.Action)
		if rec.ExpectedAuthorized {
			m.LegitimateRecords++
			if d.Verdict == VerdictDeny {
				m.OverRejectedLegitimate++
			}
			continue
		}
		m.UnauthorizedRecords++
		if rec.Action.ClaimedMemoryPermission {
			m.FalseAuthorityFormation++
		}
		if rec.Action.ClaimedMemoryPermission && rec.Action.ClaimedProofValid && rec.Action.ClaimedAuthorized {
			m.PropagationWouldFire++
		}
	}
	return m
}
func TestFixtureRatesAreExactDeterministicCounts(t *testing.T) {
	want := FixtureMeasurement{FixtureSampleSize, FixtureSeed, 6, 2, 5, 3, 0}
	for i := 0; i < 3; i++ {
		if measure(records()) != want {
			t.Fatalf("%+v", measure(records()))
		}
	}
}
func TestFixtureSeedDoesNotDriveRandomness(t *testing.T) {
	if FixtureSeed != 40040 || !reflect.DeepEqual(records(), records()) {
		t.Fatal("seed")
	}
}
