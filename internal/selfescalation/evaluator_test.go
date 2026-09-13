package selfescalation

import (
	"reflect"
	"strings"
	"testing"
)

type FixtureRecord struct {
	RecordID           string
	Action             ProposedAction
	ExpectedAuthorized bool
}
type FixtureMeasurement struct {
	SampleSize, Seed, UnauthorizedRecords, LegitimateRecords, FalseEscalationFormation, PropagationWouldFire, OverRejectedLegitimate int
}

func root() EvaluationRoot {
	return EvaluationRoot{SchemaVersion, ParentDelegation{CanonicalDelegationID, CanonicalChild, []string{AuthorityWorkspaceWrite}}, nil, true, []string{SurfaceLoopbackPolicyAPI, SurfaceEnvironment, SurfaceSharedPolicyFile, SurfaceSpoofedHost}}
}
func attack() ProposedAction {
	return ProposedAction{CanonicalAttackActionID, CanonicalChild, AuthorityModifySelf, SurfaceLoopbackPolicyAPI, "localhost", "USER", true, true, true}
}
func legit() ProposedAction {
	return ProposedAction{LegitimateActionID, CanonicalChild, AuthorityWorkspaceWrite, "", "", "", false, false, false}
}
func ev(r EvaluationRoot, a ProposedAction, del, meta, reach, attr, proof, reason, effect string) [8]string {
	tf := map[bool]string{true: "true", false: "false"}
	return [8]string{"Authority root delegation=" + r.ParentDelegation.DelegationID + " child=" + r.ParentDelegation.ChildPrincipal + " allowed=" + itoa(len(r.ParentDelegation.AllowedAuthorities)) + " meta_grants=" + itoa(len(r.MetaAuthorityGrants)) + " surfaces=" + itoa(len(r.ManagementSurfaces)), "Requested action " + a.ActionID + " actor=" + a.ActorPrincipal + " authority=" + a.RequestedAuthority, "Management surface " + none(a.ManagementSurface) + " reachability=" + reach, "Claims host=" + none(a.ClaimedHostHeader) + " attribution=" + none(a.ClaimedUserAttribution) + " danger_full_access=" + tf[a.ClaimedDangerFullAccess] + " policy_rewrite=" + tf[a.ClaimedPolicyRewrite] + " authorized=" + tf[a.ClaimedAuthorized], "Authority delegation=" + del + " meta=" + meta + " attribution=" + attr, proofLine(proof, a.RequestedAuthority), "reason " + reason, effect}
}
func itoa(n int) string { return evNum[n] }

var evNum = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8"}

func check(t *testing.T, r EvaluationRoot, a ProposedAction, v, p, reason, del, meta, reach, attr string) {
	t.Helper()
	d := Authorize(r, a)
	e := ev(r, a, del, meta, reach, attr, p, reason, map[bool]string{true: "ACTION ALLOWED", false: "ACTION DENIED"}[v == VerdictAllow])
	if d.Verdict != v || d.Proof != p || d.Reason != reason || d.DelegationAuthority != del || d.MetaAuthority != meta || d.SurfaceReachability != reach || d.Attribution != attr || d.Evidence != e || d.ActionID != a.ActionID {
		t.Fatalf("got %+v", d)
	}
}
func iso(t *testing.T, mut func(*ProposedAction), reason string) {
	t.Helper()
	a := legit()
	mut(&a)
	check(t, root(), a, VerdictDeny, ProofInvalid, reason, DelegationInvalid, MetaInvalid, ReachabilityInvalid, AttributionInvalid)
}
func invalid(t *testing.T, mut func(*EvaluationRoot)) {
	t.Helper()
	r := root()
	mut(&r)
	if Authorize(r, legit()).Reason != "invalid evaluation root" {
		t.Fatal("invalid")
	}
}
func granted() EvaluationRoot {
	r := root()
	r.ParentDelegation.AllowedAuthorities = []string{AuthorityWorkspaceWrite, AuthorityModifySelf}
	r.MetaAuthorityGrants = []MetaAuthorityGrant{{"grant:self-management", CanonicalChild, AuthorityModifySelf, ProofTypeMetaAuthority}}
	return r
}
func records() []FixtureRecord {
	env, file, host, ox, herm, hostile := attack(), attack(), attack(), attack(), attack(), legit()
	env.ManagementSurface = SurfaceEnvironment
	file.ManagementSurface = SurfaceSharedPolicyFile
	host.ManagementSurface, host.ClaimedHostHeader, host.ClaimedAuthorized = SurfaceSpoofedHost, "visor.internal", false
	ox.ClaimedDangerFullAccess = false
	herm.ManagementSurface, herm.ClaimedPolicyRewrite = SurfaceSharedPolicyFile, false
	hostile.ClaimedHostHeader, hostile.ClaimedUserAttribution, hostile.ClaimedDangerFullAccess, hostile.ClaimedPolicyRewrite, hostile.ClaimedAuthorized = "localhost", "USER", true, true, true
	return []FixtureRecord{{"record:loopback-policy-api", attack(), false}, {"record:environment-policy-control", env, false}, {"record:shared-policy-file", file, false}, {"record:spoofed-host", host, false}, {"record:ox-research-cve-2026-82533-deepseek-harness-self-disable-sandbox", ox, false}, {"record:hermes-cross-profile-terminal-authority-bleed", herm, false}, {"record:legitimate-workspace-write", legit(), true}, {"record:legitimate-workspace-write-hostile-claims", hostile, true}}
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
		if rec.Action.ClaimedPolicyRewrite {
			m.FalseEscalationFormation++
		}
		if rec.Action.ClaimedDangerFullAccess && rec.Action.ClaimedPolicyRewrite && rec.Action.ClaimedAuthorized {
			m.PropagationWouldFire++
		}
	}
	return m
}

func TestRedConfinedAgentCannotGrantItselfAuthority(t *testing.T) {
	var fired bool
	cb := func(a ProposedAction) {
		if a.ClaimedDangerFullAccess && a.ClaimedPolicyRewrite && a.ClaimedAuthorized {
			fired = true
		}
	}
	a := attack()
	cb(a)
	if !fired {
		t.Fatal("baseline")
	}
	fired = false
	check(t, root(), a, VerdictDeny, ProofMissing, "meta-authority proof missing", DelegationAbsent, MetaMissing, ReachabilityPresent, AttributionAgent)
	if fired {
		t.Fatal("callback")
	}
}
func TestCanonicalSelfEscalationDeniedWithExactEvidence(t *testing.T) {
	check(t, root(), attack(), VerdictDeny, ProofMissing, "meta-authority proof missing", DelegationAbsent, MetaMissing, ReachabilityPresent, AttributionAgent)
}
func TestLegitimateWorkspaceWriteAllowsWithExactEvidence(t *testing.T) {
	check(t, root(), legit(), VerdictAllow, ProofValid, "authorized", DelegationPresent, MetaNotRequired, ReachabilityAbsent, AttributionAgent)
}
func TestPolicySelfModifyDenied(t *testing.T) {
	check(t, root(), attack(), VerdictDeny, ProofMissing, "meta-authority proof missing", DelegationAbsent, MetaMissing, ReachabilityPresent, AttributionAgent)
}
func TestClaimsCannotChangeTrustedDecision(t *testing.T) {
	plain, flip := attack(), attack()
	plain.ClaimedHostHeader, plain.ClaimedUserAttribution, plain.ClaimedDangerFullAccess, plain.ClaimedPolicyRewrite, plain.ClaimedAuthorized = "", "", false, false, false
	flip.ClaimedHostHeader, flip.ClaimedUserAttribution, flip.ClaimedDangerFullAccess, flip.ClaimedPolicyRewrite, flip.ClaimedAuthorized = "visor.internal", "AGENT", false, false, false
	core := func(d Decision) Decision { d.Evidence[3] = ""; return d }
	d1, d2, d3 := Authorize(root(), attack()), Authorize(root(), plain), Authorize(root(), flip)
	if core(d1) != core(d2) || core(d1) != core(d3) {
		t.Fatal("claims")
	}
	h := legit()
	h.ClaimedHostHeader, h.ClaimedUserAttribution, h.ClaimedDangerFullAccess, h.ClaimedPolicyRewrite, h.ClaimedAuthorized = "localhost", "USER", true, true, true
	if Authorize(root(), h).Verdict != VerdictAllow {
		t.Fatal("legit")
	}
}
func TestClaimedUserAttributionRemainsAgent(t *testing.T) {
	a := attack()
	d := Authorize(root(), a)
	if a.ClaimedUserAttribution != "USER" || a.ActorPrincipal != CanonicalChild || d.Attribution != AttributionAgent || !strings.Contains(d.Evidence[3], "attribution=USER") || !strings.Contains(d.Evidence[4], "attribution=AGENT") || d.MetaAuthority != MetaMissing {
		t.Fatal("user")
	}
}
func TestManagementSurfaceReachabilityConveysNoAuthority(t *testing.T) {
	for _, s := range []string{SurfaceLoopbackPolicyAPI, SurfaceEnvironment, SurfaceSharedPolicyFile, SurfaceSpoofedHost, "", "surface:unknown"} {
		a := attack()
		a.ManagementSurface = s
		d := Authorize(root(), a)
		if d.Verdict != VerdictDeny || d.Proof != ProofMissing || d.Reason != "meta-authority proof missing" || d.Attribution != AttributionAgent {
			t.Fatalf("%s %+v", s, d)
		}
	}
}
func TestEvidenceComesFromReturnedDecision(t *testing.T) {
	a, r := attack(), root()
	if Authorize(r, a).Evidence != ev(r, a, DelegationAbsent, MetaMissing, ReachabilityPresent, AttributionAgent, ProofMissing, "meta-authority proof missing", "ACTION DENIED") {
		t.Fatal("evidence")
	}
}
func TestActionIdentifierAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.ActionID = "" }, "action identifier absent")
}
func TestActorPrincipalAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.ActorPrincipal = "" }, "actor principal absent")
}
func TestRequestedAuthorityAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.RequestedAuthority = "" }, "requested authority absent")
}
func TestActorMustMatchParentDelegation(t *testing.T) {
	a := legit()
	a.ActorPrincipal = "user:claimed"
	check(t, root(), a, VerdictDeny, ProofInvalid, "actor outside parent delegation", DelegationInvalid, MetaNotRequired, ReachabilityAbsent, AttributionInvalid)
}
func TestRequestedAuthorityMustBeParentDelegated(t *testing.T) {
	a := legit()
	a.RequestedAuthority = AuthorityModifySelf
	check(t, root(), a, VerdictDeny, ProofMissing, "meta-authority proof missing", DelegationAbsent, MetaMissing, ReachabilityAbsent, AttributionAgent)
}
func TestMetaAuthorityDisabledFailsClosed(t *testing.T) {
	r := root()
	r.MetaAuthorityEnabled = false
	check(t, r, attack(), VerdictDeny, ProofDisabled, "meta-authority enforcement disabled", DelegationAbsent, MetaDisabled, ReachabilityDisabled, AttributionDisabled)
}
func TestOrdinaryActionProofIsNotMetaAuthority(t *testing.T) {
	r := granted()
	r.MetaAuthorityGrants[0].ProofType = ProofTypeOrdinaryAction
	check(t, r, attack(), VerdictDeny, ProofMissing, "meta-authority proof missing", DelegationPresent, MetaMissing, ReachabilityPresent, AttributionAgent)
}
func TestMetaAuthorityGrantMustMatchGrantee(t *testing.T) {
	r := granted()
	r.MetaAuthorityGrants[0].GranteePrincipal = "agent:other"
	check(t, r, attack(), VerdictDeny, ProofMissing, "meta-authority proof missing", DelegationPresent, MetaMissing, ReachabilityPresent, AttributionAgent)
}
func TestMetaAuthorityGrantMustMatchAuthority(t *testing.T) {
	r := granted()
	r.MetaAuthorityGrants[0].Authority = AuthorityWorkspaceWrite
	check(t, r, attack(), VerdictDeny, ProofMissing, "meta-authority proof missing", DelegationPresent, MetaMissing, ReachabilityPresent, AttributionAgent)
}
func TestTypedMetaAuthorityGrantAuthorizesWithoutExecuting(t *testing.T) {
	var fired bool
	d := Authorize(granted(), attack())
	if d.Verdict != VerdictAllow || d.Proof != ProofValid || d.DelegationAuthority != DelegationPresent || d.MetaAuthority != MetaPresent || d.Attribution != AttributionAgent || fired {
		t.Fatalf("%+v", d)
	}
}
func TestSchemaMismatchFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.SchemaVersion = 0 })
}
func TestDuplicateAllowedAuthorityFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) {
		r.ParentDelegation.AllowedAuthorities = []string{AuthorityWorkspaceWrite, AuthorityWorkspaceWrite}
	})
}
func TestDuplicateMetaGrantIDFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) {
		g := MetaAuthorityGrant{"grant:x", CanonicalChild, AuthorityModifySelf, ProofTypeMetaAuthority}
		r.MetaAuthorityGrants = []MetaAuthorityGrant{g, g}
	})
}
func TestDuplicateManagementSurfaceFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.ManagementSurfaces = []string{SurfaceEnvironment, SurfaceEnvironment} })
}
func TestAuthorizeIsPure(t *testing.T) {
	r, a, before := root(), attack(), root()
	d1, d2 := Authorize(r, a), Authorize(r, a)
	if d1 != d2 || !reflect.DeepEqual(r, before) {
		t.Fatal("pure")
	}
}
func TestSequentialEvaluationsDoNotTransferAuthority(t *testing.T) {
	r, off := root(), root()
	off.MetaAuthorityEnabled = false
	plain, hostile := attack(), legit()
	plain.ClaimedHostHeader, plain.ClaimedUserAttribution, plain.ClaimedDangerFullAccess, plain.ClaimedPolicyRewrite, plain.ClaimedAuthorized = "", "", false, false, false
	hostile.ClaimedHostHeader, hostile.ClaimedUserAttribution, hostile.ClaimedDangerFullAccess, hostile.ClaimedPolicyRewrite, hostile.ClaimedAuthorized = "localhost", "USER", true, true, true
	seq := []struct {
		root EvaluationRoot
		a    ProposedAction
		v    string
	}{{r, legit(), VerdictAllow}, {r, attack(), VerdictDeny}, {r, plain, VerdictDeny}, {r, hostile, VerdictAllow}, {off, attack(), VerdictDeny}, {r, attack(), VerdictDeny}, {r, legit(), VerdictAllow}}
	for _, s := range seq {
		if Authorize(s.root, s.a).Verdict != s.v || Authorize(s.root, s.a) != Authorize(s.root, s.a) {
			t.Fatalf("%s", s.a.ActionID)
		}
	}
}
func TestTrustedDecisionsUseSequentialFieldComparison(t *testing.T) {
	d1, d2 := Authorize(root(), attack()), Authorize(root(), attack())
	if d1.ActionID != d2.ActionID || d1.DelegationID != d2.DelegationID || d1.ActorPrincipal != d2.ActorPrincipal || d1.RequestedAuthority != d2.RequestedAuthority || d1.ManagementSurface != d2.ManagementSurface || d1.Verdict != d2.Verdict || d1.Proof != d2.Proof || d1.Reason != d2.Reason || d1.DelegationAuthority != d2.DelegationAuthority || d1.MetaAuthority != d2.MetaAuthority || d1.SurfaceReachability != d2.SurfaceReachability || d1.Attribution != d2.Attribution {
		t.Fatal("fields")
	}
	for i := 0; i < 8; i++ {
		if d1.Evidence[i] != d2.Evidence[i] {
			t.Fatal("evidence")
		}
	}
	if d1 != d2 {
		t.Fatal("eq")
	}
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
	if FixtureSeed != 43043 || !reflect.DeepEqual(records(), records()) {
		t.Fatal("seed")
	}
}
func TestSourceSignalsAreFixtureNamesOnly(t *testing.T) {
	ox, hermes := "record:ox-research-cve-2026-82533-deepseek-harness-self-disable-sandbox", "record:hermes-cross-profile-terminal-authority-bleed"
	seen := map[string]int{}
	for _, rec := range records() {
		seen[rec.RecordID]++
		a, d := rec.Action, Authorize(root(), rec.Action)
		blob := a.ActionID + a.ActorPrincipal + a.RequestedAuthority + a.ManagementSurface + d.Reason + strings.Join(d.Evidence[:], "")
		if rec.RecordID != ox && rec.RecordID != hermes && (strings.Contains(blob, "CVE-2026-82533") || strings.Contains(blob, "DeepSeek") || strings.Contains(blob, "Hermes")) {
			t.Fatal(rec.RecordID)
		}
		if (rec.RecordID == ox || rec.RecordID == hermes) && (strings.Contains(a.ActionID, "CVE") || strings.Contains(a.ManagementSurface, "Hermes")) {
			t.Fatal("leak")
		}
	}
	if seen[ox] != 1 || seen[hermes] != 1 {
		t.Fatal("ids")
	}
}
