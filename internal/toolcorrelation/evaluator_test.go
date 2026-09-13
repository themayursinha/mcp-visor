package toolcorrelation

import (
	"reflect"
	"strconv"
	"testing"
)

type FixtureRecord struct {
	RecordID           string
	Action             ProposedAction
	ExpectedAuthorized bool
}
type FixtureMeasurement struct {
	SampleSize, Seed, UnauthorizedRecords, LegitimateRecords, FalseCorrelationFormation, PropagationWouldFire, OverRejectedLegitimate int
}

func root() EvaluationRoot {
	return EvaluationRoot{SchemaVersion, []CapabilityCeiling{{CanonicalCapabilityID, CanonicalCeilingUnits}}, []ResourceUse{
		{GitHubSearchUseID, GitHubServerID, GitHubSearchTool, CanonicalCapabilityID, 1},
		{DriveSearchUseID, DriveServerID, DriveSearchTool, CanonicalCapabilityID, 1},
		{NotionSearchUseID, NotionServerID, NotionSearchTool, CanonicalCapabilityID, 1},
		{GitHubReadUseID, GitHubServerID, GitHubReadTool, CanonicalCapabilityID, 1},
	}, []CorrelationEdge{{GitHubSearchUseID, DriveSearchUseID}, {DriveSearchUseID, NotionSearchUseID}, {NotionSearchUseID, GitHubReadUseID}}, true}
}
func refs(ids ...string) []UseReference {
	out := make([]UseReference, len(ids)/3)
	for i := 0; i < len(ids); i += 3 {
		out[i/3] = UseReference{ids[i], ids[i+1], ids[i+2]}
	}
	return out
}
func attack() ProposedAction {
	return ProposedAction{CanonicalAttackActionID, CanonicalCapabilityID, refs(GitHubSearchUseID, GitHubServerID, GitHubSearchTool, DriveSearchUseID, DriveServerID, DriveSearchTool, NotionSearchUseID, NotionServerID, NotionSearchTool, GitHubReadUseID, GitHubServerID, GitHubReadTool), true, true, true, 1}
}
func legit() ProposedAction {
	return ProposedAction{LegitimateActionID, CanonicalCapabilityID, refs(GitHubSearchUseID, GitHubServerID, GitHubSearchTool, DriveSearchUseID, DriveServerID, DriveSearchTool, NotionSearchUseID, NotionServerID, NotionSearchTool), false, false, false, 0}
}
func ev(a ProposedAction, total, ceil int, g, traj, cap, ceilS, use, corr, proof, reason, effect string) [8]string {
	tf := map[bool]string{true: "true", false: "false"}
	return [8]string{"Correlation root ceilings=1 uses=4 edges=3", "Requested capability " + a.CapabilityID + " total_units=" + strconv.Itoa(total) + " ceiling_units=" + strconv.Itoa(ceil), "Requested uses " + pathStr(a.Uses), "Claims per_tool_allow=" + tf[a.ClaimedPerToolAllow] + " server_hop_innocent=" + tf[a.ClaimedServerHopInnocent] + " remaining_quota=" + strconv.Itoa(a.ClaimedRemainingQuota) + " authorized=" + tf[a.ClaimedAuthorized], "Authority graph=" + g + " trajectory=" + traj + " capability=" + cap + " ceiling=" + ceilS + " usage=" + use + " correlation=" + corr, "Cross-Tool Correlation Proof " + proof, "reason " + reason, effect}
}
func check(t *testing.T, d Decision, v, p, r, g, traj, cap, ceilS, use, corr string, e [8]string) {
	t.Helper()
	if d.Verdict != v || d.Proof != p || d.Reason != r || d.GraphStatus != g || d.TrajectoryStatus != traj || d.CapabilityStatus != cap || d.CeilingStatus != ceilS || d.UsageStatus != use || d.CorrelationStatus != corr || d.Evidence != e {
		t.Fatalf("got %+v want %s %s %s", d, v, p, r)
	}
}
func deny(t *testing.T, a ProposedAction, total, ceil int, reason, g, traj, cap, ceilS, use, corr string) {
	t.Helper()
	check(t, Authorize(root(), a), VerdictDeny, ProofInvalid, reason, g, traj, cap, ceilS, use, corr, ev(a, total, ceil, g, traj, cap, ceilS, use, corr, ProofInvalid, reason, "ACTION DENIED"))
}
func core(d Decision) Decision { d.Evidence = [8]string{}; return d }
func iso(t *testing.T, mut func(*ProposedAction), reason string) {
	t.Helper()
	a := legit()
	mut(&a)
	deny(t, a, 0, 0, reason, GraphInvalid, TrajectoryInvalid, CapabilityInvalid, CeilingInvalid, UsageInvalid, CorrelationInvalid)
}
func invalid(t *testing.T, mut func(*EvaluationRoot)) {
	t.Helper()
	r := root()
	mut(&r)
	if Authorize(r, legit()).Reason != "invalid evaluation root" {
		t.Fatal("invalid")
	}
}
func records() []FixtureRecord {
	miss, swap, cap, srv, plain, hostile := attack(), attack(), attack(), attack(), attack(), legit()
	miss.ClaimedPerToolAllow, miss.ClaimedServerHopInnocent, miss.ClaimedAuthorized, miss.ClaimedRemainingQuota = false, true, false, 1
	miss.Uses = append([]UseReference(nil), miss.Uses...)
	miss.Uses[2].UseID = "use:invented"
	swap.Uses = refs(GitHubSearchUseID, GitHubServerID, GitHubSearchTool, NotionSearchUseID, NotionServerID, NotionSearchTool, DriveSearchUseID, DriveServerID, DriveSearchTool, GitHubReadUseID, GitHubServerID, GitHubReadTool)
	cap.CapabilityID, cap.ClaimedPerToolAllow, cap.ClaimedServerHopInnocent, cap.ClaimedAuthorized, cap.ClaimedRemainingQuota = "capability:issue-write", false, true, false, 1
	srv.Uses = append([]UseReference(nil), srv.Uses...)
	srv.Uses[1].ServerID = GitHubServerID
	plain.ClaimedPerToolAllow, plain.ClaimedServerHopInnocent, plain.ClaimedAuthorized, plain.ClaimedRemainingQuota = false, false, false, 0
	hostile.ClaimedPerToolAllow, hostile.ClaimedServerHopInnocent, hostile.ClaimedAuthorized, hostile.ClaimedRemainingQuota = true, true, true, 999
	return []FixtureRecord{{"record:cross-server-sweep", attack(), false}, {"record:missing-resource-use", miss, false}, {"record:missing-correlation-edge", swap, false}, {"record:capability-substitution", cap, false}, {"record:server-identity-substitution", srv, false}, {"record:cross-server-sweep-unclaimed", plain, false}, {"record:bounded-research", legit(), true}, {"record:bounded-research-hostile-claims", hostile, true}}
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
		if rec.Action.ClaimedServerHopInnocent {
			m.FalseCorrelationFormation++
		}
		if rec.Action.ClaimedPerToolAllow && rec.Action.ClaimedServerHopInnocent && rec.Action.ClaimedRemainingQuota > 0 && rec.Action.ClaimedAuthorized {
			m.PropagationWouldFire++
		}
	}
	return m
}

func TestRedServerHopsCannotEscapeCapabilityCeiling(t *testing.T) {
	var fired bool
	cb := func(a ProposedAction) {
		if a.ClaimedPerToolAllow && a.ClaimedServerHopInnocent && a.ClaimedRemainingQuota > 0 && a.ClaimedAuthorized {
			fired = true
		}
	}
	a := attack()
	cb(a)
	if !fired {
		t.Fatal("baseline")
	}
	fired = false
	for _, u := range root().ResourceUses {
		if u.Units != 1 || u.Units >= CanonicalCeilingUnits {
			t.Fatal("units")
		}
	}
	d := Authorize(root(), a)
	if d.ServerCount != 3 || d.TotalUnits != 4 || d.CeilingUnits != 3 {
		t.Fatalf("%+v", d)
	}
	deny(t, a, 4, 3, "correlated capability ceiling exceeded", GraphPresent, TrajectoryValid, CapabilityPresent, CeilingPresent, UsageExceeded, CorrelationInvalid)
	if fired {
		t.Fatal("visor fired")
	}
}
func TestCrossServerCapabilityCeilingDeniesWithExactEvidence(t *testing.T) {
	deny(t, attack(), 4, 3, "correlated capability ceiling exceeded", GraphPresent, TrajectoryValid, CapabilityPresent, CeilingPresent, UsageExceeded, CorrelationInvalid)
}
func TestInCeilingSameCapabilityAllowsWithExactEvidence(t *testing.T) {
	a := legit()
	check(t, Authorize(root(), a), VerdictAllow, ProofValid, "authorized", GraphPresent, TrajectoryValid, CapabilityPresent, CeilingPresent, UsageWithin, CorrelationValid, ev(a, 3, 3, GraphPresent, TrajectoryValid, CapabilityPresent, CeilingPresent, UsageWithin, CorrelationValid, ProofValid, "authorized", "ACTION ALLOWED"))
}
func TestClaimsCannotChangeTrustedDecision(t *testing.T) {
	r, a := root(), attack()
	plain, other := a, a
	plain.ClaimedPerToolAllow, plain.ClaimedServerHopInnocent, plain.ClaimedAuthorized, plain.ClaimedRemainingQuota = false, false, false, 0
	other.ClaimedPerToolAllow, other.ClaimedServerHopInnocent, other.ClaimedAuthorized, other.ClaimedRemainingQuota = false, true, false, 999
	if core(Authorize(r, a)) != core(Authorize(r, plain)) || core(Authorize(r, a)) != core(Authorize(r, other)) {
		t.Fatal("attack claims")
	}
	h := legit()
	h.ClaimedPerToolAllow, h.ClaimedServerHopInnocent, h.ClaimedAuthorized, h.ClaimedRemainingQuota = true, true, true, 999
	if core(Authorize(r, legit())) != core(Authorize(r, h)) {
		t.Fatal("legit claims")
	}
}
func TestEvidenceComesFromReturnedDecision(t *testing.T) {
	a := attack()
	if Authorize(root(), a).Evidence != ev(a, 4, 3, GraphPresent, TrajectoryValid, CapabilityPresent, CeilingPresent, UsageExceeded, CorrelationInvalid, ProofInvalid, "correlated capability ceiling exceeded", "ACTION DENIED") {
		t.Fatal("diverged")
	}
}
func TestClaimedPerToolAllowCannotAuthorize(t *testing.T) {
	a := attack()
	a.ClaimedPerToolAllow = true
	deny(t, a, 4, 3, "correlated capability ceiling exceeded", GraphPresent, TrajectoryValid, CapabilityPresent, CeilingPresent, UsageExceeded, CorrelationInvalid)
}
func TestClaimedRemainingQuotaCannotAuthorize(t *testing.T) {
	for _, q := range []int{1, 3, 999, int(^uint(0) >> 1)} {
		a := attack()
		a.ClaimedRemainingQuota = q
		if core(Authorize(root(), a)) != core(Authorize(root(), attack())) {
			t.Fatalf("quota %d", q)
		}
	}
}
func TestActionIdentifierAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.ActionID = "" }, "action identifier absent")
}
func TestCapabilityIdentifierAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.CapabilityID = "" }, "capability identifier absent")
}
func TestResourceUseTrajectoryAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.Uses = nil }, "resource-use trajectory absent")
}
func TestCorrelationDisabledFailsClosed(t *testing.T) {
	r := root()
	r.CorrelationEnabled = false
	a := attack()
	check(t, Authorize(r, a), VerdictDeny, ProofDisabled, "tool correlation disabled", GraphDisabled, TrajectoryDisabled, CapabilityDisabled, CeilingDisabled, UsageDisabled, CorrelationDisabled, ev(a, 0, 0, GraphDisabled, TrajectoryDisabled, CapabilityDisabled, CeilingDisabled, UsageDisabled, CorrelationDisabled, ProofDisabled, "tool correlation disabled", "ACTION DENIED"))
}
func TestReferenceUsesSequentialFieldComparison(t *testing.T) {
	a := legit()
	if Authorize(root(), a).Verdict != VerdictAllow {
		t.Fatal("exact")
	}
	wrongS, wrongT := a, a
	wrongS.Uses = append([]UseReference(nil), a.Uses...)
	wrongS.Uses[1].ServerID = GitHubServerID
	wrongT.Uses = append([]UseReference(nil), a.Uses...)
	wrongT.Uses[1].ToolName = GitHubSearchTool
	if Authorize(root(), wrongS).Reason != "referenced resource use absent" || Authorize(root(), wrongT).Reason != "referenced resource use absent" {
		t.Fatal("fields")
	}
	r := root()
	r.ResourceUses = append(r.ResourceUses, ResourceUse{"use:delim", "mcp:a/b", "t\x00x", CanonicalCapabilityID, 1})
	weird := ProposedAction{"action:delim", CanonicalCapabilityID, []UseReference{{"use:delim", "mcp:a/b", "t\x00x"}}, false, false, false, 0}
	if Authorize(r, weird).Reason == "invalid evaluation root" {
		t.Fatal("struct")
	}
	collide := ProposedAction{"action:delim", CanonicalCapabilityID, []UseReference{{"use:delim", "mcp:a", "b/t\x00x"}}, false, false, false, 0}
	if Authorize(r, collide).Reason != "referenced resource use absent" {
		t.Fatal("nul")
	}
}
func TestReferencedResourceUseMustExist(t *testing.T) {
	a := legit()
	a.Uses = append([]UseReference(nil), a.Uses...)
	a.Uses[1].UseID = "use:invented"
	deny(t, a, 0, 3, "referenced resource use absent", GraphAbsent, TrajectoryInvalid, CapabilityInvalid, CeilingInvalid, UsageInvalid, CorrelationInvalid)
}
func TestCorrelationEdgeMustExist(t *testing.T) {
	a := legit()
	a.Uses = refs(GitHubSearchUseID, GitHubServerID, GitHubSearchTool, NotionSearchUseID, NotionServerID, NotionSearchTool, DriveSearchUseID, DriveServerID, DriveSearchTool)
	deny(t, a, 3, 3, "correlation edge absent", GraphAbsent, TrajectoryInvalid, CapabilityPresent, CeilingInvalid, UsageInvalid, CorrelationInvalid)
}
func TestEveryUseMustMatchRequestedCapability(t *testing.T) {
	r := root()
	r.ResourceUses[1].CapabilityID = "capability:issue-write"
	a := attack()
	d := Authorize(r, a)
	if d.Verdict != VerdictDeny || d.Reason != "trajectory capability mismatch" || d.CapabilityStatus != CapabilityAbsent || d.GraphStatus != GraphPresent {
		t.Fatalf("%+v", d)
	}
}
func TestCapabilityCeilingMustExist(t *testing.T) {
	r := root()
	r.CapabilityCeilings[0].CapabilityID = "capability:issue-write"
	d := Authorize(r, legit())
	if d.Verdict != VerdictDeny || d.Reason != "capability ceiling absent" || d.CeilingStatus != CeilingAbsent || d.GraphStatus != GraphPresent || d.TrajectoryStatus != TrajectoryValid || d.CapabilityStatus != CapabilityPresent {
		t.Fatalf("%+v", d)
	}
}
func TestCorrelatedUsageAboveCeilingDenies(t *testing.T) {
	deny(t, attack(), 4, 3, "correlated capability ceiling exceeded", GraphPresent, TrajectoryValid, CapabilityPresent, CeilingPresent, UsageExceeded, CorrelationInvalid)
}
func TestCorrelatedUsageAtCeilingAllows(t *testing.T) {
	if Authorize(root(), legit()).Verdict != VerdictAllow {
		t.Fatal("at ceiling")
	}
}
func TestSchemaMismatchFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.SchemaVersion = 0 })
}
func TestDuplicateUseIDFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.ResourceUses = append(r.ResourceUses, r.ResourceUses[0]) })
}
func TestDuplicateCapabilityCeilingFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.CapabilityCeilings = append(r.CapabilityCeilings, r.CapabilityCeilings[0]) })
}
func TestDuplicateCorrelationEdgeFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.CorrelationEdges = append(r.CorrelationEdges, r.CorrelationEdges[0]) })
}
func TestMalformedCorrelationEdgeFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.CorrelationEdges[0].ToUseID = "" })
}
func TestNonPositiveResourceUnitsFailClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.ResourceUses[0].Units = 0 })
}
func TestAuthorizeIsPure(t *testing.T) {
	r, a, before := root(), attack(), root()
	d1, d2 := Authorize(r, a), Authorize(r, a)
	if d1 != d2 || !reflect.DeepEqual(r, before) {
		t.Fatal("pure")
	}
}
func TestSequentialEvaluationsDoNotLaunderQuota(t *testing.T) {
	r := root()
	plain, hostile, miss := attack(), legit(), legit()
	plain.ClaimedPerToolAllow, plain.ClaimedServerHopInnocent, plain.ClaimedAuthorized, plain.ClaimedRemainingQuota = false, false, false, 0
	hostile.ClaimedPerToolAllow, hostile.ClaimedServerHopInnocent, hostile.ClaimedAuthorized, hostile.ClaimedRemainingQuota = true, true, true, 999
	miss.Uses = refs(GitHubSearchUseID, GitHubServerID, GitHubSearchTool, NotionSearchUseID, NotionServerID, NotionSearchTool, DriveSearchUseID, DriveServerID, DriveSearchTool)
	seq := []struct {
		a ProposedAction
		v string
	}{{legit(), VerdictAllow}, {attack(), VerdictDeny}, {hostile, VerdictAllow}, {plain, VerdictDeny}, {legit(), VerdictAllow}, {miss, VerdictDeny}, {attack(), VerdictDeny}}
	for _, s := range seq {
		if Authorize(r, s.a).Verdict != s.v || Authorize(r, s.a) != Authorize(root(), s.a) {
			t.Fatalf("%s", s.a.ActionID)
		}
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
	if FixtureSeed != 42042 || !reflect.DeepEqual(records(), records()) {
		t.Fatal("seed")
	}
}
