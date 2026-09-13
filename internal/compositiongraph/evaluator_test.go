package compositiongraph

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
	SampleSize, Seed, UnauthorizedRecords, LegitimateRecords, FalseCompositionFormation, PropagationWouldFire, OverRejectedLegitimate int
}

func skills() []InstalledSkill {
	return []InstalledSkill{
		{SkillCredentialDiscovery, []CapabilityEdge{{EdgeDiscoverCredentials, CredentialSource, CredentialArtifact, EffectRead, ""}}},
		{SkillContextNormalizer, []CapabilityEdge{{EdgeNormalizeCredential, CredentialArtifact, ContextArtifact, EffectTransform, ""}}},
		{SkillMCPSubmitter, []CapabilityEdge{{EdgeSubmitExternal, ContextArtifact, ExternalDisclosure, EffectSend, CanonicalDestination}}},
		{SkillReportReader, []CapabilityEdge{{EdgeReadReport, ReportSource, ReportArtifact, EffectRead, ""}}},
		{SkillReportTransformer, []CapabilityEdge{{EdgeTransformReport, ReportArtifact, ReportContext, EffectTransform, ""}}},
		{SkillReportSender, []CapabilityEdge{{EdgeSendReport, ReportContext, ExternalDelivery, EffectSend, CanonicalDestination}}},
	}
}
func mandate() CapabilityMandate {
	return CapabilityMandate{CanonicalMandateID, []string{EffectRead, EffectTransform, EffectSend}, []string{CanonicalDestination}, []string{ReportSource, ReportArtifact, ReportContext, ExternalDelivery}}
}
func root() EvaluationRoot { return EvaluationRoot{SchemaVersion, mandate(), skills(), true} }
func steps(ids ...string) []StepReference {
	out := make([]StepReference, len(ids)/2)
	for i := 0; i < len(ids); i += 2 {
		out[i/2] = StepReference{ids[i], ids[i+1]}
	}
	return out
}
func attack() ProposedAction {
	return ProposedAction{CanonicalAttackActionID, CredentialSource, ExternalDisclosure, CanonicalDestination, steps(SkillCredentialDiscovery, EdgeDiscoverCredentials, SkillContextNormalizer, EdgeNormalizeCredential, SkillMCPSubmitter, EdgeSubmitExternal), true, true, true, true}
}
func legit() ProposedAction {
	return ProposedAction{LegitimateActionID, ReportSource, ExternalDelivery, CanonicalDestination, steps(SkillReportReader, EdgeReadReport, SkillReportTransformer, EdgeTransformReport, SkillReportSender, EdgeSendReport), false, false, false, false}
}
func isolatedA() ProposedAction {
	a := attack()
	a.Steps = steps(SkillCredentialDiscovery, EdgeDiscoverCredentials)
	return a
}
func isolatedB() ProposedAction {
	a := attack()
	a.Steps = steps(SkillContextNormalizer, EdgeNormalizeCredential)
	return a
}
func ev(a ProposedAction, g, cont, eff, dest, art, comp, proof, reason, effect string) [8]string {
	tf := map[bool]string{true: "true", false: "false"}
	return [8]string{"Composition root mandate=" + CanonicalMandateID + " skills=6 edges=6", "Requested flow " + a.StartArtifactClass + "|" + a.FinalArtifactClass + " destination=" + a.Destination, "Declared path " + pathStr(a.Steps), "Claims signatures=" + tf[a.ClaimedSignaturesValid] + " individual_allow=" + tf[a.ClaimedIndividualAllow] + " composition_valid=" + tf[a.ClaimedCompositionValid] + " authorized=" + tf[a.ClaimedAuthorized], "Authority graph=" + g + " continuity=" + cont + " effects=" + eff + " destination=" + dest + " artifacts=" + art + " composition=" + comp, "Capability Composition Proof " + proof, "reason " + reason, effect}
}
func check(t *testing.T, d Decision, v, p, r, g, cont, eff, dest, art, comp string, e [8]string) {
	t.Helper()
	if d.Verdict != v || d.Proof != p || d.Reason != r || d.GraphStatus != g || d.PathContinuity != cont || d.EffectAuthority != eff || d.DestinationAuthority != dest || d.ArtifactAuthority != art || d.CompositionStatus != comp || d.Evidence != e {
		t.Fatalf("got %+v want %s %s %s", d, v, p, r)
	}
}
func deny(t *testing.T, a ProposedAction, reason, g, cont, eff, dest, art, comp string) {
	t.Helper()
	check(t, Authorize(root(), a), VerdictDeny, ProofInvalid, reason, g, cont, eff, dest, art, comp, ev(a, g, cont, eff, dest, art, comp, ProofInvalid, reason, "ACTION DENIED"))
}
func core(d Decision) Decision { d.Evidence = [8]string{}; return d }
func iso(t *testing.T, mut func(*ProposedAction), reason string) {
	t.Helper()
	a := legit()
	mut(&a)
	deny(t, a, reason, GraphInvalid, ContinuityInvalid, AuthorityInvalid, AuthorityInvalid, AuthorityInvalid, CompositionInvalid)
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
	miss, disc, plain, hostile := attack(), attack(), attack(), legit()
	miss.ClaimedSignaturesValid, miss.ClaimedIndividualAllow, miss.ClaimedAuthorized, miss.ClaimedCompositionValid = false, false, false, true
	miss.Steps = append([]StepReference(nil), miss.Steps...)
	miss.Steps[2].EdgeID = "edge:invented"
	disc.ClaimedSignaturesValid, disc.ClaimedIndividualAllow, disc.ClaimedAuthorized, disc.ClaimedCompositionValid = false, false, false, true
	disc.Steps = steps(SkillCredentialDiscovery, EdgeDiscoverCredentials, SkillMCPSubmitter, EdgeSubmitExternal)
	plain.ClaimedSignaturesValid, plain.ClaimedIndividualAllow, plain.ClaimedCompositionValid, plain.ClaimedAuthorized = false, false, false, false
	hostile.ClaimedSignaturesValid, hostile.ClaimedIndividualAllow, hostile.ClaimedCompositionValid, hostile.ClaimedAuthorized = true, true, true, true
	return []FixtureRecord{{"record:credential-disclosure", attack(), false}, {"record:isolated-a-claim", isolatedA(), false}, {"record:isolated-b-claim", isolatedB(), false}, {"record:missing-edge", miss, false}, {"record:discontinuous-path", disc, false}, {"record:credential-disclosure-unclaimed", plain, false}, {"record:legitimate-report", legit(), true}, {"record:legitimate-report-hostile-claims", hostile, true}}
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
		if rec.Action.ClaimedCompositionValid {
			m.FalseCompositionFormation++
		}
		if rec.Action.ClaimedSignaturesValid && rec.Action.ClaimedIndividualAllow && rec.Action.ClaimedCompositionValid && rec.Action.ClaimedAuthorized {
			m.PropagationWouldFire++
		}
	}
	return m
}

func TestRedThreeBenignClaimsCannotAuthorizeCredentialDisclosure(t *testing.T) {
	var fired bool
	cb := func(a ProposedAction) {
		if a.ClaimedSignaturesValid && a.ClaimedIndividualAllow && a.ClaimedCompositionValid && a.ClaimedAuthorized {
			fired = true
		}
	}
	a := attack()
	cb(a)
	if !fired {
		t.Fatal("baseline")
	}
	fired = false
	deny(t, a, "composed artifact trajectory outside mandate", GraphPresent, ContinuityValid, AuthorityPresent, AuthorityPresent, AuthorityAbsent, CompositionInvalid)
	if fired {
		t.Fatal("visor fired")
	}
}
func TestCredentialDisclosureDeniedWithExactEvidence(t *testing.T) {
	deny(t, attack(), "composed artifact trajectory outside mandate", GraphPresent, ContinuityValid, AuthorityPresent, AuthorityPresent, AuthorityAbsent, CompositionInvalid)
}
func TestLegitimateCompositionAllowsWithExactEvidence(t *testing.T) {
	a := legit()
	check(t, Authorize(root(), a), VerdictAllow, ProofValid, "authorized", GraphPresent, ContinuityValid, AuthorityPresent, AuthorityPresent, AuthorityPresent, CompositionValid, ev(a, GraphPresent, ContinuityValid, AuthorityPresent, AuthorityPresent, AuthorityPresent, CompositionValid, ProofValid, "authorized", "ACTION ALLOWED"))
}
func TestClaimsCannotChangeTrustedDecision(t *testing.T) {
	r, a := root(), attack()
	plain, other := a, a
	plain.ClaimedSignaturesValid, plain.ClaimedIndividualAllow, plain.ClaimedCompositionValid, plain.ClaimedAuthorized = false, false, false, false
	other.ClaimedSignaturesValid, other.ClaimedIndividualAllow, other.ClaimedCompositionValid, other.ClaimedAuthorized = false, true, false, true
	if core(Authorize(r, a)) != core(Authorize(r, plain)) || core(Authorize(r, a)) != core(Authorize(r, other)) {
		t.Fatal("attack claims")
	}
	h := legit()
	h.ClaimedSignaturesValid, h.ClaimedIndividualAllow, h.ClaimedCompositionValid, h.ClaimedAuthorized = true, true, true, true
	if core(Authorize(r, legit())) != core(Authorize(r, h)) {
		t.Fatal("legit claims")
	}
}
func TestIsolatedAClaimCannotAuthorizeSubmit(t *testing.T) {
	deny(t, isolatedA(), "capability path endpoint mismatch", GraphPresent, ContinuityInvalid, AuthorityPresent, AuthorityPresent, AuthorityAbsent, CompositionInvalid)
}
func TestIsolatedBClaimCannotAuthorizeSubmit(t *testing.T) {
	deny(t, isolatedB(), "capability path not contiguous", GraphPresent, ContinuityInvalid, AuthorityPresent, AuthorityPresent, AuthorityAbsent, CompositionInvalid)
}
func TestEvidenceComesFromReturnedDecision(t *testing.T) {
	a := attack()
	if Authorize(root(), a).Evidence != ev(a, GraphPresent, ContinuityValid, AuthorityPresent, AuthorityPresent, AuthorityAbsent, CompositionInvalid, ProofInvalid, "composed artifact trajectory outside mandate", "ACTION DENIED") {
		t.Fatal("diverged")
	}
}
func TestActionIdentifierAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.ActionID = "" }, "action identifier absent")
}
func TestStartArtifactClassAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.StartArtifactClass = "" }, "start artifact class absent")
}
func TestFinalArtifactClassAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.FinalArtifactClass = "" }, "final artifact class absent")
}
func TestDestinationAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.Destination = "" }, "destination absent")
}
func TestCapabilityPathAbsentIsolated(t *testing.T) {
	iso(t, func(a *ProposedAction) { a.Steps = nil }, "capability path absent")
}
func TestCompositionDisabledFailsClosed(t *testing.T) {
	r := root()
	r.CompositionEnabled = false
	a := attack()
	check(t, Authorize(r, a), VerdictDeny, ProofDisabled, "capability composition disabled", GraphDisabled, ContinuityDisabled, AuthorityDisabled, AuthorityDisabled, AuthorityDisabled, CompositionDisabled, ev(a, GraphDisabled, ContinuityDisabled, AuthorityDisabled, AuthorityDisabled, AuthorityDisabled, CompositionDisabled, ProofDisabled, "capability composition disabled", "ACTION DENIED"))
}
func TestReferencedSkillMustExist(t *testing.T) {
	a := legit()
	a.Steps = append([]StepReference(nil), a.Steps...)
	a.Steps[1].SkillID = "skill:invented"
	deny(t, a, "referenced skill absent", GraphAbsent, ContinuityInvalid, AuthorityInvalid, AuthorityPresent, AuthorityInvalid, CompositionInvalid)
}
func TestDeclaredEdgeMustBelongToReferencedSkill(t *testing.T) {
	a := legit()
	a.Steps = append([]StepReference(nil), a.Steps...)
	a.Steps[1] = StepReference{SkillReportReader, EdgeTransformReport}
	deny(t, a, "declared capability edge absent", GraphAbsent, ContinuityInvalid, AuthorityInvalid, AuthorityPresent, AuthorityInvalid, CompositionInvalid)
}
func TestPathMustBeContiguous(t *testing.T) {
	a := legit()
	a.Steps = append([]StepReference(nil), a.Steps...)
	a.Steps[1] = StepReference{SkillContextNormalizer, EdgeNormalizeCredential}
	deny(t, a, "capability path not contiguous", GraphPresent, ContinuityInvalid, AuthorityPresent, AuthorityPresent, AuthorityAbsent, CompositionInvalid)
}
func TestPathEndpointMustMatch(t *testing.T) {
	a := legit()
	a.FinalArtifactClass = ReportContext
	deny(t, a, "capability path endpoint mismatch", GraphPresent, ContinuityInvalid, AuthorityPresent, AuthorityPresent, AuthorityPresent, CompositionInvalid)
}
func TestEveryComposedEffectMustBeAllowed(t *testing.T) {
	r, a := root(), legit()
	r.Mandate.AllowedEffects = []string{EffectRead, EffectSend}
	check(t, Authorize(r, a), VerdictDeny, ProofInvalid, "composed effect outside mandate", GraphPresent, ContinuityValid, AuthorityAbsent, AuthorityPresent, AuthorityPresent, CompositionInvalid, ev(a, GraphPresent, ContinuityValid, AuthorityAbsent, AuthorityPresent, AuthorityPresent, CompositionInvalid, ProofInvalid, "composed effect outside mandate", "ACTION DENIED"))
}
func TestEveryTraversedArtifactClassMustBeAllowed(t *testing.T) {
	r, a := root(), attack()
	deny(t, a, "composed artifact trajectory outside mandate", GraphPresent, ContinuityValid, AuthorityPresent, AuthorityPresent, AuthorityAbsent, CompositionInvalid)
	for _, c := range []string{CredentialSource, CredentialArtifact, ContextArtifact, ExternalDisclosure} {
		if has(r.Mandate.AllowedArtifactClasses, c) {
			t.Fatal(c)
		}
	}
}
func TestCompositionDestinationMustBeAllowed(t *testing.T) {
	r, a := root(), legit()
	r.Mandate.AllowedDestinations = []string{"mcp:internal"}
	check(t, Authorize(r, a), VerdictDeny, ProofInvalid, "composition destination outside mandate", GraphPresent, ContinuityValid, AuthorityPresent, AuthorityAbsent, AuthorityPresent, CompositionInvalid, ev(a, GraphPresent, ContinuityValid, AuthorityPresent, AuthorityAbsent, AuthorityPresent, CompositionInvalid, ProofInvalid, "composition destination outside mandate", "ACTION DENIED"))
}
func TestSchemaMismatchFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.SchemaVersion = 0 })
}
func TestDuplicateSkillIDFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.InstalledSkills = append(r.InstalledSkills, r.InstalledSkills[0]) })
}
func TestDuplicateEdgeIDFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.InstalledSkills[1].Edges[0].EdgeID = EdgeDiscoverCredentials })
}
func TestMalformedSendEdgeFailsClosed(t *testing.T) {
	invalid(t, func(r *EvaluationRoot) { r.InstalledSkills[5].Edges[0].Destination = "" })
}
func TestAuthorizeIsPure(t *testing.T) {
	r, a, before := root(), attack(), root()
	d1, d2 := Authorize(r, a), Authorize(r, a)
	if d1 != d2 || !reflect.DeepEqual(r, before) {
		t.Fatal("pure")
	}
}
func TestSequentialEvaluationsDoNotLaunderComposition(t *testing.T) {
	r := root()
	plain, hostile := attack(), legit()
	plain.ClaimedSignaturesValid, plain.ClaimedIndividualAllow, plain.ClaimedCompositionValid, plain.ClaimedAuthorized = false, false, false, false
	hostile.ClaimedSignaturesValid, hostile.ClaimedIndividualAllow, hostile.ClaimedCompositionValid, hostile.ClaimedAuthorized = true, true, true, true
	seq := []struct {
		a ProposedAction
		v string
	}{{legit(), VerdictAllow}, {attack(), VerdictDeny}, {isolatedA(), VerdictDeny}, {hostile, VerdictAllow}, {isolatedB(), VerdictDeny}, {plain, VerdictDeny}, {legit(), VerdictAllow}}
	for _, s := range seq {
		got := Authorize(r, s.a)
		if got.Verdict != s.v || got != Authorize(root(), s.a) {
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
	if FixtureSeed != 41041 || !reflect.DeepEqual(records(), records()) {
		t.Fatal("seed")
	}
}
