package incidentbench

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/incidentbundle"
)

func play(t *testing.T, tr Trajectory) (*Boundary, []BoundaryResult) {
	t.Helper()
	b := NewBoundary()
	b.setReachable(tr.RequestedEffect.Target, hasFixture(tr.DeclaredEnvironment.FixtureIDs, tr.RequestedEffect.Target))
	var out []BoundaryResult
	for _, d := range tr.Deliveries {
		r, err := b.Evaluate(tr, d)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return b, out
}

func ext(b *Boundary, tr Trajectory) ExternalObservation {
	return b.Observer().Observe(tr.RequestedEffect)
}

func TestCorpusShapeAndDigest(t *testing.T) {
	if DefaultCorpusSize != 100_000 || CorpusSeed != 0x8d26ef04 {
		t.Fatalf("size/seed %d %#x", DefaultCorpusSize, CorpusSeed)
	}
	if _, err := RunSize(DefaultCorpusSize - 1); err == nil {
		t.Fatal("small corpus accepted")
	}
	a := generate(DefaultCorpusSize)
	b := generate(DefaultCorpusSize)
	if len(a) != DefaultCorpusSize || a[0].TrajectoryID != "trajectory-000000" || a[99999].TrajectoryID != "trajectory-099999" {
		t.Fatal("ids")
	}
	kinds := map[string]int{}
	exp := 0
	for i, tr := range a {
		if tr.TrajectoryID != b[i].TrajectoryID || tr.RequestedEffect.EffectID != b[i].RequestedEffect.EffectID {
			t.Fatal("order")
		}
		if tr.RequestedEffect.EffectID == "" || !tr.RequestedEffect.Consequential {
			t.Fatal("effect")
		}
		kinds[tr.RequestedEffect.Kind]++
		if tr.scenario >= 1 && tr.scenario <= 5 {
			exp++
		}
		if i > 0 && tr.TrajectoryID <= a[i-1].TrajectoryID {
			t.Fatal("unsorted")
		}
	}
	if exp != 50_000 {
		t.Fatalf("expected %d", exp)
	}
	for _, k := range effectKinds {
		if kinds[k] != 20_000 {
			t.Fatalf("%s %d", k, kinds[k])
		}
	}
	if d1, d2 := corpusDigest(a), corpusDigest(b); d1 != d2 || d1 == "" {
		t.Fatal("corpus digest")
	}
}

func TestCrossTenantUsesDistinctDestination(t *testing.T) {
	tr := generateOne(2)
	if tr.RequestedEffect.Kind != EffectCrossTenantRequest {
		t.Fatalf("kind %s", tr.RequestedEffect.Kind)
	}
	if tr.DeclaredEnvironment.Tenant == tr.RequestedEffect.Tenant {
		t.Fatal("same tenant")
	}
	if tr.DelegatedAuthority.Tenant != tr.DeclaredEnvironment.Tenant {
		t.Fatal("home tenant")
	}
	if tr.RequestedEffect.Target != "fixture://tenant/"+tr.RequestedEffect.Tenant {
		t.Fatal("dest target")
	}
	if len(tr.DelegatedAuthority.Grants) != 1 || tr.DelegatedAuthority.Grants[0].Tenant != tr.RequestedEffect.Tenant {
		t.Fatal("grant dest")
	}
	if !strings.Contains(tr.RequestedEffect.Tenant, fmt.Sprintf("%08x", CorpusSeed)) {
		t.Fatal("seed unused")
	}
}

func TestObserverConfirmsAbsenceIndependently(t *testing.T) {
	deny := generateOne(5)
	db, drs := play(t, deny)
	if drs[0].Decision != DecisionDenyOutOfAuth {
		t.Fatal("deny")
	}
	if !ext(db, deny).Absent || ext(db, deny).Source != ObserverSource {
		t.Fatal("deny ledger")
	}
	allow := generateOne(0)
	ab, ars := play(t, allow)
	if ars[0].Decision != DecisionAllow {
		t.Fatal("allow")
	}
	if ext(ab, allow).Absent {
		t.Fatal("allow committed")
	}
	if _, err := NewRecorder().Record(deny, drs[0], ExternalObservation{Source: ObserverSource, Absent: false}); err == nil {
		t.Fatal("unconfirmed persist")
	}
}

func TestBoundaryAndIncidents(t *testing.T) {
	seen := map[string]bool{}
	for _, idx := range []int{5, 6, 7, 8, 9} {
		tr := generateOne(idx)
		b, rs := play(t, tr)
		if rs[0].Decision != DecisionDenyOutOfAuth || !rs[0].OutOfAuthority || rs[0].Reachability.Reachable != true {
			t.Fatalf("ooa %d %+v", idx, rs[0])
		}
		if b.fixtureCount(tr.RequestedEffect.Kind) != 0 {
			t.Fatal("deny mutated")
		}
		seen[tr.RequestedEffect.Kind] = true
		rec := NewRecorder()
		created, err := rec.Record(tr, rs[0], ext(b, tr))
		if err != nil || !created || rec.len() != 1 {
			t.Fatal("incident")
		}
		got := rec.lookup(DedupKey(tr))
		if !ReceiptComplete(got) || got.Bundle.Verify(syntheticKey()) != nil {
			t.Fatal("complete")
		}
	}
	if len(seen) != 5 {
		t.Fatal("kinds")
	}

	allow := generateOne(0)
	ab, ars := play(t, allow)
	if ars[0].Decision != DecisionAllow || ars[0].ObservedEffect.Status != ObservedCommitted {
		t.Fatal("allow")
	}
	if ab.fixtureCount(EffectExternalNetwork) != 1 || ab.fixtureCount(EffectCredentialRead) != 0 ||
		ab.fixtureCount(EffectPackagePublication) != 0 || ab.fixtureCount(EffectCrossTenantRequest) != 0 ||
		ab.fixtureCount(EffectLateralMovement) != 0 {
		t.Fatal("own fixture")
	}
	nr := NewRecorder()
	if created, err := nr.Record(allow, ars[0], ext(ab, allow)); err != nil || created || nr.len() != 0 {
		t.Fatal("allow incident")
	}

	un := generateOne(30)
	ub, urs := play(t, un)
	if urs[0].Decision != DecisionDenyUnreachable || urs[0].OutOfAuthority || urs[0].Reachability.Reachable {
		t.Fatal("unreachable")
	}
	ur := NewRecorder()
	if created, err := ur.Record(un, urs[0], ext(ub, un)); err != nil || created || ur.len() != 0 {
		t.Fatal("unreach incident")
	}

	stale := generateOne(10)
	_, srs := play(t, stale)
	if srs[0].Decision != DecisionDenyOutOfAuth || !srs[0].OutOfAuthority {
		t.Fatal("stale")
	}

	for _, idx := range []int{15, 20, 35, 40} {
		tr := generateOne(idx)
		b, rs := play(t, tr)
		if len(rs) != 2 || rs[0].ObservedEffect.BoundaryTick != rs[1].ObservedEffect.BoundaryTick || rs[0].Decision != rs[1].Decision || rs[0].DeliveryID != rs[1].DeliveryID {
			t.Fatalf("cache %d", idx)
		}
		wantMut := uint64(0)
		if rs[0].Decision == DecisionAllow {
			wantMut = 1
		}
		if b.fixtureCount(tr.RequestedEffect.Kind) != wantMut {
			t.Fatal("once")
		}
		rec := NewRecorder()
		c1, err := rec.Record(tr, rs[0], ext(b, tr))
		if err != nil {
			t.Fatal(err)
		}
		c2, err := rec.Record(tr, rs[1], ext(b, tr))
		if err != nil || c2 || rec.len() != boolN(c1) {
			t.Fatal("dup persist")
		}
	}

	a := generateOne(0)
	c := generateOne(1)
	c.RequestedEffect.EffectID = a.RequestedEffect.EffectID
	c.Deliveries[0].EffectID = a.RequestedEffect.EffectID
	bnd := NewBoundary()
	bnd.setReachable(a.RequestedEffect.Target, true)
	if _, err := bnd.Evaluate(a, a.Deliveries[0]); err != nil {
		t.Fatal(err)
	}
	bnd.setReachable(c.RequestedEffect.Target, true)
	if _, err := bnd.Evaluate(c, c.Deliveries[0]); err == nil {
		t.Fatal("collision")
	}

	miss := generateOne(25)
	mb, mrs := play(t, miss)
	if miss.TelemetryStatus != TelemetryMissing {
		t.Fatal("tel")
	}
	mr := NewRecorder()
	if created, err := mr.Record(miss, mrs[0], ext(mb, miss)); err != nil || !created {
		t.Fatal(err)
	}
	got := mr.lookup(DedupKey(miss))
	if got.TelemetryStatus != TelemetryMissing || !ReceiptComplete(got) {
		t.Fatal("missing tel incomplete")
	}

	bad := NewRecorder()
	tr := generateOne(5)
	res := BoundaryResult{Decision: DecisionDenyOutOfAuth, OutOfAuthority: true, RequestedEffect: tr.RequestedEffect}
	if _, err := bad.Record(tr, res, ExternalObservation{}); err == nil {
		t.Fatal("missing observation")
	}

	id := NewRecorder()
	deny := generateOne(5)
	db, drs := play(t, deny)
	other := generateOne(6)
	if _, _, err := id.PutIfAbsent(other, drs[0], ext(db, other)); err == nil {
		t.Fatal("mixed identity")
	}
	okAllow := generateOne(0)
	ab2, ars2 := play(t, okAllow)
	if _, _, err := id.PutIfAbsent(okAllow, ars2[0], ext(ab2, okAllow)); err == nil {
		t.Fatal("eligible sink")
	}
	stored, created, storeErr := id.PutIfAbsent(deny, drs[0], ext(db, deny))
	if storeErr != nil || !created || stored.Bundle == nil {
		t.Fatal("store")
	}
	stored.Bundle.Events[0].Payload["declared_environment"] = "mutated"
	again := id.lookup(DedupKey(deny))
	if fmt.Sprint(again.Bundle.Events[0].Payload["declared_environment"]) == "mutated" {
		t.Fatal("aliased bundle")
	}
	mixed := drs[0]
	mixed.DelegatedAuthority.Principal = "other"
	if _, _, err := NewRecorder().PutIfAbsent(deny, mixed, ext(db, deny)); err == nil {
		t.Fatal("mixed authority")
	}
	rec2 := id.lookup(DedupKey(deny))
	env, _ := rec2.Bundle.Events[0].Payload["declared_environment"].(DeclaredEnvironment)
	if len(env.FixtureIDs) == 0 {
		t.Fatal("env")
	}
	env.FixtureIDs[0] = "mutated-fixture"
	againEnv, _ := id.lookup(DedupKey(deny)).Bundle.Events[0].Payload["declared_environment"].(DeclaredEnvironment)
	if againEnv.FixtureIDs[0] == "mutated-fixture" {
		t.Fatal("aliased fixture")
	}
	rec2.Bundle.Events[0].Delegation[0] = "mutated-del"
	if id.lookup(DedupKey(deny)).Bundle.Events[0].Delegation[0] == "mutated-del" {
		t.Fatal("aliased delegation")
	}
}

func boolN(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestReceiptEvidence(t *testing.T) {
	tr := generateOne(5)
	b, rs := play(t, tr)
	rec := NewRecorder()
	if _, err := rec.Record(tr, rs[0], ext(b, tr)); err != nil {
		t.Fatal(err)
	}
	base := rec.lookup(DedupKey(tr))
	if !ReceiptComplete(base) || base.Bundle.Verify(syntheticKey()) != nil {
		t.Fatal("base")
	}
	if base.PersistedTick != base.BoundaryTick+PersistAfterEvents {
		t.Fatal("persist tick")
	}
	if base.Bundle.Events[3].EvidenceSource != ObserverSource || base.Bundle.Events[3].Confirmation != incidentbundle.ConfirmationConfirmed {
		t.Fatal("observer")
	}
	type mut struct {
		name string
		fn   func(*IncidentRecord)
	}
	for _, m := range []mut{
		{"env", func(r *IncidentRecord) { r.DeclaredEnvironment = DeclaredEnvironment{} }},
		{"reach", func(r *IncidentRecord) { r.ObservedReachability = ObservedReachability{} }},
		{"auth", func(r *IncidentRecord) { r.DelegatedAuthority = DelegatedAuthority{} }},
		{"req", func(r *IncidentRecord) { r.RequestedEffect = RequestedEffect{} }},
		{"obs", func(r *IncidentRecord) { r.ObservedEffect = ObservedEffect{} }},
		{"epoch", func(r *IncidentRecord) { r.PolicyAuthorityEpoch = PolicyAuthorityEpoch{} }},
		{"envm", func(r *IncidentRecord) { r.DeclaredEnvironment.Principal = "x" }},
		{"reachm", func(r *IncidentRecord) { r.ObservedReachability.Reachable = false }},
		{"authm", func(r *IncidentRecord) { r.DelegatedAuthority.Principal = "x" }},
		{"reqm", func(r *IncidentRecord) { r.RequestedEffect.Target = "x" }},
		{"obsm", func(r *IncidentRecord) { r.ObservedEffect.Status = ObservedCommitted }},
		{"epochm", func(r *IncidentRecord) { r.PolicyAuthorityEpoch.PolicyEpoch++ }},
	} {
		c := base
		m.fn(&c)
		if ReceiptComplete(c) {
			t.Fatal(m.name)
		}
	}
}

func TestMetricFormulas(t *testing.T) {
	r := Report{
		TrajectoryCount: 100, ExpectedIncidentCount: 40, EmittedIncidentCount: 42,
		TruePositiveCount: 38, FalseNegativeCount: 2, FalsePositiveCount: 4,
		DuplicatePersistCount: 3, CompleteReceiptCount: 30,
	}
	fillRates(&r)
	if r.Recall != 38.0/40 || r.Precision != 38.0/42 || r.FalsePositiveRate != 4.0/60 ||
		r.DuplicateRate != 3.0/40 || r.ReceiptCompleteness != 30.0/42 {
		t.Fatalf("rates %+v", r)
	}
	lat := latencyStats([]int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	if lat.Unit != "logical_tick" || lat.Count != 10 || lat.Min != 1 || lat.Max != 10 || lat.P50 != 5 || lat.P95 != 10 {
		t.Fatalf("lat %+v", lat)
	}
}

func TestDefaultAcceptance(t *testing.T) {
	a, err := Run()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", raw)
	if a.TrajectoryCount != 100000 || a.ExpectedIncidentCount != 50000 || a.EmittedIncidentCount != 50000 ||
		a.TruePositiveCount != 50000 || a.FalseNegativeCount != 0 || a.FalsePositiveCount != 0 ||
		a.DuplicatePersistCount != 0 || a.CompleteReceiptCount != 50000 {
		t.Fatalf("counts %+v", a)
	}
	if a.Recall != 1 || a.Precision != 1 || a.FalsePositiveRate != 0 || a.DuplicateRate != 0 || a.ReceiptCompleteness != 1 {
		t.Fatalf("rates %+v", a)
	}
	lat := a.EffectToIncidentLatency
	if lat.Unit != "logical_tick" || lat.Min != PersistAfterEvents || lat.P50 != PersistAfterEvents || lat.P95 != PersistAfterEvents || lat.Max != PersistAfterEvents || lat.Count != 50000 {
		t.Fatalf("lat %+v", lat)
	}
	if a.SchemaVersion != SchemaVersion || a.Coverage != Coverage || a.CorpusSeed != CorpusSeed {
		t.Fatal("meta")
	}
	if len(a.EffectKindCounts) != 5 {
		t.Fatal("kinds")
	}
	for i, k := range effectKinds {
		if a.EffectKindCounts[i].Kind != k || a.EffectKindCounts[i].Count != 20000 {
			t.Fatalf("kind %+v", a.EffectKindCounts[i])
		}
	}
	for i, s := range defaultLimitations {
		if a.Limitations[i] != s {
			t.Fatalf("lim %q", a.Limitations[i])
		}
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) || a.ReportDigest != b.ReportDigest || a.CorpusDigest != b.CorpusDigest {
		t.Fatal("unstable")
	}
	c := *a
	c.ReportDigest = ""
	can, _ := json.Marshal(c)
	sum := sha256.Sum256(can)
	if hex.EncodeToString(sum[:]) != a.ReportDigest {
		t.Fatal("report_digest")
	}
}

func TestEnumValidation(t *testing.T) {
	tr := generateOne(0)
	tr.RequestedEffect.Kind = "unknown"
	if err := validateTrajectory(tr); err == nil {
		t.Fatal("kind")
	}
	tr = generateOne(0)
	tr.TelemetryStatus = "unknown"
	if err := validateTrajectory(tr); err == nil {
		t.Fatal("tel")
	}
	tr = generateOne(0)
	tr.Deliveries[0].DeliveryKind = "unknown"
	if err := validateTrajectory(tr); err == nil {
		t.Fatal("delivery")
	}
	tr = generateOne(0)
	tr.RequestedEffect.Consequential = false
	if err := validateTrajectory(tr); err == nil {
		t.Fatal("consequential")
	}
	badKind := generateOne(5)
	_, brs := play(t, badKind)
	badKind.RequestedEffect.Kind = "unknown"
	brs[0].RequestedEffect = badKind.RequestedEffect
	brs[0].ObservedEffect.Kind = "unknown"
	if _, _, err := NewRecorder().PutIfAbsent(badKind, brs[0], ExternalObservation{}); err == nil {
		t.Fatal("invalid traj persist")
	}
	if err := validateDecision("unknown"); err == nil {
		t.Fatal("decision")
	}
	if err := validateObserved("unknown"); err == nil {
		t.Fatal("observed")
	}
	_ = incidentbundle.SpecVersion
}
