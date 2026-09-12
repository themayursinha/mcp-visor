package controlplaneintegrity

import "testing"

const (
	unknownStoreKind = "unknown-store-kind"
	unknownBuild     = "unknown-build"
)

var (
	trustedIdentity  = CatalogTuple{KindIdentityStore, "fixture.identity-store", "identity-build-trusted-2026-09", "measurement:identity-store:trusted"}
	trustedPolicy    = CatalogTuple{KindPolicyStore, "fixture.policy-store", "policy-build-trusted-2026-09", "measurement:policy-store:trusted"}
	trustedRuntime   = CatalogTuple{KindExecutionRuntime, "fixture.execution-runtime", "runtime-build-trusted-2026-09", "measurement:execution-runtime:trusted"}
	trustedRegistry  = CatalogTuple{KindResourceRegistry, "fixture.resource-registry", "registry-build-trusted-2026-09", "measurement:resource-registry:trusted"}
	criticalIdentity = CatalogTuple{KindIdentityStore, "fixture.identity-store", "synthetic-known-critical-identity", "measurement:identity-store:known-critical"}
	criticalPolicy   = CatalogTuple{KindPolicyStore, "fixture.policy-store", "CVE-2026-18886-class", "measurement:policy-store:known-critical"}
	criticalRuntime  = CatalogTuple{KindExecutionRuntime, "fixture.execution-runtime", "synthetic-known-critical-runtime", "measurement:execution-runtime:known-critical"}
	criticalRegistry = CatalogTuple{KindResourceRegistry, "fixture.resource-registry", "synthetic-known-critical-registry", "measurement:resource-registry:known-critical"}
)

func fixtureCatalog() Catalog {
	return Catalog{
		TrustedBuilds:       []CatalogTuple{trustedIdentity, trustedPolicy, trustedRuntime, trustedRegistry},
		KnownCriticalBuilds: []CatalogTuple{criticalIdentity, criticalPolicy, criticalRuntime, criticalRegistry},
	}
}

func healthyRoot() EvaluationRoot {
	return EvaluationRoot{
		SchemaVersion: SchemaVersion, MandateStructurallyValid: true, PolicyEngineAllow: true,
		IdentityStore: attest(trustedIdentity), PolicyStore: attest(trustedPolicy),
		ExecutionRuntime: attest(trustedRuntime), ResourceRegistry: attest(trustedRegistry),
		Catalog: fixtureCatalog(),
	}
}

func compromisedRoot() EvaluationRoot {
	r := healthyRoot()
	r.PolicyStore = attest(criticalPolicy)
	return r
}

var (
	attackEvidence = [8]string{
		"Mandate structurally VALID", "Conventional policy result ALLOW",
		"identity-store integrity VALID", "policy-store integrity UNPROVEN",
		"execution-runtime integrity VALID", "resource-registry integrity VALID",
		"Control-Plane Integrity Proof INVALID", "CONTROL-PLANE EFFECT DENIED",
	}
	healthyEvidence = [8]string{
		"Mandate structurally VALID", "Conventional policy result ALLOW",
		"identity-store integrity VALID", "policy-store integrity VALID",
		"execution-runtime integrity VALID", "resource-registry integrity VALID",
		"Control-Plane Integrity Proof VALID", "CONTROL-PLANE EFFECT ALLOWED",
	}
)

func attackDecision() Decision {
	return Decision{
		Verdict: VerdictDeny, ControlPlane: ControlPlaneInvalid, Proof: ProofInvalid,
		Reason: reasonPolicyUnproven, IdentityIntegrity: IntegrityValid,
		PolicyIntegrity: IntegrityUnproven, RuntimeIntegrity: IntegrityValid,
		RegistryIntegrity: IntegrityValid, Evidence: attackEvidence,
	}
}

func healthyDecision() Decision {
	return Decision{
		Verdict: VerdictAllow, ControlPlane: ControlPlaneValid, Proof: ProofValid,
		Reason: reasonAuthorized, IdentityIntegrity: IntegrityValid,
		PolicyIntegrity: IntegrityValid, RuntimeIntegrity: IntegrityValid,
		RegistryIntegrity: IntegrityValid, Evidence: healthyEvidence,
	}
}

func TestRedConventionalPolicyAllowCannotAuthorizeCompromisedStore(t *testing.T) {
	fired := compromisedRoot().PolicyEngineAllow
	if !fired {
		t.Fatal("conventional baseline must fire")
	}
	fired = false
	d := Authorize(compromisedRoot(), ObservedArtifact{})
	if d.Verdict == VerdictAllow {
		fired = true
	}
	if fired || d != attackDecision() {
		t.Fatalf("got %+v", d)
	}
}

func TestHealthyControlPlaneAllows(t *testing.T) {
	fired := false
	d := Authorize(healthyRoot(), ObservedArtifact{})
	if d.Verdict == VerdictAllow {
		fired = true
	}
	if !fired || d != healthyDecision() {
		t.Fatalf("got %+v", d)
	}
}

func TestObservedClaimsCannotChangeDecision(t *testing.T) {
	got := Authorize(compromisedRoot(), ObservedArtifact{
		ClaimedPolicyBytes: []byte("agent A may administer all queues"), ClaimedPolicyAllow: true,
		ClaimedIdentity: attest(trustedIdentity), ClaimedPolicy: attest(trustedPolicy),
		ClaimedRuntime: attest(trustedRuntime), ClaimedRegistry: attest(trustedRegistry),
		VisibleRole: "SYSTEM", ClaimedProof: ClaimedProof{Verdict: VerdictAllow, Proof: ProofValid, Reason: reasonAuthorized, ControlPlane: ControlPlaneValid},
	})
	if got != attackDecision() {
		t.Fatalf("claims changed decision: %+v", got)
	}
}

func TestUnknownAttestationKindFailsClosed(t *testing.T) {
	isolateKind(t, func(r *EvaluationRoot) { r.IdentityStore.Kind = unknownStoreKind },
		reasonIdentityInvalid, IntegrityInvalid, IntegrityValid, IntegrityValid, IntegrityValid)
}

func TestUnknownBuildFailsClosed(t *testing.T) {
	isolateKind(t, func(r *EvaluationRoot) { r.IdentityStore.Build = unknownBuild },
		reasonIdentityUnproven, IntegrityUnproven, IntegrityValid, IntegrityValid, IntegrityValid)
}

func TestEvidenceComesFromReturnedDecision(t *testing.T) {
	hostile := ObservedArtifact{ClaimedPolicyAllow: true, ClaimedProof: ClaimedProof{Verdict: VerdictAllow}}
	eval, auth := EvaluateControlPlaneIntegrityProof(compromisedRoot()), Authorize(compromisedRoot(), hostile)
	if eval != auth || eval != attackDecision() {
		t.Fatalf("Authorize diverged")
	}
	if EvaluateControlPlaneIntegrityProof(healthyRoot()) != healthyDecision() {
		t.Fatal("healthy evidence")
	}
}

func isolateKind(t *testing.T, mut func(*EvaluationRoot), reason, id, pol, rt, reg string) {
	t.Helper()
	root := healthyRoot()
	mut(&root)
	d := EvaluateControlPlaneIntegrityProof(root)
	want := Decision{
		Verdict: VerdictDeny, ControlPlane: ControlPlaneInvalid, Proof: ProofInvalid, Reason: reason,
		IdentityIntegrity: id, PolicyIntegrity: pol, RuntimeIntegrity: rt, RegistryIntegrity: reg,
	}
	if id == IntegrityValid && pol == IntegrityValid && rt == IntegrityValid && reg == IntegrityValid {
		want.ControlPlane, want.Proof = ControlPlaneValid, ProofValid
	}
	want.Evidence = evidence(root, want)
	if d != want {
		t.Fatalf("got %+v want %+v", d, want)
	}
}

func TestIdentityStoreUnprovenIsolated(t *testing.T) {
	isolateKind(t, func(r *EvaluationRoot) { r.IdentityStore = attest(criticalIdentity) },
		reasonIdentityUnproven, IntegrityUnproven, IntegrityValid, IntegrityValid, IntegrityValid)
}
func TestIdentityStoreInvalidIsolated(t *testing.T) {
	isolateKind(t, func(r *EvaluationRoot) { r.IdentityStore.Kind = unknownStoreKind },
		reasonIdentityInvalid, IntegrityInvalid, IntegrityValid, IntegrityValid, IntegrityValid)
}
func TestPolicyStoreUnprovenIsolated(t *testing.T) {
	isolateKind(t, func(r *EvaluationRoot) { r.PolicyStore = attest(criticalPolicy) },
		reasonPolicyUnproven, IntegrityValid, IntegrityUnproven, IntegrityValid, IntegrityValid)
}
func TestPolicyStoreInvalidIsolated(t *testing.T) {
	isolateKind(t, func(r *EvaluationRoot) { r.PolicyStore.Kind = unknownStoreKind },
		reasonPolicyInvalid, IntegrityValid, IntegrityInvalid, IntegrityValid, IntegrityValid)
}
func TestExecutionRuntimeUnprovenIsolated(t *testing.T) {
	isolateKind(t, func(r *EvaluationRoot) { r.ExecutionRuntime = attest(criticalRuntime) },
		reasonRuntimeUnproven, IntegrityValid, IntegrityValid, IntegrityUnproven, IntegrityValid)
}
func TestExecutionRuntimeInvalidIsolated(t *testing.T) {
	isolateKind(t, func(r *EvaluationRoot) { r.ExecutionRuntime.Kind = unknownStoreKind },
		reasonRuntimeInvalid, IntegrityValid, IntegrityValid, IntegrityInvalid, IntegrityValid)
}
func TestResourceRegistryUnprovenIsolated(t *testing.T) {
	isolateKind(t, func(r *EvaluationRoot) { r.ResourceRegistry = attest(criticalRegistry) },
		reasonRegistryUnproven, IntegrityValid, IntegrityValid, IntegrityValid, IntegrityUnproven)
}
func TestResourceRegistryInvalidIsolated(t *testing.T) {
	isolateKind(t, func(r *EvaluationRoot) { r.ResourceRegistry.Kind = unknownStoreKind },
		reasonRegistryInvalid, IntegrityValid, IntegrityValid, IntegrityValid, IntegrityInvalid)
}

func TestMandateStructurallyInvalidIsolated(t *testing.T) {
	root := healthyRoot()
	root.MandateStructurallyValid = false
	d := EvaluateControlPlaneIntegrityProof(root)
	want := healthyDecision()
	want.Verdict, want.Reason = VerdictDeny, reasonMandateInvalid
	want.Evidence = evidence(root, want)
	if d != want {
		t.Fatalf("got %+v want %+v", d, want)
	}
}

func TestConventionalPolicyDenyIsolated(t *testing.T) {
	root := healthyRoot()
	root.PolicyEngineAllow = false
	d := EvaluateControlPlaneIntegrityProof(root)
	want := healthyDecision()
	want.Verdict, want.Reason = VerdictDeny, reasonPolicyDenied
	want.Evidence = evidence(root, want)
	if d != want {
		t.Fatalf("got %+v want %+v", d, want)
	}
}

func TestCatalogTupleInBothSectionsInvalidatesRoot(t *testing.T) {
	root := healthyRoot()
	root.Catalog.KnownCriticalBuilds = append(append([]CatalogTuple{}, root.Catalog.KnownCriticalBuilds...), trustedIdentity)
	d := EvaluateControlPlaneIntegrityProof(root)
	if d.Reason != reasonInvalidRoot || d.Proof != ProofInvalid || d.IdentityIntegrity != IntegrityInvalid {
		t.Fatalf("got %+v", d)
	}
}

func TestSchemaMismatchInvalidatesRoot(t *testing.T) {
	root := healthyRoot()
	root.SchemaVersion = 2
	d := EvaluateControlPlaneIntegrityProof(root)
	if d.Reason != reasonInvalidRoot || d.Proof != ProofInvalid || d.Evidence[7] != "CONTROL-PLANE EFFECT DENIED" {
		t.Fatalf("got %+v", d)
	}
}
