package resourceidentity

import "testing"

func attackRoot() EvaluationRoot {
	return EvaluationRoot{
		SchemaVersion: SchemaVersion, IdentityAuthorized: IdentityA, IdentityAtEffect: IdentityB,
		MandatingPrincipal: "user:operator", MandatingTrustClass: TrustTrustedUser,
		MandatedIdentity: IdentityA, PathPermissionValid: true, EffectClassWrite: true,
	}
}

func legitRoot() EvaluationRoot {
	r := attackRoot()
	r.IdentityAtEffect = IdentityA
	return r
}

var (
	attackEvidence = [8]string{
		"Path permission VALID", "Effect class WRITE",
		"Authorized resource identity object:workspace-output-result-A",
		"Effect-time resource identity object:outside-mandate-B",
		"Identity continuity FAILED", "Mandate for effect-time identity ABSENT",
		"Resource Identity Proof INVALID", "WRITE DENIED",
	}
	legitEvidence = [8]string{
		"Path permission VALID", "Effect class WRITE",
		"Authorized resource identity object:workspace-output-result-A",
		"Effect-time resource identity object:workspace-output-result-A",
		"Identity continuity PRESERVED", "Mandate for effect-time identity PRESENT",
		"Resource Identity Proof VALID", "WRITE ALLOWED",
	}
)

func TestRedMutablePathCannotAuthorizeSwappedResource(t *testing.T) {
	fired := false
	baseline := func() { fired = true }
	baseline()
	if !fired {
		t.Fatal("path-only baseline must fire")
	}
	fired = false
	d := Authorize(attackRoot(), ObservedArtifact{RequestedPath: "/workspace/output/result.txt", IsSymlink: true})
	if d.Verdict == VerdictAllow {
		fired = true
	}
	if fired || d.Reason != reasonContinuity || d.Evidence != attackEvidence {
		t.Fatalf("got %+v", d)
	}
}

func TestLegitimateResourceIdentityContinuityAllowsWrite(t *testing.T) {
	d := Authorize(legitRoot(), ObservedArtifact{RequestedPath: "/workspace/output/result.txt"})
	if d.Verdict != VerdictAllow || d.Reason != reasonAuthorized || d.Evidence != legitEvidence {
		t.Fatalf("got %+v", d)
	}
}

func TestPathAndSymlinkClaimsCannotChangeDecision(t *testing.T) {
	want := Authorize(attackRoot(), ObservedArtifact{})
	got := Authorize(attackRoot(), ObservedArtifact{
		RequestedPath: "/workspace/output/result.txt", ResolvedPath: "/etc/sensitive.conf",
		PresentationName: "result.txt", SymlinkTarget: "/etc/sensitive.conf", IsSymlink: true, VisibleRole: "USER",
	})
	if got != want {
		t.Fatalf("path claims changed decision: %+v", got)
	}
}

func TestSmashedClaimedProofCannotAuthorize(t *testing.T) {
	d := Authorize(attackRoot(), ObservedArtifact{ClaimedProof: ClaimedProof{
		Verdict: VerdictAllow, Proof: ProofValid, Reason: reasonAuthorized,
		IdentityAuthorized: IdentityA, IdentityAtEffect: IdentityA, MandatedIdentity: IdentityA,
	}})
	if d.Verdict != VerdictDeny || d.Evidence != attackEvidence {
		t.Fatalf("smashed proof: %+v", d)
	}
}

func TestUnknownMandatingTrustClassFailsClosed(t *testing.T) {
	root := legitRoot()
	root.MandatingTrustClass = "TRUSTED_ASSISTANT"
	d := EvaluateResourceIdentityProof(root)
	if d.Reason != reasonInvalidRoot || d.Proof != ProofInvalid {
		t.Fatalf("got %+v", d)
	}
}

func TestFailedPrerequisitesDeny(t *testing.T) {
	root := legitRoot()
	root.PathPermissionValid = false
	d := EvaluateResourceIdentityProof(root)
	if d.Proof != ProofValid || d.Verdict != VerdictDeny || d.Reason != reasonPathPermission {
		t.Fatalf("path: %+v", d)
	}
	root = legitRoot()
	root.EffectClassWrite = false
	d = EvaluateResourceIdentityProof(root)
	if d.Proof != ProofValid || d.Reason != reasonNotWrite {
		t.Fatalf("write: %+v", d)
	}
	root = legitRoot()
	root.SchemaVersion = 2
	if EvaluateResourceIdentityProof(root).Reason != reasonInvalidRoot {
		t.Fatal("schema")
	}
}

func TestEvidenceComesFromReturnedDecision(t *testing.T) {
	eval := EvaluateResourceIdentityProof(attackRoot())
	auth := Authorize(attackRoot(), ObservedArtifact{IsSymlink: true, ClaimedProof: ClaimedProof{Verdict: VerdictAllow}})
	if eval != auth || eval.Evidence != attackEvidence {
		t.Fatalf("Authorize diverged")
	}
	if EvaluateResourceIdentityProof(legitRoot()).Evidence != legitEvidence {
		t.Fatal("legit evidence")
	}
}

func isolate(t *testing.T, mut func(*EvaluationRoot), reason string) {
	t.Helper()
	root := legitRoot()
	mut(&root)
	d := EvaluateResourceIdentityProof(root)
	if d.Verdict != VerdictDeny || d.Proof != ProofInvalid || d.Reason != reason {
		t.Fatalf("got %s/%s %q want %q", d.Verdict, d.Proof, d.Reason, reason)
	}
}

func TestAuthorizedIdentityAbsentIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.IdentityAuthorized = "" }, reasonAuthorizedAbsent)
}
func TestEffectTimeIdentityAbsentIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.IdentityAtEffect = "" }, reasonEffectAbsent)
}
func TestIdentityContinuityMismatchIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.IdentityAtEffect, r.MandatedIdentity = IdentityB, IdentityB }, reasonContinuity)
}
func TestMandatingPrincipalAbsentIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.MandatingPrincipal = "" }, reasonMandatingAbsent)
}
func TestMandatedIdentityAbsentIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.MandatedIdentity = "" }, reasonMandatedAbsent)
}
func TestMandatingAuthorityInsufficientIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.MandatingTrustClass = TrustUntrustedExternal }, reasonMandatingLacks)
}
func TestEffectTimeIdentityOutsideMandateIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.MandatedIdentity = IdentityB }, reasonMandateMissing)
}
