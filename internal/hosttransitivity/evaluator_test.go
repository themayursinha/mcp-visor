package hosttransitivity

import (
	"reflect"
	"testing"
)

func origGrant() HostGrant {
	return HostGrant{OriginalGrantID, OriginalPrincipalID, OriginalHostID, OriginalDomain, []string{OriginalHostID}, []string{"/srv/origin/credential"}, []string{"/srv/origin/export"}, false, false, false}
}
func origRoot(enabled bool) EvaluationRoot {
	return EvaluationRoot{SchemaVersion, OriginalPrincipalID, OriginalHostID, OriginalDomain, origGrant(), enabled}
}
func xferRoot() EvaluationRoot {
	g := origGrant()
	g.GrantID, g.DeclaredHosts, g.CredentialReadPaths, g.BulkEgressPaths = TransferGrantID, []string{OriginalHostID, ReplicaHostID}, nil, nil
	return EvaluationRoot{SchemaVersion, OriginalPrincipalID, OriginalHostID, OriginalDomain, g, true}
}
func replicaRoot() EvaluationRoot {
	g := HostGrant{ReplicaGrantID, ReplicaPrincipalID, ReplicaHostID, ReplicaDomain, []string{ReplicaHostID}, nil, nil, false, false, true}
	return EvaluationRoot{SchemaVersion, ReplicaPrincipalID, ReplicaHostID, ReplicaDomain, g, true}
}
func bind(p, h, d, target, effect string) ProposedAction {
	return ProposedAction{ActionID: "action:" + effect, EffectClass: effect, RequestedPrincipalID: p, RequestedHostID: h, RequestedExecutionDomain: d,
		ObservedPrincipalID: p, ObservedHostID: h, ObservedExecutionDomain: d, TargetHostID: target}
}
func attackAct() ProposedAction {
	a := bind(ReplicaPrincipalID, ReplicaHostID, ReplicaDomain, ReplicaHostID, EffectReplicaBootstrap)
	a.ActionID = "action:replica-bootstrap"
	a.ClaimedInheritedGrantID, a.ClaimedReplicaPrincipalID = OriginalGrantID, ReplicaPrincipalID
	a.ClaimedHostAuthorized, a.ClaimedGrantValid, a.ClaimedProofValid, a.ClaimedAuthorized = true, true, true, true
	return a
}
func xferAct() ProposedAction {
	a := bind(OriginalPrincipalID, OriginalHostID, OriginalDomain, ReplicaHostID, EffectTransfer)
	a.ActionID = "action:declared-transfer"
	return a
}
func credAct(path string) ProposedAction {
	a := bind(OriginalPrincipalID, OriginalHostID, OriginalDomain, OriginalHostID, EffectCredentialRead)
	a.ResourcePath = path
	return a
}
func replicaBoot() ProposedAction {
	a := bind(ReplicaPrincipalID, ReplicaHostID, ReplicaDomain, ReplicaHostID, EffectReplicaBootstrap)
	a.ActionID = "action:replica-bootstrap"
	return a
}

var attackEvidence = [8]string{
	"Grant grant:principal-a:host-origin", "Held binding principal-a@host-origin/domain-origin",
	"Requested binding replica-b@host-replica/domain-replica", "Observed binding replica-b@host-replica/domain-replica",
	"Target host host-replica", "Authority local=INVALID target=ABSENT path=NOT_APPLICABLE edge=ABSENT",
	"Host Transitivity Proof INVALID", "HOST EFFECT DENIED",
}
var xferEvidence = [8]string{
	"Grant grant:declared-transfer", "Held binding principal-a@host-origin/domain-origin",
	"Requested binding principal-a@host-origin/domain-origin", "Observed binding principal-a@host-origin/domain-origin",
	"Target host host-replica", "Authority local=VALID target=PRESENT path=NOT_APPLICABLE edge=PRESENT",
	"Host Transitivity Proof VALID", "HOST EFFECT ALLOWED",
}

func check(t *testing.T, d Decision, v, p, r, lb, th, pa, ea string, ev [8]string) {
	t.Helper()
	if d.Verdict != v || d.Proof != p || d.Reason != r || d.LocalGrantBinding != lb || d.TargetHostAuthority != th || d.PathAuthority != pa || d.EdgeAuthority != ea || d.Evidence != ev {
		t.Fatalf("got %+v", d)
	}
}

func TestRedInheritedH1GrantCannotBootstrapReplicaOnH2(t *testing.T) {
	a := attackAct()
	fired := a.ClaimedInheritedGrantID != "" && a.ClaimedHostAuthorized && a.ClaimedAuthorized
	if !fired {
		t.Fatal("baseline")
	}
	d := Authorize(origRoot(true), a)
	if d.Verdict == VerdictAllow {
		t.Fatal("visor fired")
	}
	check(t, d, VerdictDeny, ProofInvalid, reasonHeldBinding, BindingInvalid, AuthorityAbsent, PathNotApplicable, AuthorityAbsent, attackEvidence)
}
func TestReplicaBootstrapDeniedWithExactEvidence(t *testing.T) {
	check(t, Authorize(origRoot(true), attackAct()), VerdictDeny, ProofInvalid, reasonHeldBinding, BindingInvalid, AuthorityAbsent, PathNotApplicable, AuthorityAbsent, attackEvidence)
}
func TestDeclaredHostTransferAllowsWithExactEvidence(t *testing.T) {
	check(t, Authorize(xferRoot(), xferAct()), VerdictAllow, ProofValid, reasonAuthorized, BindingValid, AuthorityPresent, PathNotApplicable, AuthorityPresent, xferEvidence)
}
func TestFreshReplicaGrantAllowsLocalBootstrap(t *testing.T) {
	if Authorize(replicaRoot(), replicaBoot()).Verdict != VerdictAllow {
		t.Fatal("fresh")
	}
}
func TestClaimsCannotChangeDecision(t *testing.T) {
	plain, other := replicaBoot(), attackAct()
	plain.ActionID, other.ClaimedInheritedGrantID, other.ClaimedAuthorized = "action:replica-bootstrap", "x", false
	r := origRoot(true)
	if Authorize(r, attackAct()) != Authorize(r, plain) || Authorize(r, attackAct()) != Authorize(r, other) {
		t.Fatal("attack claims")
	}
	with := xferAct()
	with.ClaimedAuthorized, with.ClaimedProofValid, with.ClaimedHostAuthorized = true, true, true
	if Authorize(xferRoot(), xferAct()) != Authorize(xferRoot(), with) {
		t.Fatal("xfer claims")
	}
}
func TestEvidenceComesFromReturnedDecision(t *testing.T) {
	r, a := origRoot(true), attackAct()
	if EvaluateHostTransitivity(r, a) != Authorize(r, a) {
		t.Fatal("diverged")
	}
}

func isolateXfer(t *testing.T, mut func(*ProposedAction), reason string) {
	t.Helper()
	a := xferAct()
	mut(&a)
	d := Authorize(xferRoot(), a)
	if d.Verdict != VerdictDeny || d.Proof != ProofInvalid || d.Reason != reason {
		t.Fatalf("got %+v want %s", d, reason)
	}
}
func TestActionIdentifierAbsentIsolated(t *testing.T) {
	isolateXfer(t, func(a *ProposedAction) { a.ActionID = "" }, reasonActionAbsent)
}
func TestUnsupportedEffectClassIsolated(t *testing.T) {
	isolateXfer(t, func(a *ProposedAction) { a.EffectClass = "NOPE" }, reasonUnsupported)
}
func TestRequestedPrincipalAbsentIsolated(t *testing.T) {
	isolateXfer(t, func(a *ProposedAction) { a.RequestedPrincipalID = "" }, reasonReqPrincipal)
}
func TestRequestedHostAbsentIsolated(t *testing.T) {
	isolateXfer(t, func(a *ProposedAction) { a.RequestedHostID = "" }, reasonReqHost)
}
func TestRequestedExecutionDomainAbsentIsolated(t *testing.T) {
	isolateXfer(t, func(a *ProposedAction) { a.RequestedExecutionDomain = "" }, reasonReqDomain)
}
func TestObservedPrincipalAbsentIsolated(t *testing.T) {
	isolateXfer(t, func(a *ProposedAction) { a.ObservedPrincipalID = "" }, reasonObsPrincipal)
}
func TestObservedHostAbsentIsolated(t *testing.T) {
	isolateXfer(t, func(a *ProposedAction) { a.ObservedHostID = "" }, reasonObsHost)
}
func TestObservedExecutionDomainAbsentIsolated(t *testing.T) {
	isolateXfer(t, func(a *ProposedAction) { a.ObservedExecutionDomain = "" }, reasonObsDomain)
}
func TestTargetHostAbsentIsolated(t *testing.T) {
	isolateXfer(t, func(a *ProposedAction) { a.TargetHostID = "" }, reasonTargetAbsent)
}
func TestHostAuthorityDisabledFailsClosed(t *testing.T) {
	d := Authorize(origRoot(false), attackAct())
	if d.Proof != ProofDisabled || d.Reason != reasonDisabled || d.LocalGrantBinding != BindingDisabled {
		t.Fatalf("%+v", d)
	}
}
func TestRequestedBindingMismatchIsolated(t *testing.T) {
	if Authorize(origRoot(true), attackAct()).Reason != reasonHeldBinding {
		t.Fatal("c11")
	}
}
func TestObservedBindingMismatchIsolated(t *testing.T) {
	a := credAct("/srv/origin/credential")
	a.ObservedHostID = ReplicaHostID
	if Authorize(origRoot(true), a).Reason != reasonObsBinding {
		t.Fatal("c12")
	}
}
func TestCredentialReadOutsideGrantDenied(t *testing.T) {
	if Authorize(origRoot(true), credAct("/outside/grant")).Reason != reasonCredRead {
		t.Fatal("c13")
	}
}
func TestRemoteExecToUndeclaredHostDenied(t *testing.T) {
	a := bind(OriginalPrincipalID, OriginalHostID, OriginalDomain, ReplicaHostID, EffectRemoteExec)
	if Authorize(origRoot(true), a).Reason != reasonRemoteExec {
		t.Fatal("c14")
	}
}
func TestBulkEgressOutsideDeclaredPathDenied(t *testing.T) {
	r := xferRoot()
	a := bind(OriginalPrincipalID, OriginalHostID, OriginalDomain, ReplicaHostID, EffectBulkEgress)
	a.EgressPath = "/outside/declared/paths"
	if Authorize(r, a).Reason != reasonBulkEgress {
		t.Fatal("c15")
	}
}
func TestPackageInstallOnNewlyReachedHostDenied(t *testing.T) {
	a := bind(OriginalPrincipalID, OriginalHostID, OriginalDomain, ReplicaHostID, EffectPackageInstall)
	if Authorize(origRoot(true), a).Reason != reasonPkgInstall {
		t.Fatal("c16")
	}
}
func TestPersistentListenerDeniedWithoutGrant(t *testing.T) {
	a := bind(OriginalPrincipalID, OriginalHostID, OriginalDomain, OriginalHostID, EffectPersistentListener)
	if Authorize(origRoot(true), a).Reason != reasonListener {
		t.Fatal("c17")
	}
}
func TestReplicaBootstrapRequiresFreshLocalGrant(t *testing.T) {
	a := bind(OriginalPrincipalID, OriginalHostID, OriginalDomain, ReplicaHostID, EffectReplicaBootstrap)
	if Authorize(origRoot(true), a).Reason != reasonReplica {
		t.Fatal("c18")
	}
}
func TestTransferRequiresBothHostsDeclared(t *testing.T) {
	r := origRoot(true)
	a := bind(OriginalPrincipalID, OriginalHostID, OriginalDomain, ReplicaHostID, EffectTransfer)
	if Authorize(r, a).Reason != reasonTransfer {
		t.Fatal("c19")
	}
}
func TestTransferDoesNotAuthorizeLaterReplicaAction(t *testing.T) {
	if Authorize(xferRoot(), xferAct()).Verdict != VerdictAllow {
		t.Fatal("xfer")
	}
	if Authorize(origRoot(true), attackAct()).Verdict == VerdictAllow {
		t.Fatal("inherit")
	}
	if Authorize(replicaRoot(), replicaBoot()).Verdict != VerdictAllow {
		t.Fatal("fresh")
	}
}
func TestSchemaMismatchFailsClosed(t *testing.T) {
	r := origRoot(true)
	r.SchemaVersion = 2
	if Authorize(r, xferAct()).Reason != reasonInvalidRoot {
		t.Fatal("schema")
	}
}
func TestMalformedGrantBindingFailsClosed(t *testing.T) {
	r := origRoot(true)
	r.Grant.PrincipalID = ReplicaPrincipalID
	if Authorize(r, credAct("/srv/origin/credential")).Reason != reasonInvalidRoot {
		t.Fatal("grant")
	}
}
func TestDuplicateDeclaredHostFailsClosed(t *testing.T) {
	r := origRoot(true)
	r.Grant.DeclaredHosts = []string{OriginalHostID, OriginalHostID}
	if Authorize(r, credAct("/srv/origin/credential")).Reason != reasonInvalidRoot {
		t.Fatal("dup")
	}
}
func TestAuthorizeIsPure(t *testing.T) {
	r, a := origRoot(true), attackAct()
	rc, ac := r, a
	rc.Grant.DeclaredHosts = append([]string{}, r.Grant.DeclaredHosts...)
	for i := 0; i < 3; i++ {
		if Authorize(r, a) != Authorize(rc, ac) {
			t.Fatal("impure")
		}
	}
	if !reflect.DeepEqual(r.Grant.DeclaredHosts, rc.Grant.DeclaredHosts) {
		t.Fatal("mutated")
	}
}
func TestSequentialHostEvaluationsDoNotTransferAuthority(t *testing.T) {
	steps := []struct {
		r EvaluationRoot
		a ProposedAction
		v string
	}{
		{origRoot(true), credAct("/srv/origin/credential"), VerdictAllow},
		{xferRoot(), xferAct(), VerdictAllow},
		{origRoot(true), attackAct(), VerdictDeny},
		{origRoot(true), bind(OriginalPrincipalID, OriginalHostID, OriginalDomain, ReplicaHostID, EffectRemoteExec), VerdictDeny},
		{replicaRoot(), replicaBoot(), VerdictAllow},
		{origRoot(true), attackAct(), VerdictDeny},
		{origRoot(true), credAct("/srv/origin/credential"), VerdictAllow},
	}
	for i, s := range steps {
		if Authorize(s.r, s.a).Verdict != s.v {
			t.Fatalf("step %d", i)
		}
	}
}
func TestUnknownEffectFailsClosed(t *testing.T) {
	isolateXfer(t, func(a *ProposedAction) { a.EffectClass = "SHELL" }, reasonUnsupported)
}
