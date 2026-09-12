package authoritycontext

import (
	"reflect"
	"testing"
)

func coderMandate(domains ...string) AuthorityMandate {
	if len(domains) == 0 {
		domains = []string{CoderDomain}
	}
	return AuthorityMandate{CoderMandateID, CoderPrincipalID, domains}
}
func coderRoot(enabled bool) EvaluationRoot {
	return EvaluationRoot{SchemaVersion, CoderPrincipalID, CoderDomain, coderMandate(), enabled}
}
func adminRoot() EvaluationRoot {
	return EvaluationRoot{SchemaVersion, AdminPrincipalID, AdminDomain, AuthorityMandate{AdminMandateID, AdminPrincipalID, []string{AdminDomain}}, true}
}
func webRoot() EvaluationRoot {
	return EvaluationRoot{SchemaVersion, WebPrincipalID, WebDomain, AuthorityMandate{WebMandateID, WebPrincipalID, []string{WebDomain}}, true}
}
func coderAct(reqP, reqD, obsP, obsD string) ProposedAction {
	return ProposedAction{ActionID: "action:coder-build", EffectClass: EffectExecute, RequestedPrincipalID: reqP, RequestedDomain: reqD, ObservedPrincipalID: obsP, ObservedDomain: obsD}
}
func attackAct() ProposedAction {
	a := coderAct(CoderPrincipalID, CoderDomain, AdminPrincipalID, AdminDomain)
	a.ClaimedPrincipalID, a.ClaimedDomain = CoderPrincipalID, CoderDomain
	a.ClaimedInheritedPrincipalID, a.ClaimedInheritedDomain = AdminPrincipalID, AdminDomain
	a.ClaimedContextValid, a.ClaimedProofValid, a.ClaimedAuthorized, a.ClaimedCachedInitialization = true, true, true, true
	return a
}
func legitCoder() ProposedAction {
	return coderAct(CoderPrincipalID, CoderDomain, CoderPrincipalID, CoderDomain)
}
func legitAdmin() ProposedAction {
	return ProposedAction{ActionID: "action:admin-shell", EffectClass: EffectExecute, RequestedPrincipalID: AdminPrincipalID, RequestedDomain: AdminDomain, ObservedPrincipalID: AdminPrincipalID, ObservedDomain: AdminDomain}
}
func legitWeb() ProposedAction {
	return ProposedAction{ActionID: "action:web-read", EffectClass: EffectExecute, RequestedPrincipalID: WebPrincipalID, RequestedDomain: WebDomain, ObservedPrincipalID: WebPrincipalID, ObservedDomain: WebDomain}
}

var attackEvidence = [8]string{
	"Mandate mandate:coder-agent", "Held principal coder-agent",
	"Requested context coder-agent@docker-coder", "Observed context admin-agent@host",
	"Principal binding INVALID", "Observed-domain authority ABSENT",
	"Authority-Context Integrity Proof INVALID", "CONTEXT EFFECT DENIED",
}
var legitEvidence = [8]string{
	"Mandate mandate:coder-agent", "Held principal coder-agent",
	"Requested context coder-agent@docker-coder", "Observed context coder-agent@docker-coder",
	"Principal binding VALID", "Observed-domain authority PRESENT",
	"Authority-Context Integrity Proof VALID", "CONTEXT EFFECT ALLOWED",
}

func check(t *testing.T, d Decision, v, p, r, pb, da, cb string, ev [8]string) {
	t.Helper()
	if d.Verdict != v || d.Proof != p || d.Reason != r || d.PrincipalBinding != pb || d.DomainAuthority != da || d.ContextBinding != cb || d.Evidence != ev {
		t.Fatalf("got %+v", d)
	}
}

func TestRedClaimedAdminAmbientCannotAuthorizeCoder(t *testing.T) {
	fired := attackAct().ClaimedCachedInitialization && attackAct().ClaimedAuthorized
	if !fired {
		t.Fatal("baseline must fire")
	}
	d := Authorize(coderRoot(true), attackAct())
	if d.Verdict == VerdictAllow {
		t.Fatal("visor fired")
	}
	check(t, d, VerdictDeny, ProofInvalid, reasonObsReqPrincipal, BindingInvalid, AuthorityAbsent, BindingInvalid, attackEvidence)
}
func TestAttackAdminAmbientDeniedWithExactEvidence(t *testing.T) {
	check(t, Authorize(coderRoot(true), attackAct()), VerdictDeny, ProofInvalid, reasonObsReqPrincipal, BindingInvalid, AuthorityAbsent, BindingInvalid, attackEvidence)
}
func TestLegitimateCoderContextAllowsWithExactEvidence(t *testing.T) {
	check(t, Authorize(coderRoot(true), legitCoder()), VerdictAllow, ProofValid, reasonAuthorized, BindingValid, AuthorityPresent, BindingValid, legitEvidence)
}
func TestClaimsCannotChangeDecision(t *testing.T) {
	plain := coderAct(CoderPrincipalID, CoderDomain, AdminPrincipalID, AdminDomain)
	other := attackAct()
	other.ClaimedPrincipalID, other.ClaimedDomain, other.ClaimedInheritedPrincipalID, other.ClaimedInheritedDomain = "x", "y", "z", "w"
	r := coderRoot(true)
	if Authorize(r, attackAct()) != Authorize(r, plain) || Authorize(r, attackAct()) != Authorize(r, other) {
		t.Fatal("claims changed attack")
	}
	withClaims := legitCoder()
	withClaims.ClaimedAuthorized, withClaims.ClaimedProofValid, withClaims.ClaimedCachedInitialization = true, true, true
	if Authorize(r, legitCoder()) != Authorize(r, withClaims) {
		t.Fatal("claims changed legit")
	}
}
func TestEvidenceComesFromReturnedDecision(t *testing.T) {
	r, a := coderRoot(true), attackAct()
	if EvaluateAuthorityContextIntegrity(r, a) != Authorize(r, a) {
		t.Fatal("Authorize diverged")
	}
}

func isolateAct(t *testing.T, act ProposedAction, reason string) {
	t.Helper()
	d := Authorize(coderRoot(true), act)
	if d.Verdict != VerdictDeny || d.Proof != ProofInvalid || d.Reason != reason || d.PrincipalBinding != BindingInvalid || d.DomainAuthority != AuthorityInvalid || d.ContextBinding != BindingInvalid {
		t.Fatalf("got %+v want %s", d, reason)
	}
}
func TestActionIdentifierAbsentIsolated(t *testing.T) {
	a := legitCoder()
	a.ActionID = ""
	isolateAct(t, a, reasonActionAbsent)
}
func TestUnsupportedEffectClassIsolated(t *testing.T) {
	a := legitCoder()
	a.EffectClass = "NOPE"
	isolateAct(t, a, reasonUnsupported)
}
func TestRequestedPrincipalAbsentIsolated(t *testing.T) {
	a := legitCoder()
	a.RequestedPrincipalID = ""
	isolateAct(t, a, reasonReqPrincipal)
}
func TestRequestedDomainAbsentIsolated(t *testing.T) {
	a := legitCoder()
	a.RequestedDomain = ""
	isolateAct(t, a, reasonReqDomain)
}
func TestObservedPrincipalAbsentIsolated(t *testing.T) {
	a := legitCoder()
	a.ObservedPrincipalID = ""
	isolateAct(t, a, reasonObsPrincipal)
}
func TestObservedDomainAbsentIsolated(t *testing.T) {
	a := legitCoder()
	a.ObservedDomain = ""
	isolateAct(t, a, reasonObsDomain)
}
func TestAuthorityContextDisabledFailsClosed(t *testing.T) {
	d := Authorize(coderRoot(false), attackAct())
	if d.Verdict != VerdictDeny || d.Proof != ProofDisabled || d.Reason != reasonDisabled || d.PrincipalBinding != BindingDisabled || d.DomainAuthority != AuthorityDisabled || d.ContextBinding != BindingDisabled {
		t.Fatalf("got %+v", d)
	}
}
func TestRequestedPrincipalMismatchIsolated(t *testing.T) {
	d := Authorize(coderRoot(true), coderAct(WebPrincipalID, CoderDomain, WebPrincipalID, CoderDomain))
	if d.Reason != reasonHeldPrincipal || d.PrincipalBinding != BindingInvalid || d.DomainAuthority != AuthorityPresent || d.ContextBinding != BindingValid {
		t.Fatalf("got %+v", d)
	}
}
func TestObservedPrincipalMismatchIsolated(t *testing.T) {
	d := Authorize(coderRoot(true), coderAct(CoderPrincipalID, CoderDomain, AdminPrincipalID, CoderDomain))
	if d.Reason != reasonObsReqPrincipal || d.PrincipalBinding != BindingInvalid || d.DomainAuthority != AuthorityPresent || d.ContextBinding != BindingValid {
		t.Fatalf("got %+v", d)
	}
}
func TestRequestedObservedDomainMismatchIsolated(t *testing.T) {
	r := coderRoot(true)
	r.Mandate = coderMandate(CoderDomain, WebDomain)
	r.HeldExecutionDomain = WebDomain
	d := Authorize(r, coderAct(CoderPrincipalID, CoderDomain, CoderPrincipalID, WebDomain))
	if d.Reason != reasonObsReqDomain || d.PrincipalBinding != BindingValid || d.DomainAuthority != AuthorityPresent || d.ContextBinding != BindingInvalid {
		t.Fatalf("got %+v", d)
	}
}
func TestObservedDomainOutsideMandateIsolated(t *testing.T) {
	r := coderRoot(true)
	r.HeldExecutionDomain = AdminDomain
	d := Authorize(r, coderAct(CoderPrincipalID, AdminDomain, CoderPrincipalID, AdminDomain))
	if d.Reason != reasonOutsideMandate || d.PrincipalBinding != BindingValid || d.DomainAuthority != AuthorityAbsent || d.ContextBinding != BindingValid {
		t.Fatalf("got %+v", d)
	}
}
func TestHeldExecutionContextMismatchIsolated(t *testing.T) {
	r := coderRoot(true)
	r.HeldExecutionDomain = AdminDomain
	d := Authorize(r, legitCoder())
	if d.Reason != reasonHeldContext || d.PrincipalBinding != BindingValid || d.DomainAuthority != AuthorityPresent || d.ContextBinding != BindingInvalid {
		t.Fatalf("got %+v", d)
	}
}
func TestAllSixPrincipalOrderingsAreIsolated(t *testing.T) {
	pairs := []struct {
		r EvaluationRoot
		a ProposedAction
	}{{adminRoot(), legitAdmin()}, {coderRoot(true), legitCoder()}, {webRoot(), legitWeb()}}
	standalone := []Decision{Authorize(pairs[0].r, pairs[0].a), Authorize(pairs[1].r, pairs[1].a), Authorize(pairs[2].r, pairs[2].a)}
	orders := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, ord := range orders {
		for _, i := range ord {
			got := Authorize(pairs[i].r, pairs[i].a)
			if got != standalone[i] || got.Verdict != VerdictAllow {
				t.Fatalf("order %+v pair %d %+v", ord, i, got)
			}
		}
	}
}
func TestInterleavedPrincipalEvaluationsDoNotBleed(t *testing.T) {
	seq := []struct {
		r EvaluationRoot
		a ProposedAction
		v string
	}{
		{adminRoot(), legitAdmin(), VerdictAllow}, {coderRoot(true), attackAct(), VerdictDeny},
		{webRoot(), legitWeb(), VerdictAllow}, {coderRoot(true), legitCoder(), VerdictAllow},
		{coderRoot(true), attackAct(), VerdictDeny}, {adminRoot(), legitAdmin(), VerdictAllow},
		{webRoot(), legitWeb(), VerdictAllow}, {coderRoot(true), attackAct(), VerdictDeny},
		{coderRoot(true), legitCoder(), VerdictAllow},
	}
	for i, s := range seq {
		if Authorize(s.r, s.a).Verdict != s.v {
			t.Fatalf("step %d", i)
		}
	}
}
func TestPrincipalSwitchRequiresMatchingHeldRoot(t *testing.T) {
	if Authorize(adminRoot(), legitAdmin()).Verdict != VerdictAllow {
		t.Fatal("admin")
	}
	if Authorize(adminRoot(), legitCoder()).Reason != reasonHeldPrincipal {
		t.Fatal("switch")
	}
	if Authorize(coderRoot(true), legitCoder()).Verdict != VerdictAllow {
		t.Fatal("coder")
	}
}
func TestCleanupLeavesNoInheritedAuthority(t *testing.T) {
	if Authorize(adminRoot(), legitAdmin()).Verdict != VerdictAllow {
		t.Fatal("admin")
	}
	d := Authorize(coderRoot(false), attackAct())
	if d.Proof != ProofDisabled || d.Verdict != VerdictDeny {
		t.Fatalf("disabled %+v", d)
	}
	if Authorize(coderRoot(true), legitCoder()).Verdict != VerdictAllow {
		t.Fatal("after")
	}
}
func TestErrorPathLeavesNoInheritedAuthority(t *testing.T) {
	if Authorize(adminRoot(), legitAdmin()).Verdict != VerdictAllow {
		t.Fatal("admin")
	}
	bad := legitCoder()
	bad.ObservedDomain = ""
	if Authorize(coderRoot(true), bad).Reason != reasonObsDomain {
		t.Fatal("malformed")
	}
	if Authorize(coderRoot(true), attackAct()).Verdict == VerdictAllow || Authorize(coderRoot(true), legitCoder()).Verdict != VerdictAllow {
		t.Fatal("later")
	}
}
func TestSchemaMismatchFailsClosed(t *testing.T) {
	r := coderRoot(true)
	r.SchemaVersion = 2
	if Authorize(r, legitCoder()).Reason != reasonInvalidRoot {
		t.Fatal("schema")
	}
}
func TestMalformedMandateFailsClosed(t *testing.T) {
	r := coderRoot(true)
	r.Mandate.PrincipalID = AdminPrincipalID
	if Authorize(r, legitCoder()).Reason != reasonInvalidRoot {
		t.Fatal("mandate")
	}
}
func TestAuthorizeIsPure(t *testing.T) {
	r, a := coderRoot(true), attackAct()
	rc, ac := r, a
	rc.Mandate.AuthorizedDomains = append([]string{}, r.Mandate.AuthorizedDomains...)
	for i := 0; i < 3; i++ {
		if Authorize(r, a) != Authorize(rc, ac) {
			t.Fatal("impure")
		}
	}
	if !reflect.DeepEqual(r, rc) || !reflect.DeepEqual(a, ac) {
		t.Fatal("mutated")
	}
}
func TestUnknownEffectFailsClosed(t *testing.T) {
	a := legitCoder()
	a.EffectClass = "SHELL"
	isolateAct(t, a, reasonUnsupported)
}
func TestEmptyObservedContextFailsClosed(t *testing.T) {
	a := legitCoder()
	a.ObservedPrincipalID, a.ObservedDomain = "", ""
	isolateAct(t, a, reasonObsPrincipal)
}
