package principalderivation

import "testing"

const localAgent = "agent:local-agent"

func attackRoot() EvaluationRoot {
	return EvaluationRoot{
		SchemaVersion: SchemaVersion, TransportTrustClass: TransportUnattested,
		MandatingTrustClass: TrustTrustedUser, ToolCapabilityAvailable: true,
	}
}

func legitRoot() EvaluationRoot {
	return EvaluationRoot{
		SchemaVersion: SchemaVersion, TransportTrustClass: TransportAttested,
		TransportPrincipal: localAgent, SessionIdentityBound: true, SessionPrincipal: localAgent,
		AgentAuthenticated: true, AgentPrincipal: localAgent, DelegationFromUser: true,
		MandatingPrincipal: "user:operator", MandatingTrustClass: TrustTrustedUser,
		MandatedAgentPrincipal: localAgent, ToolCapabilityAvailable: true,
	}
}

var (
	attackEvidence = [8]string{
		"Transport identity UNATTESTED",
		"Transport identity -> session identity DENIED (session identity ABSENT)",
		"Session identity -> agent identity DENIED (authenticated MCP principal ABSENT)",
		"Agent identity -> mandate DENIED (delegation from user ABSENT)",
		"Tool capability AVAILABLE", "Caller authority ZERO",
		"Principal Derivation Proof INVALID", "Request DENY",
	}
	legitEvidence = [8]string{
		"Transport identity ATTESTED agent:local-agent",
		"Transport identity -> session identity JUSTIFIED agent:local-agent",
		"Session identity -> agent identity JUSTIFIED agent:local-agent",
		"Agent identity -> mandate JUSTIFIED user:operator=>agent:local-agent",
		"Tool capability AVAILABLE", "Caller authority USER",
		"Principal Derivation Proof VALID", "Request ALLOW",
	}
)

func TestRedLocalhostDoesNotConferPrincipalAuthority(t *testing.T) {
	fired := false
	baseline := func() { fired = true }
	baseline()
	if !fired {
		t.Fatal("conventional localhost path must fire")
	}
	fired = false
	d := Authorize(attackRoot(), ObservedArtifact{Destination: "localhost", DNSAnswer: "127.0.0.1", Host: "localhost"})
	if d.Verdict == VerdictAllow {
		fired = true
	}
	if fired || d.Verdict != VerdictDeny || d.Proof != ProofInvalid || d.Reason != reasonTransportUnattested || d.Evidence != attackEvidence {
		t.Fatalf("got %+v", d)
	}
}

func TestLegitimateSessionBoundAgentWithMandateAllows(t *testing.T) {
	d := Authorize(legitRoot(), ObservedArtifact{WebpageBytes: "ok"})
	if d.Verdict != VerdictAllow || d.Proof != ProofValid || d.Reason != reasonAuthorized || d.Evidence != legitEvidence {
		t.Fatalf("got %+v", d)
	}
}

func TestDNSRebindingCannotDerivePrincipal(t *testing.T) {
	d := Authorize(attackRoot(), ObservedArtifact{Destination: "localhost", DNSAnswer: "127.0.0.1", WebpageBytes: "rebind"})
	if d != Authorize(attackRoot(), ObservedArtifact{}) {
		t.Fatalf("dns metadata changed decision: %+v", d)
	}
}

func TestForwardedHeaderSpoofingCannotDerivePrincipal(t *testing.T) {
	d := Authorize(attackRoot(), ObservedArtifact{Host: "localhost", Origin: "https://evil.test", XForwardedProto: "https", XForwardedHost: "localhost"})
	if d != Authorize(attackRoot(), ObservedArtifact{}) {
		t.Fatalf("headers changed decision: %+v", d)
	}
}

func TestUnixSocketRelayCannotDerivePrincipal(t *testing.T) {
	d := Authorize(attackRoot(), ObservedArtifact{SocketLocality: "LOCAL", TransportKind: "unix"})
	if d != Authorize(attackRoot(), ObservedArtifact{}) {
		t.Fatalf("unix socket changed decision: %+v", d)
	}
}

func TestSmashedClaimedProofCannotAuthorize(t *testing.T) {
	art := ObservedArtifact{ClaimedPrincipal: localAgent, VisibleRole: "SYSTEM", ClaimedProof: ClaimedProof{
		Verdict: VerdictAllow, Proof: ProofValid, CallerAuthority: AuthorityUser, Principal: localAgent, Reason: reasonAuthorized,
	}}
	d := Authorize(attackRoot(), art)
	if d.Verdict != VerdictDeny || d.Evidence != attackEvidence {
		t.Fatalf("smashed proof authorized: %+v", d)
	}
}

func TestUnknownTransportEnumFailsClosed(t *testing.T) {
	root := legitRoot()
	root.TransportTrustClass = "LOCALHOST"
	d := EvaluatePrincipalDerivationProof(root)
	if d.Reason != reasonInvalidRoot || d.Evidence[5] != "Caller authority ZERO" || d.Evidence[7] != "Request DENY" {
		t.Fatalf("got %+v", d)
	}
}

func TestUnknownMandatingTrustClassFailsClosed(t *testing.T) {
	root := legitRoot()
	root.MandatingTrustClass = "TRUSTED_ASSISTANT"
	d := EvaluatePrincipalDerivationProof(root)
	if d.Reason != reasonInvalidRoot || d.Proof != ProofInvalid {
		t.Fatalf("got %+v", d)
	}
}

func TestFailedPrerequisitesDeny(t *testing.T) {
	root := legitRoot()
	root.ToolCapabilityAvailable = false
	d := EvaluatePrincipalDerivationProof(root)
	if d.Verdict != VerdictDeny || d.Proof != ProofValid || d.Reason != reasonToolUnavailable || d.CallerAuthority != AuthorityUser {
		t.Fatalf("tool: %+v", d)
	}
	root = legitRoot()
	root.SchemaVersion = 2
	if EvaluatePrincipalDerivationProof(root).Reason != reasonInvalidRoot {
		t.Fatal("schema")
	}
	root = legitRoot()
	root.TransportPrincipal = ""
	if EvaluatePrincipalDerivationProof(root).Reason != reasonTransportAbsent {
		t.Fatal("empty transport")
	}
}

func TestEvidenceComesFromReturnedDecision(t *testing.T) {
	eval := EvaluatePrincipalDerivationProof(attackRoot())
	auth := Authorize(attackRoot(), ObservedArtifact{Host: "localhost", ClaimedProof: ClaimedProof{Verdict: VerdictAllow}})
	if eval != auth || eval.Evidence != attackEvidence {
		t.Fatalf("Authorize diverged: %+v vs %+v", eval, auth)
	}
	if EvaluatePrincipalDerivationProof(legitRoot()).Evidence != legitEvidence {
		t.Fatal("legit evidence")
	}
}

func isolate(t *testing.T, mut func(*EvaluationRoot), reason string) {
	t.Helper()
	root := legitRoot()
	mut(&root)
	d := EvaluatePrincipalDerivationProof(root)
	if d.Verdict != VerdictDeny || d.Proof != ProofInvalid || d.Reason != reason {
		t.Fatalf("got %s/%s %q want DENY/INVALID %q", d.Verdict, d.Proof, d.Reason, reason)
	}
}

func TestUnattestedTransportIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.TransportTrustClass = TransportUnattested }, reasonTransportUnattested)
}
func TestTransportPrincipalAbsentIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.TransportPrincipal = "" }, reasonTransportAbsent)
}
func TestSessionIdentityUnboundIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.SessionIdentityBound = false }, reasonSessionUnbound)
}
func TestTransportSessionPrincipalMismatchIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) {
		r.SessionPrincipal, r.AgentPrincipal, r.MandatedAgentPrincipal = "agent:other", "agent:other", "agent:other"
	}, reasonTransportSession)
}
func TestMCPPrincipalUnauthenticatedIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.AgentAuthenticated = false }, reasonUnauthenticated)
}
func TestSessionAgentIdentityMismatchIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) {
		r.AgentPrincipal, r.MandatedAgentPrincipal = "agent:other", "agent:other"
	}, reasonSessionAgent)
}
func TestUserDelegationAbsentIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.DelegationFromUser = false }, reasonNoDelegation)
}
func TestMandatingPrincipalAbsentIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.MandatingPrincipal = "" }, reasonMandatingAbsent)
}
func TestMandatingAuthorityInsufficientIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.MandatingTrustClass = TrustUntrustedExternal }, reasonMandatingLacks)
}
func TestMandateTargetPrincipalMismatchIsolated(t *testing.T) {
	isolate(t, func(r *EvaluationRoot) { r.MandatedAgentPrincipal = "agent:other" }, reasonMandateTarget)
}
