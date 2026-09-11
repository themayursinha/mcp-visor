package ownership

import (
	"testing"
	"time"
)

var (
	fixedNow = time.Date(2026, 9, 11, 10, 5, 0, 0, time.UTC)
	grantOn  = time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	grantOff = time.Date(2026, 9, 11, 10, 15, 0, 0, time.UTC)
)

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	r, err := NewRegistry([]Capability{
		{Server: "mcp-server-A", Owner: "tenant-A", Tool: "calculator", EffectClass: "COMPUTE"},
		{Server: "mcp-server-B", Owner: "tenant-B", Tool: "read_secret", EffectClass: "CREDENTIAL"},
		{Server: "mcp-server-B", Owner: "tenant-B", Tool: "internal_fetch", EffectClass: "NETWORK", ScopeArgument: "resource"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.AddGrant(Grant{
		ID: "b-to-a-fetch-x", Owner: "tenant-B", Delegate: "tenant-A",
		Server: "mcp-server-B", Tool: "internal_fetch", EffectClass: "NETWORK",
		ScopeArgument: "resource", ExactValues: []string{"X"},
		IssuedAt: grantOn, ExpiresAt: grantOff,
	})
	return r
}

func TestDirectOwnerAllowed(t *testing.T) {
	r := testRegistry(t)
	for _, req := range []Request{
		{Requester: "tenant-A", Server: "mcp-server-A", Tool: "calculator", EffectClass: "COMPUTE"},
		{Requester: "tenant-B", Server: "mcp-server-B", Tool: "read_secret", EffectClass: "CREDENTIAL"},
	} {
		if p := r.Evaluate(req, fixedNow); p.Verdict != VerdictValidDirect {
			t.Fatalf("%v: verdict=%s want direct", req, p.Verdict)
		}
	}
}

func TestCrossTenantDenied(t *testing.T) {
	r := testRegistry(t)
	p := r.Evaluate(Request{Requester: "tenant-A", Server: "mcp-server-B", Tool: "read_secret", EffectClass: "CREDENTIAL"}, fixedNow)
	if p.Verdict != VerdictInvalid || p.Reason != ReasonMissing {
		t.Fatalf("verdict=%s reason=%s want INVALID/missing", p.Verdict, p.Reason)
	}
}

func TestNarrowDelegationAllowed(t *testing.T) {
	r := testRegistry(t)
	p := r.Evaluate(Request{Requester: "tenant-A", Server: "mcp-server-B", Tool: "internal_fetch", EffectClass: "NETWORK", ScopeValue: "X", HasScope: true}, fixedNow)
	if p.Verdict != VerdictValidDelegated || p.DelegationID != "b-to-a-fetch-x" {
		t.Fatalf("verdict=%s delegation=%s want delegated/b-to-a-fetch-x", p.Verdict, p.DelegationID)
	}
	if p.DelegationSHA == "" {
		t.Fatal("delegation SHA must bind the grant")
	}
}

func TestDelegationDoesNotAuthorizeSiblingTool(t *testing.T) {
	r := testRegistry(t)
	// Same grant cannot authorize read_secret: different tool, no scope.
	p := r.Evaluate(Request{Requester: "tenant-A", Server: "mcp-server-B", Tool: "read_secret", EffectClass: "CREDENTIAL", ScopeValue: "X", HasScope: true}, fixedNow)
	if p.Verdict != VerdictInvalid {
		t.Fatalf("sibling tool authorized: %+v", p)
	}
}

func TestScopeMismatchDenied(t *testing.T) {
	r := testRegistry(t)
	for _, req := range []Request{
		{Requester: "tenant-A", Server: "mcp-server-B", Tool: "internal_fetch", EffectClass: "NETWORK", ScopeValue: "Y", HasScope: true},
		{Requester: "tenant-A", Server: "mcp-server-B", Tool: "internal_fetch", EffectClass: "NETWORK"},
		{Requester: "tenant-A", Server: "mcp-server-B", Tool: "internal_fetch", EffectClass: "NETWORK", ScopeValue: "x", HasScope: true},
	} {
		if p := r.Evaluate(req, fixedNow); p.Verdict != VerdictInvalid {
			t.Fatalf("%v: verdict=%s want INVALID", req, p.Verdict)
		}
	}
}

func TestExpiryBoundaries(t *testing.T) {
	r := testRegistry(t)
	req := Request{Requester: "tenant-A", Server: "mcp-server-B", Tool: "internal_fetch", EffectClass: "NETWORK", ScopeValue: "X", HasScope: true}
	if p := r.Evaluate(req, grantOn); p.Verdict != VerdictValidDelegated {
		t.Fatalf("issued_at must be inclusive: %+v", p)
	}
	justBefore := grantOff.Add(-time.Nanosecond)
	if p := r.Evaluate(req, justBefore); p.Verdict != VerdictValidDelegated {
		t.Fatalf("pre-expiry must hold: %+v", p)
	}
	if p := r.Evaluate(req, grantOff); p.Verdict != VerdictInvalid || p.Reason != ReasonExpired {
		t.Fatalf("expires_at must be exclusive: %+v", p)
	}
	if p := r.Evaluate(req, grantOn.Add(-time.Second)); p.Reason != ReasonExpired {
		t.Fatalf("pre-issue reason=%s want expired", p.Reason)
	}
}

func TestAmbiguousGrantsDenied(t *testing.T) {
	r := testRegistry(t)
	r.AddGrant(Grant{
		ID: "b-to-a-fetch-x-dup", Owner: "tenant-B", Delegate: "tenant-A",
		Server: "mcp-server-B", Tool: "internal_fetch", EffectClass: "NETWORK",
		ScopeArgument: "resource", ExactValues: []string{"X"},
		IssuedAt: grantOn, ExpiresAt: grantOff,
	})
	p := r.Evaluate(Request{Requester: "tenant-A", Server: "mcp-server-B", Tool: "internal_fetch", EffectClass: "NETWORK", ScopeValue: "X", HasScope: true}, fixedNow)
	if p.Verdict != VerdictInvalid || p.Reason != ReasonAmbiguous {
		t.Fatalf("verdict=%s reason=%s want INVALID/ambiguous", p.Verdict, p.Reason)
	}
}

func TestMutationInvalidates(t *testing.T) {
	r := testRegistry(t)
	base := Request{Requester: "tenant-A", Server: "mcp-server-B", Tool: "internal_fetch", EffectClass: "NETWORK", ScopeValue: "X", HasScope: true}
	mutations := []Request{
		{Requester: "tenant-X", Server: "mcp-server-B", Tool: "internal_fetch", EffectClass: "NETWORK", ScopeValue: "X", HasScope: true},
		{Requester: "tenant-A", Server: "mcp-server-C", Tool: "internal_fetch", EffectClass: "NETWORK", ScopeValue: "X", HasScope: true},
		{Requester: "tenant-A", Server: "mcp-server-B", Tool: "internal_fetch", EffectClass: "COMPUTE", ScopeValue: "X", HasScope: true},
	}
	_ = base
	for i, m := range mutations {
		if p := r.Evaluate(m, fixedNow); p.Verdict != VerdictInvalid {
			t.Fatalf("mutation %d authorized: %+v", i, p)
		}
	}
}

func TestDuplicateCapabilityRejected(t *testing.T) {
	_, err := NewRegistry([]Capability{
		{Server: "s", Owner: "a", Tool: "t", EffectClass: "E"},
		{Server: "s", Owner: "b", Tool: "t", EffectClass: "E"},
	})
	if err == nil {
		t.Fatal("duplicate capability accepted")
	}
}

func TestCanonicalGrantSHADeterministic(t *testing.T) {
	r := testRegistry(t)
	var g Grant
	for _, grant := range r.grants {
		g = grant
	}
	if a, b := CanonicalGrantSHA(g), CanonicalGrantSHA(g); a != b || len(a) != 64 {
		t.Fatalf("grant SHA unstable: %q", a)
	}
}
