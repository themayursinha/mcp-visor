package receipt

import (
	"testing"
)

func TestOwnershipReceiptSignVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	r := &CapabilityOwnershipReceipt{
		Schema: "capability_ownership_v1", Requester: "tenant-A",
		Server: "mcp-server-B", Tool: "internal_fetch", Owner: "tenant-B",
		EffectClass: "NETWORK", ScopeArgument: "resource",
		DelegationID: "b-to-a-fetch-x", Status: OwnershipStatusMatched,
		Verdict: "allow", ReasonCode: "matched",
	}
	if err := r.Sign(kp); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(kp.PublicKey); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
}

func TestOwnershipReceiptMutationBreaks(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	r := &CapabilityOwnershipReceipt{Schema: "capability_ownership_v1", Requester: "tenant-A", Verdict: "allow"}
	if err := r.Sign(kp); err != nil {
		t.Fatal(err)
	}
	r.Requester = "tenant-X"
	if err := r.Verify(kp.PublicKey); err == nil {
		t.Fatal("mutated receipt verified")
	}
	other, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	r.Requester = "tenant-A"
	if err := r.Verify(other.PublicKey); err == nil {
		t.Fatal("wrong-key receipt verified")
	}
}
