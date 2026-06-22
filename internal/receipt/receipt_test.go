package receipt

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/signer"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(kp.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("pub key size: got %d, want %d", len(kp.PublicKey), ed25519.PublicKeySize)
	}
	if len(kp.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("priv key size: got %d, want %d", len(kp.PrivateKey), ed25519.PrivateKeySize)
	}
	if kp.KeyID == "" {
		t.Error("key ID empty")
	}
}

func TestReceiptSignAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	r, err := NewReceipt(
		"exec-001", "sess-001", "agent-001",
		"filesystem", "file_read",
		`{"name":"file_read","args":{"path":"/tmp/test.txt"}}`,
		`{"path":"/tmp/test.txt"}`,
		"1.0", "policy-yaml-content",
		"chain-context-data",
		"high-risk tool requires approval",
		"high", "ops-approver",
		"approve", 5*time.Minute,
	)
	if err != nil {
		t.Fatalf("NewReceipt: %v", err)
	}

	if err := r.Sign(kp); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if r.Signature == "" {
		t.Error("signature empty after signing")
	}
	if r.KeyID != kp.KeyID {
		t.Errorf("KeyID: got %s, want %s", r.KeyID, kp.KeyID)
	}

	if err := r.Verify(kp.PublicKey); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestReceiptSignWithGenericSigner(t *testing.T) {
	s, err := signer.NewApprovalSigner()
	if err != nil {
		t.Fatalf("NewApprovalSigner: %v", err)
	}
	r, err := NewReceipt("exec-001", "sess-001", "agent-001", "server", "tool", "req", "args", "1.0", "policy", "chain", "reason", "high", "approver", "approve", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewReceipt: %v", err)
	}
	if err := r.SignWith(s); err != nil {
		t.Fatalf("SignWith: %v", err)
	}
	if r.Signature == "" || r.Algorithm != "ed25519" || r.PublicKey == "" {
		t.Fatalf("receipt missing signature metadata: %+v", r)
	}
	v := signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))
	if err := r.VerifyWith(v); err != nil {
		t.Fatalf("VerifyWith: %v", err)
	}
	r.RedactedArgs = "tampered"
	if err := r.VerifyWith(v); err == nil {
		t.Fatal("VerifyWith should fail after tampering")
	}
}

func TestReceiptVerifyFailsWithModifiedPayload(t *testing.T) {
	kp, _ := GenerateKeyPair()
	r, _ := NewReceipt("exec-001", "sess-001", "agent-001", "server", "tool", "req", "args", "1.0", "policy", "chain", "reason", "high", "approver", "approve", 5*time.Minute)
	_ = r.Sign(kp)

	r.Tool = "modified_tool"
	if err := r.Verify(kp.PublicKey); err == nil {
		t.Error("verify should fail after payload modification")
	}
}

func TestReceiptVerifyFailsWithWrongKey(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	r, _ := NewReceipt("exec-001", "sess-001", "agent-001", "server", "tool", "req", "args", "1.0", "policy", "chain", "reason", "high", "approver", "approve", 5*time.Minute)
	_ = r.Sign(kp1)

	if err := r.Verify(kp2.PublicKey); err == nil {
		t.Error("verify should fail with wrong public key")
	}
}

func TestReceiptVerifyFailsUnsigned(t *testing.T) {
	kp, _ := GenerateKeyPair()
	r, _ := NewReceipt("exec-001", "sess-001", "agent-001", "server", "tool", "req", "args", "1.0", "policy", "chain", "reason", "high", "approver", "approve", 5*time.Minute)

	if err := r.Verify(kp.PublicKey); err == nil {
		t.Error("verify should fail for unsigned receipt")
	}
}

func TestReceiptExpiry(t *testing.T) {
	r, _ := NewReceipt("exec-001", "sess-001", "agent-001", "server", "tool", "req", "args", "1.0", "policy", "chain", "reason", "high", "approver", "approve", -1*time.Second)
	if !r.IsExpired() {
		t.Error("receipt with past expiry should be expired")
	}

	r2, _ := NewReceipt("exec-002", "sess-002", "agent-002", "server", "tool", "req", "args", "1.0", "policy", "chain", "reason", "high", "approver", "approve", 10*time.Minute)
	if r2.IsExpired() {
		t.Error("receipt with future expiry should not be expired")
	}
}

func TestReceiptMarshalRoundtrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	r, _ := NewReceipt("exec-001", "sess-001", "agent-001", "filesystem", "file_read", "req-hash", "args-hash", "1.0", "policy-content", "chain-content", "reason", "high", "approver", "approve", 5*time.Minute)
	_ = r.Sign(kp)

	data, err := r.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	parsed, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if err := parsed.Verify(kp.PublicKey); err != nil {
		t.Fatalf("re-verify after roundtrip: %v", err)
	}
	if parsed.ExecutionID != r.ExecutionID {
		t.Errorf("execution ID mismatch: %s vs %s", parsed.ExecutionID, r.ExecutionID)
	}
	if parsed.Server != r.Server {
		t.Errorf("server mismatch")
	}
}

func TestNonceUniqueness(t *testing.T) {
	nonces := make(map[string]bool)
	for i := 0; i < 100; i++ {
		n, err := GenerateNonce()
		if err != nil {
			t.Fatalf("GenerateNonce: %v", err)
		}
		if nonces[n] {
			t.Error("duplicate nonce")
		}
		nonces[n] = true
	}
}
