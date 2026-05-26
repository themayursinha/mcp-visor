package signer

import (
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/receipt"
)

func TestNewApprovalSigner(t *testing.T) {
	s, err := NewApprovalSigner()
	if err != nil {
		t.Fatalf("NewApprovalSigner: %v", err)
	}
	if s.KeyID() == "" {
		t.Error("KeyID empty")
	}
	if s.Algorithm() != "ed25519" {
		t.Errorf("Algorithm: got %s, want ed25519", s.Algorithm())
	}
}

func TestSignAndVerify(t *testing.T) {
	s, err := NewApprovalSigner()
	if err != nil {
		t.Fatalf("NewApprovalSigner: %v", err)
	}

	data := []byte("test data to sign")
	sig, err := s.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	v := NewVerifierFromPublicKey(s.pubKey)

	if err := v.Verify(data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSignAndVerifyFailsWithModifiedData(t *testing.T) {
	s, _ := NewApprovalSigner()
	data := []byte("original data")
	sig, _ := s.Sign(data)

	v := NewVerifierFromPublicKey(s.pubKey)
	if err := v.Verify([]byte("modified data"), sig); err == nil {
		t.Error("should fail on modified data")
	}
}

func TestSignAndVerifyFailsWithWrongKey(t *testing.T) {
	s1, _ := NewApprovalSigner()
	s2, _ := NewApprovalSigner()

	data := []byte("test data")
	sig, _ := s1.Sign(data)

	v := NewVerifierFromPublicKey(s2.pubKey)
	if err := v.Verify(data, sig); err == nil {
		t.Error("should fail with wrong public key")
	}
}

func TestKeyPersistence(t *testing.T) {
	s, err := NewApprovalSigner()
	if err != nil {
		t.Fatalf("NewApprovalSigner: %v", err)
	}

	dir := t.TempDir()
	pubPath := filepath.Join(dir, "pubkey.pem")

	if err := ExportPublicKey(s.pubKey, pubPath); err != nil {
		t.Fatalf("ExportPublicKey: %v", err)
	}

	v, err := NewApprovalVerifier(pubPath)
	if err != nil {
		t.Fatalf("NewApprovalVerifier: %v", err)
	}

	data := []byte("test for persisted key")
	sig, _ := s.Sign(data)
	if err := v.Verify(data, sig); err != nil {
		t.Fatalf("verify after load: %v", err)
	}
}

func TestReceiptSigningFlow(t *testing.T) {
	s, err := NewApprovalSigner()
	if err != nil {
		t.Fatalf("NewApprovalSigner: %v", err)
	}

	r, err := receipt.NewReceipt(
		"exec-signer-test", "sess-signer", "agent-signer",
		"cloud", "aws_iam_create_user",
		`{"name":"aws_iam_create_user"}`,
		`{"username":"test-admin"}`,
		"1.0", "policy-content",
		"chain-data", "critical operation requires approval",
		"critical", "security-approver",
		"approve", 5*time.Minute,
	)
	if err != nil {
		t.Fatalf("NewReceipt: %v", err)
	}

	receiptData, _ := json.Marshal(r)
	sig, err := s.Sign(receiptData)
	if err != nil {
		t.Fatalf("Sign receipt: %v", err)
	}

	v := NewVerifierFromPublicKey(s.pubKey)
	if err := v.Verify(receiptData, sig); err != nil {
		t.Fatalf("Verify receipt: %v", err)
	}

	modifiedR := *r
	modifiedR.Decision = "deny"
	modifiedData, _ := json.Marshal(&modifiedR)
	if err := v.Verify(modifiedData, sig); err == nil {
		t.Error("should fail when receipt is modified")
	}
}

func TestHexSignatureRoundtrip(t *testing.T) {
	sig := []byte("test-signature-bytes-32bytes!!")
	hex := HexSignature(sig)
	parsed, err := ParseHexSignature(hex)
	if err != nil {
		t.Fatalf("ParseHexSignature: %v", err)
	}
	if string(parsed) != string(sig) {
		t.Errorf("roundtrip failed: %s vs %s", string(parsed), string(sig))
	}
}

func TestGeneratedKeySize(t *testing.T) {
	s, _ := NewApprovalSigner()
	if len(s.pubKey) != ed25519.PublicKeySize {
		t.Errorf("pubkey size: got %d, want %d", len(s.pubKey), ed25519.PublicKeySize)
	}
}
