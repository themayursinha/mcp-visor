package signer_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/signer"
)

func BenchmarkApprovalSignerSign(b *testing.B) {
	s, err := signer.NewApprovalSigner()
	if err != nil {
		b.Fatal(err)
	}
	payload := []byte(`{"tool":"file_read","path":"/tmp/test","approved_by":"admin","timestamp":"2024-01-01T00:00:00Z"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Sign(payload)
	}
}

func BenchmarkApprovalVerifierVerify(b *testing.B) {
	s, err := signer.NewApprovalSigner()
	if err != nil {
		b.Fatal(err)
	}
	payload := []byte("approval-decision-payload-for-verification")
	sig, err := s.Sign(payload)
	if err != nil {
		b.Fatal(err)
	}
	pubKey := s.PublicKey().(ed25519.PublicKey)
	v := signer.NewVerifierFromPublicKey(pubKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.Verify(payload, sig)
	}
}

func BenchmarkApprovalSignerSmallPayload(b *testing.B) {
	s, err := signer.NewApprovalSigner()
	if err != nil {
		b.Fatal(err)
	}
	payload := []byte("ok")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Sign(payload)
	}
}

func BenchmarkApprovalVerifierWrongSignature(b *testing.B) {
	s, err := signer.NewApprovalSigner()
	if err != nil {
		b.Fatal(err)
	}
	pubKey := s.PublicKey().(ed25519.PublicKey)
	v := signer.NewVerifierFromPublicKey(pubKey)
	payload := []byte("real-payload")
	wrongSig := make([]byte, 64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.Verify(payload, wrongSig)
	}
}
