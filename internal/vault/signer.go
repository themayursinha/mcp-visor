package vault

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/themayursinha/mcp-visor/internal/signer"
)

type TransitSigner struct {
	client  *Client
	keyName string
	keyID   string
	pubKey  ed25519.PublicKey
}

func NewTransitSigner(client *Client, keyName string) (*TransitSigner, error) {
	pubKey, err := client.GetPublicKey(context.Background(), keyName)
	if err != nil {
		return nil, fmt.Errorf("transit signer: %w", err)
	}

	return &TransitSigner{
		client:  client,
		keyName: keyName,
		keyID:   fmt.Sprintf("vault-transit:%s", keyName),
		pubKey:  pubKey,
	}, nil
}

func (s *TransitSigner) Sign(data []byte) ([]byte, error) {
	vaultSig, err := s.client.Sign(context.Background(), s.keyName, data)
	if err != nil {
		return nil, fmt.Errorf("transit sign: %w", err)
	}
	raw, err := parseVaultSignature(vaultSig)
	if err != nil {
		return nil, fmt.Errorf("transit sign: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("transit sign: unexpected signature size %d", len(raw))
	}
	return raw, nil
}

func (s *TransitSigner) PublicKey() crypto.PublicKey {
	return s.pubKey
}

func (s *TransitSigner) KeyID() string {
	return s.keyID
}

func (s *TransitSigner) Algorithm() string {
	return "ed25519-vault-transit"
}

var _ signer.Signer = (*TransitSigner)(nil)

type TransitVerifier struct {
	client  *Client
	keyName string
	keyID   string
	pubKey  ed25519.PublicKey
}

func NewTransitVerifier(client *Client, keyName string) (*TransitVerifier, error) {
	pubKey, err := client.GetPublicKey(context.Background(), keyName)
	if err != nil {
		return nil, fmt.Errorf("transit verifier: %w", err)
	}

	return &TransitVerifier{
		client:  client,
		keyName: keyName,
		keyID:   fmt.Sprintf("vault-transit:%s", keyName),
		pubKey:  pubKey,
	}, nil
}

func (v *TransitVerifier) Verify(data []byte, signature []byte) error {
	vaultSig := fmt.Sprintf("vault:v1:%s", base64.StdEncoding.EncodeToString(signature))
	valid, err := v.client.Verify(context.Background(), v.keyName, data, vaultSig)
	if err != nil {
		return fmt.Errorf("transit verify: %w", err)
	}
	if !valid {
		return fmt.Errorf("transit verify: signature invalid")
	}
	return nil
}

func (v *TransitVerifier) PublicKey() crypto.PublicKey {
	return v.pubKey
}

func (v *TransitVerifier) KeyID() string {
	return v.keyID
}

var _ signer.Verifier = (*TransitVerifier)(nil)
