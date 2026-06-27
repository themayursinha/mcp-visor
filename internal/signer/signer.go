package signer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

type Signer interface {
	Sign(data []byte) ([]byte, error)
	PublicKey() crypto.PublicKey
	KeyID() string
	Algorithm() string
}

type Verifier interface {
	Verify(data []byte, signature []byte) error
	PublicKey() crypto.PublicKey
	KeyID() string
}

type ApprovalSigner struct {
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
	keyID   string
}

func NewApprovalSigner() (*ApprovalSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	keyID := fmt.Sprintf("key-%s", hex.EncodeToString(pub[:8]))
	return &ApprovalSigner{
		privKey: priv,
		pubKey:  pub,
		keyID:   keyID,
	}, nil
}

func LoadApprovalSigner(privKeyPath string) (*ApprovalSigner, error) {
	data, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	var priv ed25519.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 key: %w", err)
		}
		var ok bool
		priv, ok = key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not ed25519")
		}
	case "ED25519 PRIVATE KEY":
		if len(block.Bytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid ed25519 private key size")
		}
		priv = ed25519.PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	pub := priv.Public().(ed25519.PublicKey)
	keyID := fmt.Sprintf("key-%s", hex.EncodeToString(pub[:8]))

	return &ApprovalSigner{
		privKey: priv,
		pubKey:  pub,
		keyID:   keyID,
	}, nil
}

func (s *ApprovalSigner) Sign(data []byte) ([]byte, error) {
	sig := ed25519.Sign(s.privKey, data)
	return sig, nil
}

func (s *ApprovalSigner) PublicKey() crypto.PublicKey {
	return s.pubKey
}

func (s *ApprovalSigner) KeyID() string {
	return s.keyID
}

func (s *ApprovalSigner) Algorithm() string {
	return "ed25519"
}

type ApprovalVerifier struct {
	pubKey ed25519.PublicKey
	keyID  string
}

func NewApprovalVerifier(pubKeyPath string) (*ApprovalVerifier, error) {
	data, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	var pub ed25519.PublicKey
	var keyID string

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}
		var ok bool
		pub, ok = key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is not ed25519")
		}
	default:
		if len(block.Bytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 public key size")
		}
		pub = ed25519.PublicKey(block.Bytes)
	}

	keyID = fmt.Sprintf("key-%s", hex.EncodeToString(pub[:8]))

	return &ApprovalVerifier{
		pubKey: pub,
		keyID:  keyID,
	}, nil
}

func NewVerifierFromPublicKey(pubKey ed25519.PublicKey) *ApprovalVerifier {
	keyID := fmt.Sprintf("key-%s", hex.EncodeToString(pubKey[:8]))
	return &ApprovalVerifier{
		pubKey: pubKey,
		keyID:  keyID,
	}
}

func (v *ApprovalVerifier) Verify(data []byte, signature []byte) error {
	if !ed25519.Verify(v.pubKey, data, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func (v *ApprovalVerifier) PublicKey() crypto.PublicKey {
	return v.pubKey
}

func (v *ApprovalVerifier) KeyID() string {
	return v.keyID
}

func ExportPublicKey(pub ed25519.PublicKey, path string) error {
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkix,
	}
	data := pem.EncodeToMemory(block)
	return os.WriteFile(path, data, 0o644)
}

func HexSignature(sig []byte) string {
	return hex.EncodeToString(sig)
}

func ParseHexSignature(hexSig string) ([]byte, error) {
	return hex.DecodeString(hexSig)
}
