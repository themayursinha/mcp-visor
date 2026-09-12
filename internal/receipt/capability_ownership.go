package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// CapabilityOwnershipReceipt is a signed Capability Ownership Proof
// (card t_02a1bc43): it binds requester + endpoint + capability owner +
// delegation + permitted effect. Evidence only, never a reusable
// authorization token. Raw resource values and secrets are never copied
// in: only the scope-value hash.
type CapabilityOwnershipReceipt struct {
	Schema         string `json:"schema"`
	Requester      string `json:"requester"`
	Server         string `json:"endpoint"`
	Tool           string `json:"tool"`
	Owner          string `json:"capability_owner"`
	EffectClass    string `json:"effect_class"`
	ScopeArgument  string `json:"scope_argument,omitempty"`
	ScopeValueSHA  string `json:"scope_value_sha,omitempty"`
	DelegationID   string `json:"delegation_id,omitempty"`
	DelegationSHA  string `json:"delegation_sha,omitempty"`
	Status         string `json:"status"`
	GrantIssuedAt  string `json:"grant_issued_at,omitempty"`
	GrantExpiresAt string `json:"grant_expires_at,omitempty"`
	RequestHash    string `json:"request_hash"`
	PolicyHash     string `json:"policy_hash"`
	// EvaluatedAt is unix nanoseconds: sub-second grant windows need
	// lossless evaluation instants in signed evidence.
	EvaluatedAt int64  `json:"evaluated_at"`
	Verdict     string `json:"verdict"`
	ReasonCode  string `json:"reason_code"`
	KeyID       string `json:"signature_key_id"`
	Algorithm   string `json:"signature_algorithm,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	Signature   string `json:"signature,omitempty"`
}

// Receipt statuses mirror ownership verdicts plus the reason dimension.
const (
	OwnershipStatusDirect    = "direct"
	OwnershipStatusMatched   = "matched"
	OwnershipStatusMissing   = "missing"
	OwnershipStatusExpired   = "expired"
	OwnershipStatusAmbiguous = "ambiguous"
	OwnershipStatusMismatch  = "mismatch"
)

// Sign signs the receipt with key, covering every preceding field.
func (r *CapabilityOwnershipReceipt) Sign(key *KeyPair) error {
	r.KeyID = key.KeyID
	r.Algorithm = "ed25519"
	r.PublicKey = hex.EncodeToString(key.PublicKey)
	r.Signature = ""
	sig := ed25519.Sign(key.PrivateKey, r.signingPayload())
	r.Signature = hex.EncodeToString(sig)
	return nil
}

// Verify checks the signature against pubKey.
func (r *CapabilityOwnershipReceipt) Verify(pubKey ed25519.PublicKey) error {
	if r.Signature == "" {
		return fmt.Errorf("receipt is not signed")
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pubKey, r.signingPayload(), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// SignWith signs with any SigningKey (e.g. the proxy approval signer).
func (r *CapabilityOwnershipReceipt) SignWith(s SigningKey) error {
	if s == nil {
		return fmt.Errorf("signer is nil")
	}
	r.KeyID = s.KeyID()
	r.Algorithm = s.Algorithm()
	r.Signature = ""
	if pub, ok := s.PublicKey().(ed25519.PublicKey); ok {
		r.PublicKey = hex.EncodeToString(pub)
	}
	sig, err := s.Sign(r.signingPayload())
	if err != nil {
		return fmt.Errorf("sign ownership receipt: %w", err)
	}
	r.Signature = hex.EncodeToString(sig)
	return nil
}

func (r *CapabilityOwnershipReceipt) signingPayload() []byte {
	copy := *r
	copy.Signature = ""
	data, _ := json.Marshal(copy)
	return data
}

// Marshal renders the receipt as JSON.
func (r *CapabilityOwnershipReceipt) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

// UnmarshalOwnershipReceipt parses a receipt. Numbers decode via
// UseNumber so 64-bit integers (unix-nano evaluated_at) survive exactly;
// a float64 round trip would rewrite them. Call Verify afterwards.
func UnmarshalOwnershipReceipt(data []byte) (*CapabilityOwnershipReceipt, error) {
	var r CapabilityOwnershipReceipt
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("unmarshal ownership receipt: %w", err)
	}
	return &r, nil
}
