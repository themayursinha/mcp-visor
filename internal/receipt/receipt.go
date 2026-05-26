package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type DecisionReceipt struct {
	ExecutionID      string `json:"execution_id"`
	SessionID        string `json:"session_id"`
	AgentID          string `json:"agent_id"`
	Server           string `json:"server"`
	Tool             string `json:"tool"`
	OriginalRequest  string `json:"original_request_hash"`
	RedactedArgs     string `json:"redacted_argument_hash"`
	PolicyVersion    string `json:"policy_version"`
	PolicyHash       string `json:"policy_hash"`
	ChainContextHash string `json:"chain_context_hash"`
	ApprovalReason   string `json:"approval_reason"`
	RiskLevel        string `json:"risk_level"`
	ApproverID       string `json:"approver_id"`
	Decision         string `json:"decision"`
	Expiry           int64  `json:"expiry"`
	Nonce            string `json:"nonce"`
	KeyID            string `json:"signature_key_id"`
	Signature        string `json:"signature,omitempty"`
}

type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	KeyID      string
}

func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	keyID := fmt.Sprintf("key-%s", hex.EncodeToString(pub[:8]))
	return &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
		KeyID:      keyID,
	}, nil
}

func GenerateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func NewReceipt(executionID, sessionID, agentID, server, tool, originalRequest, redactedArgs, policyVersion, policyYAML, chainContext, approvalReason, riskLevel, approverID, decision string, ttl time.Duration) (*DecisionReceipt, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	policyHash := sha256Hex([]byte(policyYAML))
	chainHash := sha256Hex([]byte(chainContext))

	return &DecisionReceipt{
		ExecutionID:      executionID,
		SessionID:        sessionID,
		AgentID:          agentID,
		Server:           server,
		Tool:             tool,
		OriginalRequest:  sha256Hex([]byte(originalRequest)),
		RedactedArgs:     sha256Hex([]byte(redactedArgs)),
		PolicyVersion:    policyVersion,
		PolicyHash:       policyHash,
		ChainContextHash: chainHash,
		ApprovalReason:   approvalReason,
		RiskLevel:        riskLevel,
		ApproverID:       approverID,
		Decision:         decision,
		Expiry:           time.Now().Add(ttl).Unix(),
		Nonce:            nonce,
	}, nil
}

func (r *DecisionReceipt) Sign(key *KeyPair) error {
	r.KeyID = key.KeyID
	r.Signature = ""

	payload := r.signingPayload()
	sig := ed25519.Sign(key.PrivateKey, payload)
	r.Signature = hex.EncodeToString(sig)
	return nil
}

func (r *DecisionReceipt) Verify(pubKey ed25519.PublicKey) error {
	if r.Signature == "" {
		return fmt.Errorf("receipt is not signed")
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	payload := r.signingPayload()
	if !ed25519.Verify(pubKey, payload, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func (r *DecisionReceipt) IsExpired() bool {
	return time.Now().Unix() > r.Expiry
}

func (r *DecisionReceipt) signingPayload() []byte {
	copy := *r
	copy.Signature = ""
	data, _ := json.Marshal(copy)
	return data
}

func (r *DecisionReceipt) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func Unmarshal(data []byte) (*DecisionReceipt, error) {
	var r DecisionReceipt
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("unmarshal receipt: %w", err)
	}
	return &r, nil
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
