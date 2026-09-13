package proxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/themayursinha/mcp-visor/internal/instructionauthority"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

const (
	instructionAuthorityAssertionSchema = 1
	instructionAuthorityMaxLifetimeSecs = 60
	instructionAuthorityMaxFutureSkew   = 5
	instructionAuthorityNonceSize       = 32
	instructionAuthoritySigSize         = ed25519.SignatureSize
)

var (
	instructionAuthorityKeyIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	instructionAuthorityHashRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type instructionAuthorityAssertion struct {
	SchemaVersion  int    `json:"schema_version"`
	KeyID          string `json:"key_id"`
	SessionID      string `json:"session_id"`
	ClientID       string `json:"client_id"`
	LogicalServer  string `json:"logical_server"`
	ToolName       string `json:"tool_name"`
	RequestSHA256  string `json:"request_sha256"`
	EnvelopeSHA256 string `json:"envelope_sha256"`
	Nonce          string `json:"nonce"`
	IssuedAtUnix   int64  `json:"issued_at_unix"`
	ExpiresAtUnix  int64  `json:"expires_at_unix"`
	Signature      string `json:"signature"`
}

type instructionAuthorityClaims struct {
	SchemaVersion  int    `json:"schema_version"`
	KeyID          string `json:"key_id"`
	SessionID      string `json:"session_id"`
	ClientID       string `json:"client_id"`
	LogicalServer  string `json:"logical_server"`
	ToolName       string `json:"tool_name"`
	RequestSHA256  string `json:"request_sha256"`
	EnvelopeSHA256 string `json:"envelope_sha256"`
	Nonce          string `json:"nonce"`
	IssuedAtUnix   int64  `json:"issued_at_unix"`
	ExpiresAtUnix  int64  `json:"expires_at_unix"`
}

type instructionAuthorityUnsignedEnvelope struct {
	InstructionObject instructionauthority.InstructionObject `json:"instruction_object"`
	EvaluationRoot    instructionAuthorityRootWire           `json:"evaluation_root"`
}

func decodeInstructionAuthorityKeys(raw map[string]string) map[string]ed25519.PublicKey {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]ed25519.PublicKey, len(raw))
	for id, enc := range raw {
		key, err := decodeInstructionAuthorityPublicKey(id, enc)
		if err != nil {
			continue
		}
		out[id] = key
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func decodeInstructionAuthorityPublicKey(id, enc string) (ed25519.PublicKey, error) {
	if !instructionAuthorityKeyIDRe.MatchString(id) {
		return nil, fmt.Errorf("invalid key id")
	}
	b, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(b) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(b) != enc {
		return nil, fmt.Errorf("invalid key")
	}
	return ed25519.PublicKey(b), nil
}

func instructionAuthoritySigningBytes(assertion instructionAuthorityAssertion) ([]byte, error) {
	claims := instructionAuthorityClaims{
		SchemaVersion:  assertion.SchemaVersion,
		KeyID:          assertion.KeyID,
		SessionID:      assertion.SessionID,
		ClientID:       assertion.ClientID,
		LogicalServer:  assertion.LogicalServer,
		ToolName:       assertion.ToolName,
		RequestSHA256:  assertion.RequestSHA256,
		EnvelopeSHA256: assertion.EnvelopeSHA256,
		Nonce:          assertion.Nonce,
		IssuedAtUnix:   assertion.IssuedAtUnix,
		ExpiresAtUnix:  assertion.ExpiresAtUnix,
	}
	return json.Marshal(claims)
}

func instructionAuthorityEnvelopeSHA256(env instructionAuthorityEnvelope) (string, error) {
	unsigned := instructionAuthorityUnsignedEnvelope{
		InstructionObject: env.InstructionObject,
		EvaluationRoot:    env.EvaluationRoot,
	}
	b, err := json.Marshal(unsigned)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func stripInstructionAuthorityMeta(raw json.RawMessage) (json.RawMessage, error) {
	nl := bytes.HasSuffix(raw, []byte{'\n'})
	body := bytes.TrimSuffix(raw, []byte{'\n'})
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	paramsRaw, ok := req["params"]
	if !ok || !jsonRawObject(paramsRaw) {
		return nil, fmt.Errorf("params")
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		return nil, err
	}
	metaRaw, ok := params["_meta"]
	if !ok || !jsonRawObject(metaRaw) {
		return nil, fmt.Errorf("_meta")
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return nil, err
	}
	if _, ok := meta[instructionAuthorityMetaKey]; !ok {
		return nil, fmt.Errorf("missing visor key")
	}
	delete(meta, instructionAuthorityMetaKey)
	newMeta, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	params["_meta"] = newMeta
	newParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	req["params"] = newParams
	out, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if nl {
		out = append(out, '\n')
	}
	return out, nil
}

var instructionAuthorityStrip = stripInstructionAuthorityMeta

func instructionAuthorityRequestSHA256(raw json.RawMessage) string {
	body := bytes.TrimSuffix(raw, []byte{'\n'})
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func structuralInstructionAuthorityAssertion(a *instructionAuthorityAssertion, nowUnix int64) string {
	if a == nil {
		return "instruction authority assertion missing"
	}
	if a.SchemaVersion != instructionAuthorityAssertionSchema ||
		a.KeyID == "" || a.SessionID == "" || a.ClientID == "" ||
		a.LogicalServer == "" || a.ToolName == "" ||
		a.RequestSHA256 == "" || a.EnvelopeSHA256 == "" ||
		a.Nonce == "" || a.Signature == "" ||
		!instructionAuthorityKeyIDRe.MatchString(a.KeyID) ||
		!instructionAuthorityHashRe.MatchString(a.RequestSHA256) ||
		!instructionAuthorityHashRe.MatchString(a.EnvelopeSHA256) ||
		a.IssuedAtUnix <= 0 ||
		a.ExpiresAtUnix <= a.IssuedAtUnix ||
		a.ExpiresAtUnix-a.IssuedAtUnix > instructionAuthorityMaxLifetimeSecs ||
		a.IssuedAtUnix > nowUnix+instructionAuthorityMaxFutureSkew {
		return "instruction authority assertion malformed"
	}
	nonce, err := base64.RawURLEncoding.DecodeString(a.Nonce)
	if err != nil || len(nonce) != instructionAuthorityNonceSize || base64.RawURLEncoding.EncodeToString(nonce) != a.Nonce {
		return "instruction authority assertion malformed"
	}
	sig, err := base64.RawURLEncoding.DecodeString(a.Signature)
	if err != nil || len(sig) != instructionAuthoritySigSize || base64.RawURLEncoding.EncodeToString(sig) != a.Signature {
		return "instruction authority assertion malformed"
	}
	return ""
}

func (p *Proxy) verifyInstructionAuthorityAssertion(
	env instructionAuthorityEnvelope,
	stripped json.RawMessage,
	callReq mcp.ToolsCallRequest,
	serverName string,
	snapshot runtimeSnapshot,
) string {
	a := env.Assertion
	now := p.now().UTC()
	if reason := structuralInstructionAuthorityAssertion(a, now.Unix()); reason != "" {
		return reason
	}
	envHash, err := instructionAuthorityEnvelopeSHA256(env)
	if err != nil {
		return "instruction authority assertion malformed"
	}
	reqHash := instructionAuthorityRequestSHA256(stripped)
	pub, ok := snapshot.instructionAuthorityKeys[a.KeyID]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return "instruction authority assertion key unknown"
	}
	msg, err := instructionAuthoritySigningBytes(*a)
	if err != nil {
		return "instruction authority assertion malformed"
	}
	sig, err := base64.RawURLEncoding.DecodeString(a.Signature)
	if err != nil || !ed25519.Verify(pub, msg, sig) {
		return "instruction authority assertion signature invalid"
	}
	if now.Unix() >= a.ExpiresAtUnix {
		return "instruction authority assertion expired"
	}
	if a.SessionID != p.session.ID {
		return "instruction authority assertion session mismatch"
	}
	if a.ClientID != p.session.ClientID {
		return "instruction authority assertion client mismatch"
	}
	if a.LogicalServer != serverName {
		return "instruction authority assertion server mismatch"
	}
	if a.ToolName != callReq.Name {
		return "instruction authority assertion tool mismatch"
	}
	if subtle.ConstantTimeCompare([]byte(a.RequestSHA256), []byte(reqHash)) != 1 {
		return "instruction authority assertion request hash mismatch"
	}
	if subtle.ConstantTimeCompare([]byte(a.EnvelopeSHA256), []byte(envHash)) != 1 {
		return "instruction authority assertion envelope hash mismatch"
	}
	if !p.session.ConsumeInstructionAuthorityNonce(a.Nonce, a.ExpiresAtUnix, now.Unix()) {
		return "instruction authority assertion replayed"
	}
	return ""
}
