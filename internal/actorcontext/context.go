// Package actorcontext is the Visor side of VerifiedActorContext v1.
// The JSON object is produced only after Agent Identity Plane verification
// and delivered on a process-start fd. MCP tools/call arguments are never
// a source of this type.
package actorcontext

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	VersionV1           = "1"
	VerificationSTSDpop = "sts+dpop"
	maxBytes            = 1 << 20
)

// ActorRef is one hop in the verified actor chain (principal first, acting agent last).
type ActorRef struct {
	ID string `json:"id"`
}

// Context is the trusted internal representation. It is not a token format.
type Context struct {
	Version              string     `json:"version"`
	PrincipalID          string     `json:"principal_id"`
	ActingAgent          string     `json:"acting_agent"`
	WorkloadID           string     `json:"workload_id,omitempty"`
	Transaction          string     `json:"transaction"`
	ActorChain           []ActorRef `json:"actor_chain"`
	Scopes               []string   `json:"scopes"`
	Issuer               string     `json:"issuer,omitempty"`
	Audience             string     `json:"audience,omitempty"`
	TokenID              string     `json:"token_id,omitempty"`
	ExpiresAt            time.Time  `json:"expires_at"`
	ProofKeyThumbprint   string     `json:"proof_key_thumbprint,omitempty"`
	VerificationMethod   string     `json:"verification_method"`
	IdentitySnapshotHash string     `json:"identity_snapshot_hash"`
}

type snapshotBody struct {
	Version            string     `json:"version"`
	PrincipalID        string     `json:"principal_id"`
	ActingAgent        string     `json:"acting_agent"`
	WorkloadID         string     `json:"workload_id"`
	Transaction        string     `json:"transaction"`
	ActorChain         []ActorRef `json:"actor_chain"`
	Scopes             []string   `json:"scopes"`
	Issuer             string     `json:"issuer"`
	Audience           string     `json:"audience"`
	TokenID            string     `json:"token_id"`
	ExpiresAt          string     `json:"expires_at"`
	ProofKeyThumbprint string     `json:"proof_key_thumbprint"`
	VerificationMethod string     `json:"verification_method"`
}

func SnapshotHash(c Context) (string, error) {
	scopes := append([]string{}, c.Scopes...)
	chain := append([]ActorRef{}, c.ActorChain...)
	body := snapshotBody{
		Version:            c.Version,
		PrincipalID:        c.PrincipalID,
		ActingAgent:        c.ActingAgent,
		WorkloadID:         c.WorkloadID,
		Transaction:        c.Transaction,
		ActorChain:         chain,
		Scopes:             scopes,
		Issuer:             c.Issuer,
		Audience:           c.Audience,
		TokenID:            c.TokenID,
		ExpiresAt:          c.ExpiresAt.UTC().Format(time.RFC3339Nano),
		ProofKeyThumbprint: c.ProofKeyThumbprint,
		VerificationMethod: c.VerificationMethod,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (c *Context) Seal() error {
	if c == nil {
		return fmt.Errorf("actorcontext: missing context")
	}
	h, err := SnapshotHash(*c)
	if err != nil {
		return err
	}
	c.IdentitySnapshotHash = h
	return c.ValidateStructure()
}

func (c Context) ValidateStructure() error {
	if c.Version != VersionV1 {
		return fmt.Errorf("actorcontext: unsupported version %q", c.Version)
	}
	if strings.TrimSpace(c.PrincipalID) == "" {
		return fmt.Errorf("actorcontext: missing principal_id")
	}
	if strings.TrimSpace(c.ActingAgent) == "" {
		return fmt.Errorf("actorcontext: missing acting_agent")
	}
	if strings.TrimSpace(c.Transaction) == "" {
		return fmt.Errorf("actorcontext: missing transaction")
	}
	if c.ExpiresAt.IsZero() {
		return fmt.Errorf("actorcontext: missing expires_at")
	}
	if strings.TrimSpace(c.VerificationMethod) == "" {
		return fmt.Errorf("actorcontext: missing verification_method")
	}
	if len(c.ActorChain) == 0 {
		return fmt.Errorf("actorcontext: empty actor_chain")
	}
	if c.ActorChain[0].ID != c.PrincipalID {
		return fmt.Errorf("actorcontext: principal_id must equal actor_chain[0]")
	}
	if c.ActorChain[len(c.ActorChain)-1].ID != c.ActingAgent {
		return fmt.Errorf("actorcontext: acting_agent must equal actor_chain last hop")
	}
	want, err := SnapshotHash(c)
	if err != nil {
		return err
	}
	if c.IdentitySnapshotHash != want {
		return fmt.Errorf("actorcontext: identity_snapshot_hash mismatch")
	}
	return nil
}

func (c Context) Check(now time.Time) error {
	if err := c.ValidateStructure(); err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !now.Before(c.ExpiresAt.UTC()) {
		return fmt.Errorf("actorcontext: expired")
	}
	return nil
}

func (c Context) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func Decode(r io.Reader) (*Context, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, fmt.Errorf("actorcontext: context exceeds 1MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Context
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("actorcontext: %w", err)
	}
	if err := c.ValidateStructure(); err != nil {
		return nil, err
	}
	return &c, nil
}

func Encode(c Context) ([]byte, error) {
	if err := c.Seal(); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

// DecodeFD reads one VerifiedActorContext from a process-start file
// descriptor. fd <= 0 means the operator omitted the flag (no context).
// fd 0/1/2 are reserved for the MCP stdio streams.
func DecodeFD(fd int) (*Context, error) {
	if fd <= 0 {
		return nil, nil
	}
	if fd < 3 {
		return nil, fmt.Errorf("actorcontext: fd %d overlaps stdin/stdout/stderr", fd)
	}
	f := os.NewFile(uintptr(fd), "verified-actor")
	if f == nil {
		return nil, fmt.Errorf("actorcontext: invalid fd %d", fd)
	}
	defer f.Close()
	return Decode(f)
}

// ArgumentIdentityKeys are tools/call argument names that must never be
// treated as VerifiedActorContext. They are stripped before relay.
var ArgumentIdentityKeys = []string{"_verified_actor", "verified_actor", "verified_actor_context"}

// StripArgumentIdentity copies args without spoofable identity keys.
func StripArgumentIdentity(args map[string]any) (map[string]any, bool) {
	if args == nil {
		return nil, false
	}
	skip := make(map[string]struct{}, len(ArgumentIdentityKeys))
	for _, k := range ArgumentIdentityKeys {
		skip[k] = struct{}{}
	}
	changed := false
	out := make(map[string]any, len(args))
	for k, v := range args {
		if _, ok := skip[k]; ok {
			changed = true
			continue
		}
		out[k] = v
	}
	if !changed {
		return args, false
	}
	return out, true
}
