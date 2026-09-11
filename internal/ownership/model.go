// Package ownership implements Capability Ownership Proofs (card
// t_02a1bc43, Architect contract): every consequential action proves the
// current principal holds a valid delegation chain to the authority
// embodied by the capability. Deterministic, stdlib-only, no model calls.
package ownership

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Verdicts for ownership evaluation.
const (
	VerdictValidDirect    = "VALID_DIRECT"
	VerdictValidDelegated = "VALID_DELEGATED"
	VerdictInvalid        = "INVALID"
)

// Reason codes for invalid proofs. Stable strings shared by the receipt,
// the audit reason, and the client error.
const (
	ReasonMissing    = "missing"
	ReasonExpired    = "expired"
	ReasonAmbiguous  = "ambiguous"
	ReasonMismatch   = "mismatch"
	ReasonNotCovered = "not_covered"
)

// Clock supplies evaluation time. Production passes the system clock once
// per call; tests inject fixed instants.
type Clock interface {
	Now() time.Time
}

// SystemClock implements Clock with wall time.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// FixedClock implements Clock with one instant for tests.
type FixedClock struct {
	At time.Time
}

// Now returns the fixed instant.
func (c FixedClock) Now() time.Time { return c.At }

// Capability binds one protected tool to its owner and effect.
type Capability struct {
	Server        string
	Owner         string
	Tool          string
	EffectClass   string
	ScopeArgument string
}

// Grant is a normalized exact delegation assertion.
type Grant struct {
	ID            string
	Owner         string
	Delegate      string
	Server        string
	Tool          string
	EffectClass   string
	ScopeArgument string
	ExactValues   []string
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

// Request is one ownership evaluation.
type Request struct {
	Requester   string
	Server      string
	Tool        string
	EffectClass string
	ScopeValue  string
	HasScope    bool
}

// Proof is the evaluated ownership claim.
type Proof struct {
	Verdict       string
	Reason        string
	Requester     string
	Server        string
	Tool          string
	Owner         string
	EffectClass   string
	DelegationID  string
	DelegationSHA string
	GrantIssued   time.Time
	GrantExpires  time.Time
	HasGrant      bool
	EvaluatedAt   time.Time
}

// CanonicalGrantSHA binds a grant's exact terms. Timestamps use RFC3339Nano:
// time.Parse accepts fractional seconds, and coarser formatting would merge
// grants whose windows differ below one second into one hash.
func CanonicalGrantSHA(g Grant) string {
	h := sha256.New()
	for _, s := range []string{g.ID, g.Owner, g.Delegate, g.Server, g.Tool, g.EffectClass, g.ScopeArgument, g.IssuedAt.UTC().Format(time.RFC3339Nano), g.ExpiresAt.UTC().Format(time.RFC3339Nano)} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	for _, v := range g.ExactValues {
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}
