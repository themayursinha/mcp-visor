// Package ownership implements Capability Ownership Proofs (card
// t_02a1bc43, Architect contract): every consequential action proves the
// current principal holds a valid delegation chain to the authority
// embodied by the capability. Deterministic, stdlib-only, no model calls.
package ownership

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
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

// CanonicalGrantSHA binds a grant's exact terms. The encoding is
// injective: every field and every collection element is length-prefixed
// (including the element count), so no two distinct grants share a hash.
// Timestamps use RFC3339Nano: time.Parse accepts fractional seconds, and
// coarser formatting would merge grants whose windows differ below one
// second into one hash.
func CanonicalGrantSHA(g Grant) string {
	h := sha256.New()
	writeField := func(s string) {
		var buf [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(buf[:], uint64(len(s)))
		h.Write(buf[:n])
		h.Write([]byte(s))
	}
	for _, s := range []string{g.ID, g.Owner, g.Delegate, g.Server, g.Tool, g.EffectClass, g.ScopeArgument, g.IssuedAt.UTC().Format(time.RFC3339Nano), g.ExpiresAt.UTC().Format(time.RFC3339Nano)} {
		writeField(s)
	}
	writeField(strconv.Itoa(len(g.ExactValues)))
	for _, v := range g.ExactValues {
		writeField(v)
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}
