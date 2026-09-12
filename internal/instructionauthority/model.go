// Package instructionauthority implements Instruction Authority
// Continuity Proofs (card t_082600d5, Architect contract): transformation
// of information must never increase the authority of its originating
// principal unless a legitimate higher-authority principal explicitly
// endorses it. Deterministic, stdlib-only, no model calls.
package instructionauthority

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// SchemaVersion is the instruction-object schema implemented here.
const SchemaVersion = 1

// Authority levels, fixed total order. Roles, representations, storage
// locations, and message slots are NOT authority: moving content into a
// USER slot never confers USER authority.
const (
	AuthorityDataOnly  = "DATA_ONLY"
	AuthorityUser      = "USER"
	AuthorityDeveloper = "DEVELOPER"
	AuthoritySystem    = "SYSTEM"
)

// Trust classes bound to ceiling authorities. Unknown principals or enum
// values fail closed as DATA_ONLY.
const (
	TrustUntrustedMCPResponse = "UNTRUSTED_MCP_RESPONSE"
	TrustTrustedUser          = "TRUSTED_USER"
	TrustTrustedDeveloper     = "TRUSTED_DEVELOPER"
	TrustTrustedSystem        = "TRUSTED_SYSTEM"
)

// Representations in the canonical laundering path.
const (
	ReprMCPOutput          = "MCP_OUTPUT"
	ReprAgentSummary       = "AGENT_SUMMARY"
	ReprSessionMemory      = "SESSION_MEMORY"
	ReprPersistentGoal     = "PERSISTENT_GOAL"
	ReprSecondAgentMessage = "SECOND_AGENT_MESSAGE"
)

// Visible roles are presentation metadata only, never authority.
const (
	RoleNone      = "NONE"
	RoleUser      = "USER"
	RoleDeveloper = "DEVELOPER"
	RoleSystem    = "SYSTEM"
)

// Continuity outcomes.
const (
	ContinuityPass   = "PASS"
	ContinuityFailed = "FAILED"
)

// authorityRank orders the lattice lowest first.
func authorityRank(a string) (int, error) {
	switch a {
	case AuthorityDataOnly:
		return 0, nil
	case AuthorityUser:
		return 1, nil
	case AuthorityDeveloper:
		return 2, nil
	case AuthoritySystem:
		return 3, nil
	default:
		return 0, fmt.Errorf("unknown authority %q", a)
	}
}

// ceilingForTrust maps a trust class to its ceiling authority. Unknown
// classes fail closed as DATA_ONLY (no error: the ceiling is the denial).
func ceilingForTrust(class string) string {
	switch class {
	case TrustTrustedUser:
		return AuthorityUser
	case TrustTrustedDeveloper:
		return AuthorityDeveloper
	case TrustTrustedSystem:
		return AuthoritySystem
	default:
		return AuthorityDataOnly
	}
}

// Origin identifies the originating principal. Immutable once set.
type Origin struct {
	Principal  string `json:"principal"`
	TrustClass string `json:"trust_class"`
}

// Derivation records one transformation hop.
type Derivation struct {
	Transformer        string `json:"transformer"`
	FromRepresentation string `json:"from_representation"`
	ViaRepresentation  string `json:"via_representation,omitempty"`
	ToRepresentation   string `json:"to_representation"`
}

// Promotion records an authority-change attempt on this object.
type Promotion struct {
	RequestedAuthority string `json:"requested_authority"`
	Attempted          bool   `json:"attempted"`
	AuthorizedPromoter string `json:"authorized_promoter"`
	EndorsementID      string `json:"endorsement_id,omitempty"`
	Continuity         string `json:"continuity"`
	// DigestFailure marks a digest-linkage break: the hop log no longer
	// describes one object's history. Set by fold, read by evidence.
	DigestFailure bool `json:"digest_failure,omitempty"`
}

// Provenance travels with every instruction-bearing object.
type Provenance struct {
	Origin                Origin       `json:"origin"`
	DerivedBy             []Derivation `json:"derived_by"`
	CurrentRepresentation string       `json:"current_representation"`
	VisibleRole           string       `json:"visible_role"`
	Authority             string       `json:"authority"`
	Lineage               []string     `json:"lineage"`
	ContentSHA256         string       `json:"content_sha256"`
	ParentContentSHA256   string       `json:"parent_content_sha256,omitempty"`
	Promotion             Promotion    `json:"promotion"`
}

// EvaluationRoot is the only caller-supplied trust root. Authorize and
// DenyEvidence take origin, instruction-bearing, and effect class from
// here, never from InstructionObject fields. History and Content are
// the only other evaluation inputs; Provenance is fold output.
// Promoter signatures and MACs are a declared non-goal.
type EvaluationRoot struct {
	Origin             Origin
	InstructionBearing bool
	EffectClass        string
}

// InstructionObject is one materialized instruction-bearing object.
// InstructionBearing and EffectClass are fixture-supplied, never inferred.
// History is the append-only derivation log; Provenance is the fold's
// read-only view over Origin and History (see fold in evaluator.go).
type InstructionObject struct {
	SchemaVersion       int        `json:"schema_version"`
	Content             string     `json:"content"`
	InstructionBearing  bool       `json:"instruction_bearing"`
	EffectClass         string     `json:"effect_class"`
	Provenance          Provenance `json:"provenance"`
	History             []Hop      `json:"history"`
	InstructionEligible bool       `json:"instruction_eligible"`
}

// Endorsement is a structured host input authorizing one promotion. Never
// parsed from object content.
type Endorsement struct {
	ID                   string `json:"id"`
	Promoter             string `json:"promoter"`
	GrantAuthority       string `json:"grant_authority"`
	ParentContentSHA     string `json:"parent_content_sha"`
	ChildContentSHA      string `json:"child_content_sha"`
	Transformer          string `json:"transformer"`
	TargetRepresentation string `json:"target_representation"`
}

// TrustedPrincipal is the immutable registry entry for a promoter.
type TrustedPrincipal struct {
	Name    string `json:"name"`
	Ceiling string `json:"ceiling"`
}

// Hop is one appended derivation record. Append-only: once recorded, a hop
// is never edited in place. The fold derives all state (authority,
// lineage, promotion outcomes, digests, representations) from Origin plus
// the hop log, so derived fields cannot go stale relative to each other.
//
// HopDigest is an injective commitment to every security-relevant field
// on the hop, including the append-time endorsement verdict and the
// promoter ceiling observed at append. ParentHopDigest chains those
// commitments. Fold and VerifyProvenance recompute the digest; a flipped
// verdict, rewritten endorsement, or swapped ceiling without a matching
// digest is a digest failure, not a promotion.
type Hop struct {
	Derivation         Derivation   `json:"derivation"`
	Content            string       `json:"content"`
	ContentDigest      string       `json:"content_digest"`
	ParentDigest       string       `json:"parent_digest"`
	VisibleRole        string       `json:"visible_role"`
	RequestedAuthority string       `json:"requested_authority,omitempty"`
	Endorsement        *Endorsement `json:"endorsement,omitempty"`
	// EndorsementValid records the append-time validation verdict. It is
	// not independently trusted: hopDigest binds it, and fold refuses a
	// grant unless the endorsement pointer, observed ceiling, and digest
	// all agree with that verdict.
	EndorsementValid bool `json:"endorsement_valid"`
	// ObservedCeiling is the promoter's registry ceiling at append time
	// (empty if the promoter was absent). Bound into HopDigest so a later
	// registry upgrade cannot be copied into history without breaking the
	// hop chain.
	ObservedCeiling string `json:"observed_ceiling,omitempty"`
	// ParentHopDigest is the previous hop's HopDigest, or the origin
	// content digest for the first hop.
	ParentHopDigest string `json:"parent_hop_digest"`
	// HopDigest is hopDigest(this hop) computed at append.
	HopDigest string `json:"hop_digest"`
}

// digest binds content bytes.
func digest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// hopDigest injectively binds one hop's security-relevant fields. Every
// field is length-prefixed so concatenations cannot collide. HopDigest
// itself is the output, never an input.
func hopDigest(hop Hop) string {
	h := sha256.New()
	write := func(s string) {
		var buf [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(buf[:], uint64(len(s)))
		h.Write(buf[:n])
		h.Write([]byte(s))
	}
	write(hop.ParentDigest)
	write(hop.ContentDigest)
	write(hop.Content)
	write(hop.VisibleRole)
	write(hop.RequestedAuthority)
	write(hop.ParentHopDigest)
	write(hop.ObservedCeiling)
	if hop.EndorsementValid {
		write("1")
	} else {
		write("0")
	}
	if hop.Endorsement == nil {
		write("0")
	} else {
		write("1")
		write(hop.Endorsement.ID)
		write(hop.Endorsement.Promoter)
		write(hop.Endorsement.GrantAuthority)
		write(hop.Endorsement.ParentContentSHA)
		write(hop.Endorsement.ChildContentSHA)
		write(hop.Endorsement.Transformer)
		write(hop.Endorsement.TargetRepresentation)
	}
	write(hop.Derivation.Transformer)
	write(hop.Derivation.FromRepresentation)
	write(hop.Derivation.ViaRepresentation)
	write(hop.Derivation.ToRepresentation)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// NewOriginObject materializes an origin object: authority is the trust
// ceiling, lineage starts empty (origin authority recorded separately).
func NewOriginObject(content string, origin Origin, representation, effectClass string, instructionBearing bool) InstructionObject {
	// Unknown trust classes fail closed through the ceiling mapping
	// (DATA_ONLY); no error path needed.
	return InstructionObject{
		SchemaVersion:      SchemaVersion,
		Content:            content,
		InstructionBearing: instructionBearing,
		EffectClass:        effectClass,
		Provenance: Provenance{
			Origin:                origin,
			CurrentRepresentation: representation,
			VisibleRole:           RoleNone,
			Authority:             ceilingForTrust(origin.TrustClass),
			Lineage:               []string{},
			ContentSHA256:         digest(content),
			Promotion:             Promotion{Continuity: ContinuityPass},
		},
		InstructionEligible: false,
	}
}
