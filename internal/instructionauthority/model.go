// Package instructionauthority implements Instruction Authority
// Continuity Proofs (card t_082600d5, Architect contract): transformation
// of information must never increase the authority of its originating
// principal unless a legitimate higher-authority principal explicitly
// endorses it. Deterministic, stdlib-only, no model calls.
package instructionauthority

import (
	"crypto/sha256"
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

// InstructionObject is one materialized instruction-bearing object.
// InstructionBearing and EffectClass are fixture-supplied, never inferred.
type InstructionObject struct {
	SchemaVersion       int        `json:"schema_version"`
	Content             string     `json:"content"`
	InstructionBearing  bool       `json:"instruction_bearing"`
	EffectClass         string     `json:"effect_class"`
	Provenance          Provenance `json:"provenance"`
	InstructionEligible bool       `json:"instruction_eligible"`
}

// digest binds content bytes.
func digest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
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
