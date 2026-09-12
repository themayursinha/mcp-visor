package instructionauthority

import (
	"fmt"
)

// Transform describes one context-construction hop.
type Transform struct {
	// Transformer names the harness stage (e.g. agent_summarizer).
	Transformer string
	// To is the resulting representation.
	To string
	// Via optionally names an intermediate store (e.g. SESSION_MEMORY).
	Via string
	// VisibleRole is presentation metadata assigned by the harness stage.
	VisibleRole string
	// RequestedAuthority, when non-empty, asks for elevation (always
	// suspect without an endorsement).
	RequestedAuthority string
	// NewContent is the transformed text.
	NewContent string
}

// Endorsement is a structured host input authorizing one promotion. Never
// parsed from object content.
type Endorsement struct {
	ID                   string
	Promoter             string
	GrantAuthority       string
	ParentContentSHA     string
	ChildContentSHA      string
	Transformer          string
	TargetRepresentation string
}

// TrustedPrincipal is the immutable registry entry for a promoter.
type TrustedPrincipal struct {
	Name    string
	Ceiling string
}

// ApplyTransform returns the object after one transformation. Origin and
// earlier derivations are copied forward and cannot be replaced. Without a
// valid endorsement, output authority never exceeds input authority: a
// requested increase is recorded as attempted, clamped, and fails
// continuity. FAILED continuity is sticky.
func ApplyTransform(obj InstructionObject, t Transform, endorse *Endorsement, registry map[string]TrustedPrincipal) InstructionObject {
	next := InstructionObject{
		SchemaVersion:      obj.SchemaVersion,
		Content:            t.NewContent,
		InstructionBearing: obj.InstructionBearing,
		EffectClass:        obj.EffectClass,
		Provenance: Provenance{
			Origin:                obj.Provenance.Origin,
			DerivedBy:             append(append([]Derivation{}, obj.Provenance.DerivedBy...), Derivation{Transformer: t.Transformer, FromRepresentation: obj.Provenance.CurrentRepresentation, ViaRepresentation: t.Via, ToRepresentation: t.To}),
			CurrentRepresentation: t.To,
			VisibleRole:           t.VisibleRole,
			Authority:             obj.Provenance.Authority,
			Lineage:               append(append([]string{}, obj.Provenance.Lineage...), obj.Provenance.Authority),
			ContentSHA256:         digest(t.NewContent),
			ParentContentSHA256:   obj.Provenance.ContentSHA256,
			Promotion:             obj.Provenance.Promotion,
		},
		InstructionEligible: false,
	}
	// Sticky failure: an already-failed lineage cannot wash clean. Later
	// attempts are still recorded (requested authority updated) so the
	// evidence never hides an escalation that followed the first failure.
	if obj.Provenance.Promotion.Continuity == ContinuityFailed {
		if t.RequestedAuthority != "" {
			next.Provenance.Promotion.Attempted = true
			next.Provenance.Promotion.RequestedAuthority = t.RequestedAuthority
		}
		return next
	}
	if t.RequestedAuthority == "" {
		return next
	}
	next.Provenance.Promotion.Attempted = true
	next.Provenance.Promotion.RequestedAuthority = t.RequestedAuthority
	if endorse != nil && validEndorsement(*endorse, obj, next, t, registry) {
		next.Provenance.Authority = endorse.GrantAuthority
		next.Provenance.Promotion.AuthorizedPromoter = endorse.Promoter
		next.Provenance.Promotion.EndorsementID = endorse.ID
		next.Provenance.Promotion.Continuity = ContinuityPass
		next.Provenance.Lineage[len(next.Provenance.Lineage)-1] = endorse.GrantAuthority
		return next
	}
	// Clamp to input authority and fail continuity.
	next.Provenance.Promotion.AuthorizedPromoter = "NONE"
	next.Provenance.Promotion.Continuity = ContinuityFailed
	return next
}

// validEndorsement checks an endorsement against the registry and both
// object states. Every binding must match exactly, including the requested
// authority: a SYSTEM grant for a USER request is not a narrow endorsement.
func validEndorsement(e Endorsement, parent, child InstructionObject, t Transform, registry map[string]TrustedPrincipal) bool {
	if e.ID == "" || e.Promoter == "" || e.GrantAuthority == "" {
		return false
	}
	if t.RequestedAuthority == "" || e.GrantAuthority != t.RequestedAuthority {
		return false
	}
	promoter, ok := registry[e.Promoter]
	if !ok {
		return false
	}
	if e.ParentContentSHA != parent.Provenance.ContentSHA256 {
		return false
	}
	if e.ChildContentSHA != child.Provenance.ContentSHA256 {
		return false
	}
	if e.Transformer != t.Transformer || e.TargetRepresentation != t.To {
		return false
	}
	grantRank, err := authorityRank(e.GrantAuthority)
	if err != nil {
		return false
	}
	ceilRank, err := authorityRank(promoter.Ceiling)
	if err != nil {
		return false
	}
	if grantRank > ceilRank {
		return false
	}
	inRank, err := authorityRank(parent.Provenance.Authority)
	if err != nil {
		return false
	}
	// The promoter must stand strictly above the input authority: peers
	// cannot promote each other. The promoter's own authority is its
	// registered ceiling.
	if ceilRank <= inRank {
		return false
	}
	if grantRank <= inRank {
		return false
	}
	return true
}

// Authorize decides whether an instruction-bearing object may execute.
// Requires continuity!=FAILED and effective authority at least USER.
// Failure never invokes the executor: content returns as an untrusted
// observation (instruction_eligible=false).
func Authorize(obj InstructionObject) (execute bool, reason string) {
	if obj.Provenance.Promotion.Continuity == ContinuityFailed {
		return false, "continuity FAILED"
	}
	rank, err := authorityRank(obj.Provenance.Authority)
	if err != nil {
		return false, "unknown authority"
	}
	userRank, _ := authorityRank(AuthorityUser)
	if rank < userRank {
		return false, "authority below USER"
	}
	return true, "authorized"
}

// DenyEvidence renders the stable denial fragments for protected output.
// Transition endpoints derive from the object's own lineage and requested
// authority (contract §12 fixes their literal form for the fixture).
func DenyEvidence(obj InstructionObject) []string {
	p := obj.Provenance
	lineage := ""
	for i, a := range p.Lineage {
		if i > 0 {
			lineage += "->"
		}
		lineage += a
	}
	from := p.Authority
	if len(p.Lineage) > 0 {
		from = p.Lineage[0]
	}
	to := p.Authority
	if p.Promotion.RequestedAuthority != "" {
		to = p.Promotion.RequestedAuthority
	}
	attempted := "NO"
	if p.Promotion.Attempted {
		attempted = "YES"
	}
	promoter := p.Promotion.AuthorizedPromoter
	if promoter == "" {
		promoter = "NONE"
	}
	return []string{
		"policy_decision=deny  policy_rule=instruction_authority_continuity",
		"reason=authority-expanding instruction",
		fmt.Sprintf("argument class INSTRUCTION  effect class %s", obj.EffectClass),
		fmt.Sprintf("visible role %s  original principal %s", p.VisibleRole, describeOrigin(p.Origin)),
		fmt.Sprintf("authority transition %s->%s", from, to),
		"lineage " + lineage,
		"attempted promotion " + attempted + "  authorized promoter " + promoter,
		"continuity " + p.Promotion.Continuity,
		fmt.Sprintf("observation preserved  authority %s", p.Authority),
		"result NOT_EXECUTED",
	}
}

// describeOrigin renders the origin for evidence. The fixture phrase for
// the canonical untrusted-MCP case is preserved verbatim.
func describeOrigin(o Origin) string {
	switch o.TrustClass {
	case TrustUntrustedMCPResponse:
		return "untrusted MCP response"
	case TrustTrustedUser:
		return "trusted user"
	case TrustTrustedDeveloper:
		return "trusted developer"
	case TrustTrustedSystem:
		return "trusted system"
	default:
		return o.Principal + " (" + o.TrustClass + ")"
	}
}
