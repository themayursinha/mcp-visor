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

// ApplyTransform returns the object after one transformation. It appends
// one hop record and recomputes Provenance from scratch via fold: no
// derived field is ever mutated piecemeal, so authority, lineage,
// promotion outcomes, digests, and representations cannot drift apart.
func ApplyTransform(obj InstructionObject, t Transform, endorse *Endorsement, registry map[string]TrustedPrincipal) InstructionObject {
	parentDigest := digest(obj.Content)
	parentHop := parentDigest
	if n := len(obj.History); n > 0 {
		parentHop = obj.History[n-1].HopDigest
	}
	var endorsed *Endorsement
	if endorse != nil {
		copied := *endorse
		endorsed = &copied
	}
	observedCeiling := ""
	if endorsed != nil {
		if p, ok := registry[endorsed.Promoter]; ok {
			observedCeiling = p.Ceiling
		}
	}
	hop := Hop{
		Derivation: Derivation{
			Transformer:        t.Transformer,
			FromRepresentation: obj.Provenance.CurrentRepresentation,
			ViaRepresentation:  t.Via,
			ToRepresentation:   t.To,
		},
		Content:            t.NewContent,
		ContentDigest:      digest(t.NewContent),
		ParentDigest:       parentDigest,
		VisibleRole:        t.VisibleRole,
		RequestedAuthority: t.RequestedAuthority,
		Endorsement:        endorsed,
		ObservedCeiling:    observedCeiling,
		ParentHopDigest:    parentHop,
	}
	// Verdict is computed at append against the current registry and bound
	// into HopDigest. Later refolds honor the recorded verdict, so a
	// registry upgrade cannot revive a rejection; flipping the boolean
	// without the matching digest is a digest failure.
	hop.EndorsementValid = endorse != nil && t.RequestedAuthority != "" &&
		validEndorsement(*endorsed, hop.ParentDigest, obj.Provenance.Authority, hop.ContentDigest, hop.Derivation.Transformer, hop.Derivation.ToRepresentation, hop.RequestedAuthority, registry)
	hop.HopDigest = hopDigest(hop)
	next := InstructionObject{
		SchemaVersion:       obj.SchemaVersion,
		Content:             t.NewContent,
		InstructionBearing:  obj.InstructionBearing,
		EffectClass:         obj.EffectClass,
		History:             append(append([]Hop{}, obj.History...), hop),
		InstructionEligible: false,
	}
	next.Provenance = fold(obj.Provenance.Origin, obj.Provenance.CurrentRepresentation, next.History)
	return next
}

// fold recomputes the full Provenance from origin plus the append-only hop
// log. It is the sole writer of derived state: every rule below sees the
// same inputs in the same order, so field-level staleness (stale IDs,
// hidden escalations, misattributed reasons, phantom depths) is
// structurally impossible.
func fold(origin Origin, originRepr string, hops []Hop) Provenance {
	prov := Provenance{
		Origin:                origin,
		DerivedBy:             []Derivation{},
		CurrentRepresentation: originRepr,
		VisibleRole:           RoleNone,
		Authority:             ceilingForTrust(origin.TrustClass),
		Lineage:               []string{},
		ContentSHA256:         "",
		Promotion:             Promotion{Continuity: ContinuityPass},
	}
	runningDigest := ""
	runningHop := ""
	if len(hops) > 0 {
		runningDigest = hops[0].ParentDigest
		runningHop = hops[0].ParentHopDigest
	}
	for i, hop := range hops {
		// Record the hop first, including a clean attempt state. Digest
		// failures, sticky failures, and grants all share this writer so
		// a later attempt cannot keep a prior promoter or endorsement ID.
		beginHop(&prov, hop, runningDigest)
		digestBroken := (runningDigest != "" && hop.ParentDigest != runningDigest) ||
			(runningHop != "" && hop.ParentHopDigest != runningHop) ||
			digest(hop.Content) != hop.ContentDigest ||
			hop.HopDigest != hopDigest(hop) ||
			(hop.EndorsementValid && hop.Endorsement == nil) ||
			(i == 0 && hop.ParentHopDigest != hop.ParentDigest)
		if hop.ContentDigest != "" {
			runningDigest = hop.ContentDigest
		}
		if hop.HopDigest != "" {
			runningHop = hop.HopDigest
		} else {
			runningHop = hopDigest(hop)
		}
		if digestBroken {
			prov.Promotion.Continuity = ContinuityFailed
			prov.Promotion.DigestFailure = true
			continue
		}
		if prov.Promotion.Continuity == ContinuityFailed {
			continue
		}
		if hop.RequestedAuthority == "" {
			continue
		}
		if !grantFromHop(&prov, hop) {
			prov.Promotion.Continuity = ContinuityFailed
		}
	}
	return prov
}

// beginHop is the only writer of per-hop presentation, lineage, and
// attempt fields. Attempt-specific promoter data is cleared whenever a
// hop requests a promotion, including hops that later fail their digest.
func beginHop(prov *Provenance, hop Hop, runningDigest string) {
	prov.DerivedBy = append(prov.DerivedBy, hop.Derivation)
	prov.Lineage = append(prov.Lineage, prov.Authority)
	prov.CurrentRepresentation = hop.Derivation.ToRepresentation
	prov.VisibleRole = hop.VisibleRole
	if runningDigest != "" {
		prov.ParentContentSHA256 = runningDigest
	}
	prov.ContentSHA256 = hop.ContentDigest
	if hop.RequestedAuthority != "" {
		prov.Promotion.Attempted = true
		prov.Promotion.RequestedAuthority = hop.RequestedAuthority
		prov.Promotion.EndorsementID = ""
		prov.Promotion.AuthorizedPromoter = ""
	}
}

// grantFromHop applies a recorded endorsement. The stored boolean is
// never enough: the endorsement pointer, grant/request equality, and the
// append-time observed ceiling must all hold. Returns false to fail
// continuity without granting.
func grantFromHop(prov *Provenance, hop Hop) bool {
	if !hop.EndorsementValid || hop.Endorsement == nil {
		return false
	}
	e := hop.Endorsement
	if e.GrantAuthority != hop.RequestedAuthority {
		return false
	}
	grantRank, err := authorityRank(e.GrantAuthority)
	if err != nil {
		return false
	}
	ceilRank, err := authorityRank(hop.ObservedCeiling)
	if err != nil {
		return false
	}
	if grantRank > ceilRank {
		return false
	}
	prov.Authority = e.GrantAuthority
	prov.Promotion.AuthorizedPromoter = e.Promoter
	prov.Promotion.EndorsementID = e.ID
	prov.Promotion.Continuity = ContinuityPass
	prov.Lineage[len(prov.Lineage)-1] = e.GrantAuthority
	return true
}

// validEndorsement checks an endorsement against the registry and the hop's
// recorded digests, transformer, target, and requested authority. Every
// binding must match exactly, including grant == requested: a SYSTEM grant
// for a USER request is not a narrow endorsement.
func validEndorsement(e Endorsement, parentDigest, parentAuthority, childDigest, transformer, to, requested string, registry map[string]TrustedPrincipal) bool {
	if e.ID == "" || e.Promoter == "" || e.GrantAuthority == "" {
		return false
	}
	if requested == "" || e.GrantAuthority != requested {
		return false
	}
	promoter, ok := registry[e.Promoter]
	if !ok {
		return false
	}
	if e.ParentContentSHA != parentDigest {
		return false
	}
	if e.ChildContentSHA != childDigest {
		return false
	}
	if e.Transformer != transformer || e.TargetRepresentation != to {
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
	inRank, err := authorityRank(parentAuthority)
	if err != nil {
		return false
	}
	// The promoter must stand strictly above the input authority: peers
	// cannot promote each other.
	if ceilRank <= inRank {
		return false
	}
	if grantRank <= inRank {
		return false
	}
	return true
}

// VerifyProvenance recomputes the provenance from origin and history and
// reports divergence: any hand-edited Authority, Lineage, Promotion,
// digest, representation, or derivation fails. Untrusted bytes must pass
// through here before Authorize.
func VerifyProvenance(obj InstructionObject, root EvaluationRoot, registry map[string]TrustedPrincipal) error {
	if err := matchRoot(obj, root); err != nil {
		return err
	}
	// History-free origin objects verify against genesis state directly:
	// fold over zero hops carries no content digest of its own. Authority
	// is the caller's origin ceiling, never a trust class edited into the
	// object.
	if len(obj.History) == 0 {
		want := Provenance{
			Origin:                root.Origin,
			DerivedBy:             []Derivation{},
			CurrentRepresentation: obj.Provenance.CurrentRepresentation,
			VisibleRole:           RoleNone,
			Authority:             ceilingForTrust(root.Origin.TrustClass),
			Lineage:               []string{},
			ContentSHA256:         digest(obj.Content),
			Promotion:             Promotion{Continuity: ContinuityPass},
		}
		if !provenanceEqual(want, obj.Provenance) {
			return fmt.Errorf("origin provenance mismatch")
		}
		return nil
	}
	originRepr := obj.History[0].Derivation.FromRepresentation
	for i, hop := range obj.History {
		if hop.EndorsementValid && hop.Endorsement == nil {
			return fmt.Errorf("hop %d claims a valid endorsement without an endorsement", i)
		}
		if digest(hop.Content) != hop.ContentDigest {
			return fmt.Errorf("hop %d content does not match content digest", i)
		}
		if hop.HopDigest != hopDigest(hop) {
			return fmt.Errorf("hop %d hop digest mismatch", i)
		}
	}
	fresh := fold(root.Origin, originRepr, obj.History)
	if fresh.Promotion.DigestFailure {
		return fmt.Errorf("digest chain broken")
	}
	if !provenanceEqual(fresh, obj.Provenance) {
		return fmt.Errorf("provenance does not match history")
	}
	// Registry cross-check: revalidate every recorded endorsement against
	// the live registry. Agreement means the verdict still holds;
	// disagreement means registry drift or tampering — both fail closed,
	// so rejections stay rejected and acceptances stay accepted only
	// while their basis stands.
	for i, hop := range obj.History {
		if hop.Endorsement == nil {
			if hop.EndorsementValid {
				return fmt.Errorf("hop %d claims a valid endorsement without an endorsement", i)
			}
			continue
		}
		parentAuthority := ""
		if i == 0 {
			parentAuthority = ceilingForTrust(root.Origin.TrustClass)
		} else {
			// Authority before this hop is not stored per hop; recompute
			// the prefix fold and read it.
			prefix := fold(root.Origin, originRepr, obj.History[:i])
			parentAuthority = prefix.Authority
		}
		live := validEndorsement(*hop.Endorsement, hop.ParentDigest, parentAuthority, hop.ContentDigest, hop.Derivation.Transformer, hop.Derivation.ToRepresentation, hop.RequestedAuthority, registry)
		if live != hop.EndorsementValid {
			return fmt.Errorf("hop %d endorsement verdict disagrees with registry", i)
		}
	}
	// Content must agree with the folded digest chain.
	want := ""
	if len(obj.History) > 0 {
		want = obj.History[len(obj.History)-1].ContentDigest
	} else {
		want = digest(obj.Content)
	}
	if obj.Provenance.ContentSHA256 != want {
		return fmt.Errorf("content digest does not match history")
	}
	if digest(obj.Content) != want {
		return fmt.Errorf("content does not match digest chain")
	}
	return nil
}

func provenanceEqual(a, b Provenance) bool {
	if a.Origin != b.Origin || a.CurrentRepresentation != b.CurrentRepresentation ||
		a.VisibleRole != b.VisibleRole || a.Authority != b.Authority ||
		a.ContentSHA256 != b.ContentSHA256 || a.ParentContentSHA256 != b.ParentContentSHA256 ||
		a.Promotion != b.Promotion {
		return false
	}
	if len(a.Lineage) != len(b.Lineage) || len(a.DerivedBy) != len(b.DerivedBy) {
		return false
	}
	for i := range a.Lineage {
		if a.Lineage[i] != b.Lineage[i] {
			return false
		}
	}
	for i := range a.DerivedBy {
		if a.DerivedBy[i] != b.DerivedBy[i] {
			return false
		}
	}
	return true
}

// Authorize decides whether an instruction-bearing object may execute.
// Requires continuity!=FAILED and effective authority at least USER.
// Failure never invokes the executor: content returns as an untrusted
// observation (instruction_eligible=false).
func matchRoot(obj InstructionObject, root EvaluationRoot) error {
	if obj.Provenance.Origin != root.Origin {
		return fmt.Errorf("origin does not match evaluation root")
	}
	if obj.InstructionBearing != root.InstructionBearing {
		return fmt.Errorf("instruction-bearing does not match evaluation root")
	}
	if obj.EffectClass != root.EffectClass {
		return fmt.Errorf("effect class does not match evaluation root")
	}
	return nil
}

func heldRootProvenance(root EvaluationRoot) Provenance {
	return Provenance{
		Origin:      root.Origin,
		DerivedBy:   []Derivation{},
		VisibleRole: RoleNone,
		Authority:   ceilingForTrust(root.Origin.TrustClass),
		Lineage:     []string{},
		Promotion:   Promotion{Continuity: ContinuityPass},
	}
}

func derivedProvenance(obj InstructionObject, root EvaluationRoot) (Provenance, error) {
	if err := matchRoot(obj, root); err != nil {
		return Provenance{}, err
	}
	if len(obj.History) == 0 {
		return Provenance{
			Origin:                root.Origin,
			DerivedBy:             []Derivation{},
			CurrentRepresentation: obj.Provenance.CurrentRepresentation,
			VisibleRole:           RoleNone,
			Authority:             ceilingForTrust(root.Origin.TrustClass),
			Lineage:               []string{},
			ContentSHA256:         digest(obj.Content),
			Promotion:             Promotion{Continuity: ContinuityPass},
		}, nil
	}
	originRepr := obj.History[0].Derivation.FromRepresentation
	p := fold(root.Origin, originRepr, obj.History)
	// Top-level content must be the hop log's final bytes. Substituting
	// obj.Content after a legitimate promotion would otherwise execute
	// uncommitted text at the folded authority.
	if digest(obj.Content) != p.ContentSHA256 {
		p.Promotion.Continuity = ContinuityFailed
		p.Promotion.DigestFailure = true
	}
	return p, nil
}

func Authorize(obj InstructionObject, root EvaluationRoot) (execute bool, reason string) {
	// Reasons are the DenyEvidence literals. DenyEvidence formats this
	// return value; it never infers a second, competing check.
	// Derived authority, continuity, and digest state are recomputed from
	// the held root and hop log. Stored Provenance.Authority is never
	// the authorization input.
	p, err := derivedProvenance(obj, root)
	if err != nil {
		return false, "evaluation root mismatch"
	}
	if !root.InstructionBearing {
		return false, "not instruction-bearing content"
	}
	if p.Promotion.DigestFailure {
		return false, "digest linkage broken"
	}
	if p.Promotion.Continuity == ContinuityFailed {
		if p.Promotion.Attempted {
			return false, "authority-expanding instruction"
		}
		return false, "continuity FAILED"
	}
	rank, err := authorityRank(p.Authority)
	if err != nil {
		return false, "unknown authority"
	}
	userRank, _ := authorityRank(AuthorityUser)
	if rank < userRank {
		return false, "insufficient authority"
	}
	return true, "authorized"
}

// DenyEvidence renders the stable denial fragments for protected output.
// Transition endpoints derive from the object's own lineage and requested
// authority (contract §12 fixes their literal form for the fixture).
func DenyEvidence(obj InstructionObject, root EvaluationRoot) []string {
	p, err := derivedProvenance(obj, root)
	if err != nil {
		p = heldRootProvenance(root)
	}
	lineage := ""
	for i, a := range p.Lineage {
		if i > 0 {
			lineage += "->"
		}
		lineage += a
	}
	from := p.Authority
	if len(p.Lineage) > 0 {
		// Immediate pre-attempt authority: the entry this hop appended,
		// not the first hop. Multi-promotion denials name the actual
		// denied transition (DEVELOPER->SYSTEM, not USER->SYSTEM).
		from = p.Lineage[len(p.Lineage)-1]
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
	argClass := "INSTRUCTION"
	if !root.InstructionBearing {
		argClass = "DATA"
	}
	_, denyReason := Authorize(obj, root)
	if denyReason == "authorized" {
		denyReason = "insufficient authority"
	}
	return []string{
		"policy_decision=deny  policy_rule=instruction_authority_continuity",
		"reason=" + denyReason,
		fmt.Sprintf("argument class %s  effect class %s", argClass, root.EffectClass),
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
