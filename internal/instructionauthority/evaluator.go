package instructionauthority

import (
	"fmt"
	"strings"
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

const reasonHistoryExceedsBound = "history exceeds bound"

// ApplyTransform returns the object after one transformation. It appends
// one hop record and recomputes Provenance from scratch via fold: no
// derived field is ever mutated piecemeal, so authority, lineage,
// promotion outcomes, digests, and representations cannot drift apart.
// A History already at MaxHistoryHops is poisoned in place: no further
// hop is appended, and continuity fails closed.
func ApplyTransform(obj InstructionObject, t Transform, endorse *Endorsement, registry map[string]TrustedPrincipal) InstructionObject {
	if len(obj.History) >= MaxHistoryHops {
		poisoned := obj
		poisoned.InstructionEligible = false
		poisoned.Provenance.Promotion.Continuity = ContinuityFailed
		poisoned.Provenance.Promotion.DigestFailure = true
		return poisoned
	}
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
	p, _ := foldTrace(origin, originRepr, hops)
	return p
}

func foldTrace(origin Origin, originRepr string, hops []Hop) (Provenance, []string) {
	if len(hops) > MaxHistoryHops {
		return boundExceededProvenance(origin, originRepr), nil
	}
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
	pre := make([]string, len(hops))
	runningDigest := ""
	runningHop := ""
	if len(hops) > 0 {
		runningDigest = hops[0].ParentDigest
		runningHop = hops[0].ParentHopDigest
	}
	for i, hop := range hops {
		pre[i] = prov.Authority
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
	return prov, pre
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
	if len(obj.History) > MaxHistoryHops {
		return fmt.Errorf("history exceeds %d hops", MaxHistoryHops)
	}
	// History-free origin objects verify against genesis state directly.
	// Content is bound to the held root digest, not to whatever bytes
	// currently sit on the object.
	if len(obj.History) == 0 {
		if root.ContentSHA256 == "" || digest(obj.Content) != root.ContentSHA256 {
			return fmt.Errorf("content does not match evaluation root")
		}
		want := Provenance{
			Origin:                root.Origin,
			DerivedBy:             []Derivation{},
			CurrentRepresentation: obj.Provenance.CurrentRepresentation,
			VisibleRole:           RoleNone,
			Authority:             ceilingForTrust(root.Origin.TrustClass),
			Lineage:               []string{},
			ContentSHA256:         root.ContentSHA256,
			Promotion:             Promotion{Continuity: ContinuityPass},
		}
		if !provenanceEqual(want, obj.Provenance) {
			return fmt.Errorf("origin provenance mismatch")
		}
		return nil
	}
	if contentChainBroken(root, obj.Content, obj.History) {
		return fmt.Errorf("content chain does not match evaluation root")
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
	fresh, preAuthority := foldTrace(root.Origin, originRepr, obj.History)
	if fresh.Promotion.DigestFailure {
		return fmt.Errorf("digest chain broken")
	}
	if !provenanceEqual(fresh, obj.Provenance) {
		return fmt.Errorf("provenance does not match history")
	}
	// Registry cross-check: revalidate every recorded endorsement against
	// the live registry using the pre-hop authority from the single fold.
	for i, hop := range obj.History {
		if hop.Endorsement == nil {
			if hop.EndorsementValid {
				return fmt.Errorf("hop %d claims a valid endorsement without an endorsement", i)
			}
			continue
		}
		live := validEndorsement(*hop.Endorsement, hop.ParentDigest, preAuthority[i], hop.ContentDigest, hop.Derivation.Transformer, hop.Derivation.ToRepresentation, hop.RequestedAuthority, registry)
		if live != hop.EndorsementValid {
			return fmt.Errorf("hop %d endorsement verdict disagrees with registry", i)
		}
	}
	// Content must agree with the folded digest chain.
	want := ""
	if len(obj.History) > 0 {
		want = obj.History[len(obj.History)-1].ContentDigest
	} else {
		want = root.ContentSHA256
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
// contentChainBroken is the full evaluation transcript:
// root.ContentSHA256 -> hop[0] -> ... -> hop[n] -> obj.Content.
// Zero hops bind content to the held genesis digest. Non-zero hops
// must start at that digest (first ParentDigest and ParentHopDigest)
// and end at obj.Content. Hop-to-hop linkage is fold's job.
func contentChainBroken(root EvaluationRoot, content string, hops []Hop) bool {
	if root.ContentSHA256 == "" {
		return true
	}
	if len(hops) == 0 {
		return digest(content) != root.ContentSHA256
	}
	if hops[0].ParentDigest != root.ContentSHA256 || hops[0].ParentHopDigest != root.ContentSHA256 {
		return true
	}
	return digest(content) != hops[len(hops)-1].ContentDigest
}

func boundExceededProvenance(origin Origin, originRepr string) Provenance {
	return Provenance{
		Origin:                origin,
		DerivedBy:             []Derivation{},
		CurrentRepresentation: originRepr,
		VisibleRole:           RoleNone,
		Authority:             ceilingForTrust(origin.TrustClass),
		Lineage:               []string{},
		ContentSHA256:         "",
		Promotion:             Promotion{Continuity: ContinuityFailed, DigestFailure: true},
	}
}

func derivedProvenance(obj InstructionObject, root EvaluationRoot) Provenance {
	// Object copies of origin, bearing, effect class, and provenance are
	// not inputs. The content chain is bound to the held genesis digest.
	if len(obj.History) > MaxHistoryHops {
		return boundExceededProvenance(root.Origin, "")
	}
	if len(obj.History) == 0 {
		p := Provenance{
			Origin:        root.Origin,
			DerivedBy:     []Derivation{},
			VisibleRole:   RoleNone,
			Authority:     ceilingForTrust(root.Origin.TrustClass),
			Lineage:       []string{},
			ContentSHA256: root.ContentSHA256,
			Promotion:     Promotion{Continuity: ContinuityPass},
		}
		if contentChainBroken(root, obj.Content, obj.History) {
			p.Promotion.Continuity = ContinuityFailed
			p.Promotion.DigestFailure = true
		}
		return p
	}
	originRepr := obj.History[0].Derivation.FromRepresentation
	p := fold(root.Origin, originRepr, obj.History)
	if contentChainBroken(root, obj.Content, obj.History) {
		p.Promotion.Continuity = ContinuityFailed
		p.Promotion.DigestFailure = true
	}
	return p
}

func Authorize(obj InstructionObject, root EvaluationRoot) (execute bool, reason string) {
	// Reasons are the DenyEvidence literals. DenyEvidence formats this
	// return value; it never infers a second, competing check.
	if len(obj.History) > MaxHistoryHops {
		return false, reasonHistoryExceedsBound
	}
	return decide(derivedProvenance(obj, root), root)
}

func decide(p Provenance, root EvaluationRoot) (execute bool, reason string) {
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
	var p Provenance
	var denyReason string
	if len(obj.History) > MaxHistoryHops {
		p = boundExceededProvenance(root.Origin, "")
		denyReason = reasonHistoryExceedsBound
	} else {
		p = derivedProvenance(obj, root)
		_, denyReason = decide(p, root)
		if denyReason == "authorized" {
			denyReason = "insufficient authority"
		}
	}
	lineage := strings.Join(p.Lineage, "->")
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
