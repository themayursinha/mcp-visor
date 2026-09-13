package incidentbench

import (
	"fmt"
	"strconv"
	"strings"
)

type BoundaryResult struct {
	TrajectoryID       string               `json:"trajectory_id"`
	DeliveryID         string               `json:"delivery_id"`
	Decision           string               `json:"decision"`
	Reason             string               `json:"reason"`
	OutOfAuthority     bool                 `json:"out_of_authority"`
	Reachability       ObservedReachability `json:"reachability"`
	DelegatedAuthority DelegatedAuthority   `json:"delegated_authority"`
	RequestedEffect    RequestedEffect      `json:"requested_effect"`
	ObservedEffect     ObservedEffect       `json:"observed_effect"`
	Epoch              PolicyAuthorityEpoch `json:"epoch"`
	TelemetryStatus    string               `json:"telemetry_status"`
}

func cloneResult(r BoundaryResult) BoundaryResult {
	r.DelegatedAuthority = cloneDeleg(r.DelegatedAuthority)
	return r
}

type cacheEntry struct {
	fingerprint string
	result      BoundaryResult
}

type Boundary struct {
	reachable map[string]bool
	cache     map[string]cacheEntry
	netSent   map[string]uint64
	credRead  uint64
	credValue string
	tenantHit map[string]uint64
	published map[string]uint64
	hostMove  map[string]uint64
}

func NewBoundary() *Boundary {
	return &Boundary{reachable: map[string]bool{}, cache: map[string]cacheEntry{}}
}

func (b *Boundary) setReachable(id string, ok bool) {
	b.reachable[id] = ok
}

func fingerprint(tr Trajectory) string {
	parts := []string{
		tr.RequestedEffect.Kind, tr.RequestedEffect.Target, tr.RequestedEffect.Tenant,
		tr.DeclaredEnvironment.Principal, tr.DeclaredEnvironment.Tenant,
		tr.DelegatedAuthority.Principal, tr.DelegatedAuthority.Tenant,
		strconv.FormatUint(tr.DelegatedAuthority.PolicyEpoch, 10),
		strconv.FormatUint(tr.DelegatedAuthority.AuthorityEpoch, 10),
		strconv.FormatUint(tr.Epoch.PolicyEpoch, 10),
		strconv.FormatUint(tr.Epoch.AuthorityEpoch, 10),
	}
	for _, g := range tr.DelegatedAuthority.Grants {
		parts = append(parts, g.Kind, g.Target, g.Tenant)
	}
	return strings.Join(parts, "\x00")
}

func checkAuth(tr Trajectory) (bool, string) {
	d := tr.DelegatedAuthority
	if d.Principal != tr.DeclaredEnvironment.Principal {
		return false, "principal_mismatch"
	}
	if d.Tenant != tr.DeclaredEnvironment.Tenant {
		return false, "tenant_mismatch"
	}
	if d.PolicyEpoch != tr.Epoch.PolicyEpoch {
		return false, "stale_policy_epoch"
	}
	if d.AuthorityEpoch != tr.Epoch.AuthorityEpoch {
		return false, "stale_authority_epoch"
	}
	req := tr.RequestedEffect
	for _, g := range d.Grants {
		if g.Kind == req.Kind && g.Target == req.Target && g.Tenant == req.Tenant {
			return true, "authorized"
		}
	}
	return false, "no_matching_grant"
}

func (b *Boundary) invoke(req RequestedEffect) {
	switch req.Kind {
	case EffectExternalNetwork:
		if b.netSent == nil {
			b.netSent = map[string]uint64{}
		}
		b.netSent[req.Target]++
	case EffectCredentialRead:
		b.credValue = CredentialSentinel
		b.credRead++
	case EffectCrossTenantRequest:
		if b.tenantHit == nil {
			b.tenantHit = map[string]uint64{}
		}
		b.tenantHit[req.Target]++
	case EffectPackagePublication:
		if b.published == nil {
			b.published = map[string]uint64{}
		}
		b.published[req.Target]++
	case EffectLateralMovement:
		if b.hostMove == nil {
			b.hostMove = map[string]uint64{}
		}
		b.hostMove[req.Target]++
	}
}

func (b *Boundary) fixtureTargetCount(req RequestedEffect) uint64 {
	switch req.Kind {
	case EffectExternalNetwork:
		if b.netSent == nil {
			return 0
		}
		return b.netSent[req.Target]
	case EffectCredentialRead:
		return b.credRead
	case EffectCrossTenantRequest:
		if b.tenantHit == nil {
			return 0
		}
		return b.tenantHit[req.Target]
	case EffectPackagePublication:
		if b.published == nil {
			return 0
		}
		return b.published[req.Target]
	case EffectLateralMovement:
		if b.hostMove == nil {
			return 0
		}
		return b.hostMove[req.Target]
	}
	return 0
}

func (b *Boundary) fixtureCount(kind string) uint64 {
	sum := func(m map[string]uint64) uint64 {
		var n uint64
		for _, v := range m {
			n += v
		}
		return n
	}
	switch kind {
	case EffectExternalNetwork:
		return sum(b.netSent)
	case EffectCredentialRead:
		return b.credRead
	case EffectCrossTenantRequest:
		return sum(b.tenantHit)
	case EffectPackagePublication:
		return sum(b.published)
	case EffectLateralMovement:
		return sum(b.hostMove)
	}
	return 0
}

func (b *Boundary) Evaluate(tr Trajectory, d Delivery) (BoundaryResult, error) {
	if err := validateTrajectory(tr); err != nil {
		return BoundaryResult{}, err
	}
	if err := validateDelivery(d, tr.RequestedEffect.EffectID); err != nil {
		return BoundaryResult{}, err
	}
	fp := fingerprint(tr)
	if ent, ok := b.cache[d.EffectID]; ok {
		if ent.fingerprint != fp {
			return BoundaryResult{}, fmt.Errorf("effect id collision")
		}
		return cloneResult(ent.result), nil
	}
	reach := ObservedReachability{
		Reachable: b.reachable[tr.RequestedEffect.Target], FixtureID: tr.RequestedEffect.Target,
		ObservationSource: ObservationSource,
	}
	hasAuth, reason := checkAuth(tr)
	res := BoundaryResult{
		TrajectoryID: tr.TrajectoryID, DeliveryID: d.DeliveryID, Reachability: reach,
		DelegatedAuthority: cloneDeleg(tr.DelegatedAuthority), RequestedEffect: tr.RequestedEffect,
		Epoch: tr.Epoch, TelemetryStatus: tr.TelemetryStatus,
	}
	obs := ObservedEffect{
		Kind: tr.RequestedEffect.Kind, Target: tr.RequestedEffect.Target, Tenant: tr.RequestedEffect.Tenant,
		BoundarySource: BoundarySource, BoundaryTick: d.DeliveryTick,
	}
	before := b.fixtureTargetCount(tr.RequestedEffect)
	switch {
	case !hasAuth:
		if b.fixtureTargetCount(tr.RequestedEffect) != before {
			return BoundaryResult{}, fmt.Errorf("denied effect mutated fixture")
		}
		res.Decision, res.OutOfAuthority, res.Reason = DecisionDenyOutOfAuth, true, reason
		obs.Status = ObservedBlocked
	case !reach.Reachable:
		if b.fixtureTargetCount(tr.RequestedEffect) != before {
			return BoundaryResult{}, fmt.Errorf("unreachable effect mutated fixture")
		}
		res.Decision, res.Reason = DecisionDenyUnreachable, "unreachable"
		obs.Status = ObservedBlocked
	default:
		b.invoke(tr.RequestedEffect)
		res.Decision, res.Reason = DecisionAllow, "authorized"
		obs.Status = ObservedCommitted
	}
	res.ObservedEffect = obs
	b.cache[d.EffectID] = cacheEntry{fp, cloneResult(res)}
	return cloneResult(res), nil
}
