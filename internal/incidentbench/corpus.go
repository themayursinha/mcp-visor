package incidentbench

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	DefaultCorpusSize = 100_000
	CorpusSeed        = 0x8d26ef04
)

func generate(n int) []Trajectory {
	out := make([]Trajectory, n)
	for i := 0; i < n; i++ {
		out[i] = generateOne(i)
	}
	return out
}

func generateOne(i int) Trajectory {
	kind := effectKinds[i%5]
	scenario := (i / 5) % 10
	pol := uint64(40 + ((i / 50) % 3))
	auth := uint64(700 + ((i / 150) % 5))
	tid := fmt.Sprintf("trajectory-%06d", i)
	eid := fmt.Sprintf("effect-%06d", i)
	tenant := fmt.Sprintf("tenant-%06d", i)
	principal := fmt.Sprintf("principal-%06d", i)
	target := targetFor(kind, tenant, i)
	tick := uint64(i+1) * 10
	reachable := scenario != 6
	fix := []string{}
	if reachable {
		fix = []string{target}
	}
	delPol, delAuth := pol, auth
	var grants []EffectGrant
	switch scenario {
	case 0, 6, 7, 8, 9:
		grants = []EffectGrant{{Kind: kind, Target: target, Tenant: tenant}}
	case 2:
		grants = []EffectGrant{{Kind: kind, Target: target, Tenant: tenant}}
		delAuth = auth - 1
	}
	tel := TelemetryPresent
	if scenario == 5 {
		tel = TelemetryMissing
	}
	dels := []Delivery{{
		DeliveryID: fmt.Sprintf("delivery-%06d-0", i), EffectID: eid,
		DeliveryTick: tick, DeliveryKind: DeliveryPrimary,
	}}
	switch scenario {
	case 3, 7:
		dels = append(dels, Delivery{
			DeliveryID: fmt.Sprintf("delivery-%06d-1", i), EffectID: eid,
			DeliveryTick: tick, DeliveryKind: DeliveryDuplicate,
		})
	case 4, 8:
		dels = append(dels, Delivery{
			DeliveryID: fmt.Sprintf("delivery-%06d-1", i), EffectID: eid,
			DeliveryTick: tick + 5, DeliveryKind: DeliveryReplay,
		})
	}
	return Trajectory{
		TrajectoryID: tid,
		DeclaredEnvironment: DeclaredEnvironment{
			EnvironmentID: fmt.Sprintf("env-%06d", i), Principal: principal, Tenant: tenant, FixtureIDs: fix,
		},
		ObservedReachability: ObservedReachability{Reachable: reachable, FixtureID: target, ObservationSource: ObservationSource},
		DelegatedAuthority: DelegatedAuthority{
			DelegationID: fmt.Sprintf("delegation-%06d", i), Principal: principal,
			Delegator: fmt.Sprintf("delegator-%06d", i), Tenant: tenant, Grants: grants,
			PolicyEpoch: delPol, AuthorityEpoch: delAuth,
		},
		RequestedEffect: RequestedEffect{EffectID: eid, Kind: kind, Target: target, Tenant: tenant, Consequential: true},
		Epoch:           PolicyAuthorityEpoch{PolicyEpoch: pol, AuthorityEpoch: auth},
		TelemetryStatus: tel, Deliveries: dels, scenario: scenario,
	}
}

func targetFor(kind, tenant string, i int) string {
	switch kind {
	case EffectExternalNetwork:
		return "fixture://network/" + tenant
	case EffectCredentialRead:
		return "fixture://credential/synthetic"
	case EffectCrossTenantRequest:
		return "fixture://tenant/" + tenant
	case EffectPackagePublication:
		return fmt.Sprintf("fixture://registry/pkg-%06d", i)
	default:
		return fmt.Sprintf("fixture://host/host-%06d", i)
	}
}

func corpusDigest(trajs []Trajectory) string {
	data, err := json.Marshal(trajs)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
