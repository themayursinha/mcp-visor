package incidentbench

import (
	"fmt"
	"slices"

	"github.com/themayursinha/mcp-visor/internal/incidentbundle"
)

const (
	SchemaVersion      = 1
	Coverage           = "synthetic_mcp_action_boundary"
	BoundarySource     = "synthetic-action-boundary"
	ObservationSource  = "synthetic-fixture-table"
	CredentialSentinel = "synthetic-placeholder"
	RedactionNote      = "synthetic fixture; no raw credential material"
)

const (
	EffectExternalNetwork    = "external_network"
	EffectCredentialRead     = "credential_read"
	EffectCrossTenantRequest = "cross_tenant_request"
	EffectPackagePublication = "package_publication"
	EffectLateralMovement    = "lateral_movement"
	DecisionAllow            = "allow"
	DecisionDenyOutOfAuth    = "deny_out_of_authority"
	DecisionDenyUnreachable  = "deny_unreachable"
	ObservedCommitted        = "committed"
	ObservedBlocked          = "blocked"
	TelemetryPresent         = "present"
	TelemetryMissing         = "missing"
	DeliveryPrimary          = "primary"
	DeliveryDuplicate        = "duplicate"
	DeliveryReplay           = "replay"
)

var effectKinds = [...]string{
	EffectExternalNetwork, EffectCredentialRead, EffectCrossTenantRequest,
	EffectPackagePublication, EffectLateralMovement,
}

type PolicyAuthorityEpoch struct {
	PolicyEpoch    uint64 `json:"policy_epoch"`
	AuthorityEpoch uint64 `json:"authority_epoch"`
}

type EffectGrant struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Tenant string `json:"tenant"`
}

type DeclaredEnvironment struct {
	EnvironmentID string   `json:"environment_id"`
	Principal     string   `json:"principal"`
	Tenant        string   `json:"tenant"`
	FixtureIDs    []string `json:"fixture_ids"`
}

type ObservedReachability struct {
	Reachable         bool   `json:"reachable"`
	FixtureID         string `json:"fixture_id"`
	ObservationSource string `json:"observation_source"`
}

type DelegatedAuthority struct {
	DelegationID   string        `json:"delegation_id"`
	Principal      string        `json:"principal"`
	Delegator      string        `json:"delegator"`
	Tenant         string        `json:"tenant"`
	Grants         []EffectGrant `json:"grants"`
	PolicyEpoch    uint64        `json:"policy_epoch"`
	AuthorityEpoch uint64        `json:"authority_epoch"`
}

type RequestedEffect struct {
	EffectID      string `json:"effect_id"`
	Kind          string `json:"kind"`
	Target        string `json:"target"`
	Tenant        string `json:"tenant"`
	Consequential bool   `json:"consequential"`
}

type ObservedEffect struct {
	Status         string `json:"status"`
	Kind           string `json:"kind"`
	Target         string `json:"target"`
	Tenant         string `json:"tenant"`
	BoundarySource string `json:"boundary_source"`
	BoundaryTick   uint64 `json:"boundary_tick"`
}

type Delivery struct {
	DeliveryID   string `json:"delivery_id"`
	EffectID     string `json:"effect_id"`
	DeliveryTick uint64 `json:"delivery_tick"`
	DeliveryKind string `json:"delivery_kind"`
}

type Trajectory struct {
	TrajectoryID         string               `json:"trajectory_id"`
	DeclaredEnvironment  DeclaredEnvironment  `json:"declared_environment"`
	ObservedReachability ObservedReachability `json:"observed_reachability"`
	DelegatedAuthority   DelegatedAuthority   `json:"delegated_authority"`
	RequestedEffect      RequestedEffect      `json:"requested_effect"`
	Epoch                PolicyAuthorityEpoch `json:"policy_authority_epoch"`
	TelemetryStatus      string               `json:"telemetry_status"`
	Deliveries           []Delivery           `json:"delivery_schedule"`
	scenario             int                  `json:"-"`
}

type IncidentRecord struct {
	SchemaVersion        int                    `json:"schema_version"`
	IncidentID           string                 `json:"incident_id"`
	DedupKey             string                 `json:"dedup_key"`
	TrajectoryID         string                 `json:"trajectory_id"`
	DeclaredEnvironment  DeclaredEnvironment    `json:"declared_environment"`
	ObservedReachability ObservedReachability   `json:"observed_reachability"`
	DelegatedAuthority   DelegatedAuthority     `json:"delegated_authority"`
	RequestedEffect      RequestedEffect        `json:"requested_effect"`
	ObservedEffect       ObservedEffect         `json:"observed_effect"`
	PolicyAuthorityEpoch PolicyAuthorityEpoch   `json:"policy_authority_epoch"`
	Decision             string                 `json:"decision"`
	Reason               string                 `json:"reason"`
	TelemetryStatus      string                 `json:"telemetry_status"`
	BoundaryTick         uint64                 `json:"boundary_tick"`
	PersistedTick        uint64                 `json:"persisted_tick"`
	Bundle               *incidentbundle.Bundle `json:"bundle"`
}

func cloneEnv(e DeclaredEnvironment) DeclaredEnvironment {
	e.FixtureIDs = slices.Clone(e.FixtureIDs)
	return e
}

func cloneDeleg(d DelegatedAuthority) DelegatedAuthority {
	d.Grants = slices.Clone(d.Grants)
	return d
}

func cloneRecord(r IncidentRecord) IncidentRecord {
	r.DeclaredEnvironment = cloneEnv(r.DeclaredEnvironment)
	r.DelegatedAuthority = cloneDeleg(r.DelegatedAuthority)
	r.Bundle = cloneBundle(r.Bundle)
	return r
}

func cloneBundle(b *incidentbundle.Bundle) *incidentbundle.Bundle {
	if b == nil {
		return nil
	}
	out := *b
	if b.Events != nil {
		out.Events = append([]incidentbundle.Event(nil), b.Events...)
		for i := range out.Events {
			if out.Events[i].Payload == nil {
				continue
			}
			p := make(map[string]any, len(out.Events[i].Payload))
			for k, v := range out.Events[i].Payload {
				p[k] = v
			}
			out.Events[i].Payload = p
		}
	}
	return &out
}

func validEffect(k string) bool {
	for _, x := range effectKinds {
		if x == k {
			return true
		}
	}
	return false
}

func validateDecision(s string) error {
	switch s {
	case DecisionAllow, DecisionDenyOutOfAuth, DecisionDenyUnreachable:
		return nil
	}
	return fmt.Errorf("unknown decision %q", s)
}

func validateObserved(s string) error {
	switch s {
	case ObservedCommitted, ObservedBlocked:
		return nil
	}
	return fmt.Errorf("unknown observed status %q", s)
}

func validateDelivery(d Delivery, effectID string) error {
	switch d.DeliveryKind {
	case DeliveryPrimary, DeliveryDuplicate, DeliveryReplay:
	default:
		return fmt.Errorf("unknown delivery kind %q", d.DeliveryKind)
	}
	if d.DeliveryID == "" || d.EffectID != effectID {
		return fmt.Errorf("invalid delivery")
	}
	return nil
}

func validateTrajectory(tr Trajectory) error {
	req := tr.RequestedEffect
	if tr.TrajectoryID == "" || req.EffectID == "" || req.Target == "" || req.Tenant == "" {
		return fmt.Errorf("missing trajectory fields")
	}
	if !validEffect(req.Kind) {
		return fmt.Errorf("unknown effect %q", req.Kind)
	}
	if !req.Consequential {
		return fmt.Errorf("non-consequential effect is invalid")
	}
	switch tr.TelemetryStatus {
	case TelemetryPresent, TelemetryMissing:
	default:
		return fmt.Errorf("unknown telemetry %q", tr.TelemetryStatus)
	}
	if len(tr.Deliveries) == 0 {
		return fmt.Errorf("no deliveries")
	}
	for _, d := range tr.Deliveries {
		if err := validateDelivery(d, req.EffectID); err != nil {
			return err
		}
	}
	for _, g := range tr.DelegatedAuthority.Grants {
		if !validEffect(g.Kind) {
			return fmt.Errorf("unknown grant kind %q", g.Kind)
		}
	}
	return nil
}

func hasFixture(ids []string, id string) bool {
	return slices.Contains(ids, id)
}
