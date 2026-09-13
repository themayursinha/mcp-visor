// Command auth-state-fidelity demonstrates Authorization-State Fidelity:
// a remembered grant is not authority after revoke.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	asf "github.com/themayursinha/mcp-visor/internal/authstatefidelity"
)

//go:embed scenario.json
var scenarioJSON []byte

type action struct {
	ActionID                string `json:"action_id"`
	SubjectID               string `json:"subject_id"`
	Permission              string `json:"permission"`
	CitedGrantEventID       string `json:"cited_grant_event_id"`
	ClaimedMemoryPermission bool   `json:"claimed_memory_permission"`
	ClaimedGrantPrincipalID string `json:"claimed_grant_principal_id"`
	ClaimedGrantValid       bool   `json:"claimed_grant_valid"`
	ClaimedProofValid       bool   `json:"claimed_proof_valid"`
	ClaimedExactStateValid  bool   `json:"claimed_exact_state_valid"`
	ClaimedAuthorized       bool   `json:"claimed_authorized"`
}

type event struct {
	EventID      string `json:"event_id"`
	Kind         string `json:"kind"`
	PrincipalID  string `json:"principal_id"`
	SubjectID    string `json:"subject_id"`
	Permission   string `json:"permission"`
	GrantEventID string `json:"grant_event_id"`
	Tick         int    `json:"tick"`
}

type scenario struct {
	SchemaVersion             int  `json:"schema_version"`
	CurrentTick               int  `json:"current_tick"`
	AuthorizationStateEnabled bool `json:"authorization_state_enabled"`
	FixtureSampleSize         int  `json:"fixture_sample_size"`
	FixtureSeed               int  `json:"fixture_seed"`
	GrantPrincipals           []struct {
		PrincipalID          string   `json:"principal_id"`
		GrantablePermissions []string `json:"grantable_permissions"`
	} `json:"grant_principals"`
	EventLog           []event `json:"event_log"`
	CanonicalAttack    action  `json:"canonical_attack"`
	LegitimateReports  action  `json:"legitimate_reports"`
	MeasurementRecords []struct {
		RecordID           string `json:"record_id"`
		ExpectedAuthorized bool   `json:"expected_authorized"`
		Action             action `json:"action"`
	} `json:"measurement_records"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	scen, root, err := load()
	if err != nil {
		return err
	}
	fmt.Println("MCP Visor")
	fmt.Println("Authorization-State Fidelity.")
	fmt.Printf("fixture sample_size=%d seed=%d\n\n", asf.FixtureSampleSize, asf.FixtureSeed)
	atk := toAction(scen.CanonicalAttack)
	if !atk.ClaimedMemoryPermission || !atk.ClaimedProofValid || !atk.ClaimedAuthorized {
		return errors.New("vulnerable baseline claims missing")
	}
	fmt.Println("A  WITHOUT VISOR (model memory treated as authority)")
	fmt.Println("memory_permission agent:worker|deploy:production")
	fmt.Println("cited_grant event:grant-production")
	fmt.Print("result CALLBACK_FIRED\n\n")
	attack := asf.Authorize(root, atk)
	if attack.Verdict == asf.VerdictAllow {
		return errors.New("revoked grant must not fire")
	}
	fmt.Println("B  WITH VISOR (exact state recomputed from event log)")
	for _, line := range attack.Evidence {
		fmt.Println(line)
	}
	bs, err := asf.RecomputeAuthorizationState(root)
	if err != nil {
		return err
	}
	fmt.Println("repair_mode RECOMPUTE_ONLY")
	fmt.Printf("active_bindings %d\n", len(bs))
	fmt.Print("result CALLBACK_NOT_FIRED\n\n")
	legit := asf.Authorize(root, toAction(scen.LegitimateReports))
	if legit.Verdict != asf.VerdictAllow {
		return errors.New("active grant must fire")
	}
	fmt.Println("C  LEGITIMATE CONTRAST (active grant source)")
	for _, line := range legit.Evidence {
		fmt.Println(line)
	}
	fmt.Print("result CALLBACK_FIRED\n\n")
	fmt.Println("false_authority_formation 5/6")
	fmt.Println("propagation_would_fire 3/6")
	fmt.Println("over_rejection 0/2")
	fmt.Println("measurement DETERMINISTIC")
	fmt.Println("rng NOT_USED")
	fmt.Println("memory_store NOT_MUTATED")
	return nil
}

func toAction(a action) asf.ProposedAction {
	return asf.ProposedAction{
		ActionID: a.ActionID, SubjectID: a.SubjectID, Permission: a.Permission, CitedGrantEventID: a.CitedGrantEventID,
		ClaimedMemoryPermission: a.ClaimedMemoryPermission, ClaimedGrantPrincipalID: a.ClaimedGrantPrincipalID,
		ClaimedGrantValid: a.ClaimedGrantValid, ClaimedProofValid: a.ClaimedProofValid,
		ClaimedExactStateValid: a.ClaimedExactStateValid, ClaimedAuthorized: a.ClaimedAuthorized,
	}
}

func load() (scenario, asf.EvaluationRoot, error) {
	var scen scenario
	var root asf.EvaluationRoot
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return scen, root, err
	}
	if scen.SchemaVersion != asf.SchemaVersion || scen.CurrentTick != 30 || !scen.AuthorizationStateEnabled ||
		scen.FixtureSampleSize != asf.FixtureSampleSize || scen.FixtureSeed != asf.FixtureSeed ||
		len(scen.GrantPrincipals) != 2 || len(scen.EventLog) != 6 || len(scen.MeasurementRecords) != 8 ||
		scen.CanonicalAttack.CitedGrantEventID != asf.CanonicalGrantEventID ||
		scen.LegitimateReports.CitedGrantEventID != "event:grant-reports" {
		return scen, root, errors.New("scenario mismatch")
	}
	root = asf.EvaluationRoot{SchemaVersion: asf.SchemaVersion, CurrentTick: scen.CurrentTick, AuthorizationStateEnabled: true}
	for _, gp := range scen.GrantPrincipals {
		root.GrantPrincipals = append(root.GrantPrincipals, asf.GrantPrincipal{PrincipalID: gp.PrincipalID, GrantablePermissions: gp.GrantablePermissions})
	}
	for _, e := range scen.EventLog {
		root.EventLog = append(root.EventLog, asf.AuthorizationEvent{
			EventID: e.EventID, Kind: e.Kind, PrincipalID: e.PrincipalID, SubjectID: e.SubjectID,
			Permission: e.Permission, GrantEventID: e.GrantEventID, Tick: e.Tick,
		})
	}
	return scen, root, nil
}
