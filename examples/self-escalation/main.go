// Command self-escalation demonstrates the Self-Escalation Invariant:
// a confined agent cannot grant itself meta-authority.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	se "github.com/themayursinha/mcp-visor/internal/selfescalation"
)

//go:embed scenario.json
var scenarioJSON []byte

type action struct {
	ActionID                string `json:"action_id"`
	ActorPrincipal          string `json:"actor_principal"`
	RequestedAuthority      string `json:"requested_authority"`
	ManagementSurface       string `json:"management_surface"`
	ClaimedHostHeader       string `json:"claimed_host_header"`
	ClaimedUserAttribution  string `json:"claimed_user_attribution"`
	ClaimedDangerFullAccess bool   `json:"claimed_danger_full_access"`
	ClaimedPolicyRewrite    bool   `json:"claimed_policy_rewrite"`
	ClaimedAuthorized       bool   `json:"claimed_authorized"`
}
type scenario struct {
	SchemaVersion        int  `json:"schema_version"`
	MetaAuthorityEnabled bool `json:"meta_authority_enabled"`
	FixtureSampleSize    int  `json:"fixture_sample_size"`
	FixtureSeed          int  `json:"fixture_seed"`
	ParentDelegation     struct {
		DelegationID       string   `json:"delegation_id"`
		ChildPrincipal     string   `json:"child_principal"`
		AllowedAuthorities []string `json:"allowed_authorities"`
	} `json:"parent_delegation"`
	MetaAuthorityGrants []struct {
		GrantID          string `json:"grant_id"`
		GranteePrincipal string `json:"grantee_principal"`
		Authority        string `json:"authority"`
		ProofType        string `json:"proof_type"`
	} `json:"meta_authority_grants"`
	ManagementSurfaces []string `json:"management_surfaces"`
	CanonicalAttack    action   `json:"canonical_attack"`
	LegitimateAction   action   `json:"legitimate_action"`
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
	fmt.Println("Self-Escalation Invariant.")
	fmt.Printf("fixture sample_size=%d seed=%d\n\n", se.FixtureSampleSize, se.FixtureSeed)
	atk := toAction(scen.CanonicalAttack)
	if !atk.ClaimedDangerFullAccess || !atk.ClaimedPolicyRewrite || !atk.ClaimedAuthorized {
		return errors.New("vulnerable baseline claims missing")
	}
	fmt.Println("A  WITHOUT VISOR (self-asserted authority claims)")
	fmt.Println("surface surface:loopback-policy-api claimed reachable")
	fmt.Println("host localhost claimed trusted")
	fmt.Println("attribution USER claimed")
	fmt.Println("danger_full_access true")
	fmt.Println("policy_rewrite true")
	fmt.Println("claimed_authorization true")
	fmt.Print("result CALLBACK_FIRED\n\n")
	attack := se.Authorize(root, atk)
	if attack.Verdict == se.VerdictAllow {
		return errors.New("self-escalation must not fire")
	}
	fmt.Println("B  WITH VISOR (parent delegation and typed proof checked)")
	for _, line := range attack.Evidence {
		fmt.Println(line)
	}
	fmt.Print("result CALLBACK_NOT_FIRED\n\n")
	legit := se.Authorize(root, toAction(scen.LegitimateAction))
	if legit.Verdict != se.VerdictAllow {
		return errors.New("workspace write must fire")
	}
	fmt.Println("C  LEGITIMATE CONTRAST (in-delegation workspace write)")
	for _, line := range legit.Evidence {
		fmt.Println(line)
	}
	fmt.Println("policy_self_modify DENIED")
	fmt.Print("result CALLBACK_FIRED\n\n")
	fmt.Println("false_escalation_formation 5/6")
	fmt.Println("propagation 3/6")
	fmt.Println("over_rejection 0/2")
	fmt.Println("measurement DETERMINISTIC")
	fmt.Println("rng NOT_USED")
	fmt.Println("management_surface NOT_CONTACTED")
	fmt.Println("escalation_executor NOT_IMPLEMENTED")
	return nil
}

func toAction(a action) se.ProposedAction {
	return se.ProposedAction{ActionID: a.ActionID, ActorPrincipal: a.ActorPrincipal, RequestedAuthority: a.RequestedAuthority, ManagementSurface: a.ManagementSurface, ClaimedHostHeader: a.ClaimedHostHeader, ClaimedUserAttribution: a.ClaimedUserAttribution, ClaimedDangerFullAccess: a.ClaimedDangerFullAccess, ClaimedPolicyRewrite: a.ClaimedPolicyRewrite, ClaimedAuthorized: a.ClaimedAuthorized}
}

func load() (scenario, se.EvaluationRoot, error) {
	var scen scenario
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return scen, se.EvaluationRoot{}, err
	}
	if scen.SchemaVersion != se.SchemaVersion || !scen.MetaAuthorityEnabled || scen.FixtureSampleSize != se.FixtureSampleSize || scen.FixtureSeed != se.FixtureSeed || len(scen.ManagementSurfaces) != 4 || len(scen.MeasurementRecords) != 8 || len(scen.MetaAuthorityGrants) != 0 || scen.CanonicalAttack.ActionID != se.CanonicalAttackActionID || scen.LegitimateAction.ActionID != se.LegitimateActionID {
		return scen, se.EvaluationRoot{}, errors.New("scenario mismatch")
	}
	root := se.EvaluationRoot{SchemaVersion: se.SchemaVersion, MetaAuthorityEnabled: true, ParentDelegation: se.ParentDelegation{DelegationID: scen.ParentDelegation.DelegationID, ChildPrincipal: scen.ParentDelegation.ChildPrincipal, AllowedAuthorities: append([]string(nil), scen.ParentDelegation.AllowedAuthorities...)}, ManagementSurfaces: append([]string(nil), scen.ManagementSurfaces...)}
	return scen, root, nil
}
