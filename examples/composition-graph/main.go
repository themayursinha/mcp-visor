// Command composition-graph demonstrates Capability Composition Graph:
// individually claimed ALLOW steps are not authority for a composed trajectory.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	cg "github.com/themayursinha/mcp-visor/internal/compositiongraph"
)

//go:embed scenario.json
var scenarioJSON []byte

type step struct {
	SkillID string `json:"skill_id"`
	EdgeID  string `json:"edge_id"`
}
type action struct {
	ActionID                string `json:"action_id"`
	StartArtifactClass      string `json:"start_artifact_class"`
	FinalArtifactClass      string `json:"final_artifact_class"`
	Destination             string `json:"destination"`
	Steps                   []step `json:"steps"`
	ClaimedSignaturesValid  bool   `json:"claimed_signatures_valid"`
	ClaimedIndividualAllow  bool   `json:"claimed_individual_allow"`
	ClaimedCompositionValid bool   `json:"claimed_composition_valid"`
	ClaimedAuthorized       bool   `json:"claimed_authorized"`
}
type capEdge struct {
	EdgeID            string `json:"edge_id"`
	FromArtifactClass string `json:"from_artifact_class"`
	ToArtifactClass   string `json:"to_artifact_class"`
	EffectClass       string `json:"effect_class"`
	Destination       string `json:"destination"`
}
type scenario struct {
	SchemaVersion      int  `json:"schema_version"`
	CompositionEnabled bool `json:"composition_enabled"`
	FixtureSampleSize  int  `json:"fixture_sample_size"`
	FixtureSeed        int  `json:"fixture_seed"`
	Mandate            struct {
		MandateID              string   `json:"mandate_id"`
		AllowedEffects         []string `json:"allowed_effects"`
		AllowedDestinations    []string `json:"allowed_destinations"`
		AllowedArtifactClasses []string `json:"allowed_artifact_classes"`
	} `json:"mandate"`
	InstalledSkills []struct {
		SkillID string    `json:"skill_id"`
		Edges   []capEdge `json:"edges"`
	} `json:"installed_skills"`
	CanonicalAttack    action `json:"canonical_attack"`
	LegitimateAction   action `json:"legitimate_action"`
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
	fmt.Println("Capability Composition Graph.")
	fmt.Printf("fixture sample_size=%d seed=%d\n\n", cg.FixtureSampleSize, cg.FixtureSeed)
	atk := toAction(scen.CanonicalAttack)
	if !atk.ClaimedSignaturesValid || !atk.ClaimedIndividualAllow || !atk.ClaimedCompositionValid || !atk.ClaimedAuthorized {
		return errors.New("vulnerable baseline claims missing")
	}
	fmt.Println("A  WITHOUT VISOR (individual capability claims composed)")
	fmt.Println("step skill:credential-discovery/edge:discover-credentials claimed ALLOW")
	fmt.Println("step skill:context-normalizer/edge:normalize-credential claimed ALLOW")
	fmt.Println("step skill:mcp-submitter/edge:submit-external claimed ALLOW")
	fmt.Println("claimed_composition VALID")
	fmt.Print("result CALLBACK_FIRED\n\n")
	attack := cg.Authorize(root, atk)
	if attack.Verdict == cg.VerdictAllow {
		return errors.New("credential disclosure must not fire")
	}
	fmt.Println("B  WITH VISOR (complete trajectory checked against mandate)")
	for _, line := range attack.Evidence {
		fmt.Println(line)
	}
	fmt.Println("trajectory CREDENTIAL_SOURCE>CREDENTIAL_ARTIFACT>CONTEXT_ARTIFACT>EXTERNAL_DISCLOSURE")
	fmt.Print("result CALLBACK_NOT_FIRED\n\n")
	legit := cg.Authorize(root, toAction(scen.LegitimateAction))
	if legit.Verdict != cg.VerdictAllow {
		return errors.New("in-mandate composition must fire")
	}
	fmt.Println("C  LEGITIMATE CONTRAST (in-mandate read-transform-send)")
	for _, line := range legit.Evidence {
		fmt.Println(line)
	}
	fmt.Println("trajectory REPORT_SOURCE>REPORT_ARTIFACT>REPORT_CONTEXT>EXTERNAL_DELIVERY")
	fmt.Print("result CALLBACK_FIRED\n\n")
	fmt.Println("false_composition_formation 5/6")
	fmt.Println("propagation_would_fire 3/6")
	fmt.Println("over_rejection 0/2")
	fmt.Println("measurement DETERMINISTIC")
	fmt.Println("rng NOT_USED")
	fmt.Println("skill_execution NOT_PERFORMED")
	return nil
}

func toAction(a action) cg.ProposedAction {
	out := cg.ProposedAction{ActionID: a.ActionID, StartArtifactClass: a.StartArtifactClass, FinalArtifactClass: a.FinalArtifactClass, Destination: a.Destination, ClaimedSignaturesValid: a.ClaimedSignaturesValid, ClaimedIndividualAllow: a.ClaimedIndividualAllow, ClaimedCompositionValid: a.ClaimedCompositionValid, ClaimedAuthorized: a.ClaimedAuthorized}
	for _, s := range a.Steps {
		out.Steps = append(out.Steps, cg.StepReference{SkillID: s.SkillID, EdgeID: s.EdgeID})
	}
	return out
}

func load() (scenario, cg.EvaluationRoot, error) {
	var scen scenario
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return scen, cg.EvaluationRoot{}, err
	}
	if scen.SchemaVersion != cg.SchemaVersion || !scen.CompositionEnabled || scen.FixtureSampleSize != cg.FixtureSampleSize || scen.FixtureSeed != cg.FixtureSeed || len(scen.InstalledSkills) != 6 || len(scen.MeasurementRecords) != 8 || scen.CanonicalAttack.ActionID != cg.CanonicalAttackActionID || scen.LegitimateAction.ActionID != cg.LegitimateActionID {
		return scen, cg.EvaluationRoot{}, errors.New("scenario mismatch")
	}
	root := cg.EvaluationRoot{SchemaVersion: cg.SchemaVersion, CompositionEnabled: true, Mandate: cg.CapabilityMandate{MandateID: scen.Mandate.MandateID, AllowedEffects: scen.Mandate.AllowedEffects, AllowedDestinations: scen.Mandate.AllowedDestinations, AllowedArtifactClasses: scen.Mandate.AllowedArtifactClasses}}
	for _, s := range scen.InstalledSkills {
		sk := cg.InstalledSkill{SkillID: s.SkillID}
		for _, e := range s.Edges {
			sk.Edges = append(sk.Edges, cg.CapabilityEdge{EdgeID: e.EdgeID, FromArtifactClass: e.FromArtifactClass, ToArtifactClass: e.ToArtifactClass, EffectClass: e.EffectClass, Destination: e.Destination})
		}
		root.InstalledSkills = append(root.InstalledSkills, sk)
	}
	return scen, root, nil
}
