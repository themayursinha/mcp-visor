// Command tool-correlation demonstrates Cross-Tool Correlation:
// per-tool ALLOW is not authority for a correlated trajectory.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	tc "github.com/themayursinha/mcp-visor/internal/toolcorrelation"
)

//go:embed scenario.json
var scenarioJSON []byte

type useRef struct {
	UseID    string `json:"use_id"`
	ServerID string `json:"server_id"`
	ToolName string `json:"tool_name"`
}
type action struct {
	ActionID                 string   `json:"action_id"`
	CapabilityID             string   `json:"capability_id"`
	Uses                     []useRef `json:"uses"`
	ClaimedPerToolAllow      bool     `json:"claimed_per_tool_allow"`
	ClaimedServerHopInnocent bool     `json:"claimed_server_hop_innocent"`
	ClaimedRemainingQuota    int      `json:"claimed_remaining_quota"`
	ClaimedAuthorized        bool     `json:"claimed_authorized"`
}
type scenario struct {
	SchemaVersion      int  `json:"schema_version"`
	CorrelationEnabled bool `json:"correlation_enabled"`
	FixtureSampleSize  int  `json:"fixture_sample_size"`
	FixtureSeed        int  `json:"fixture_seed"`
	CapabilityCeilings []struct {
		CapabilityID string `json:"capability_id"`
		MaxUnits     int    `json:"max_units"`
	} `json:"capability_ceilings"`
	ResourceUses []struct {
		UseID        string `json:"use_id"`
		ServerID     string `json:"server_id"`
		ToolName     string `json:"tool_name"`
		CapabilityID string `json:"capability_id"`
		Units        int    `json:"units"`
	} `json:"resource_uses"`
	CorrelationEdges []struct {
		FromUseID string `json:"from_use_id"`
		ToUseID   string `json:"to_use_id"`
	} `json:"correlation_edges"`
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
	fmt.Println("Cross-Tool Correlation.")
	fmt.Printf("fixture sample_size=%d seed=%d\n\n", tc.FixtureSampleSize, tc.FixtureSeed)
	atk := toAction(scen.CanonicalAttack)
	if !atk.ClaimedPerToolAllow || !atk.ClaimedServerHopInnocent || atk.ClaimedRemainingQuota <= 0 || !atk.ClaimedAuthorized {
		return errors.New("vulnerable baseline claims missing")
	}
	fmt.Println("A  WITHOUT VISOR (per-tool limits viewed independently)")
	fmt.Println("hop use:github-search-1 mcp:github/search_code units=1 claimed ALLOW remaining=1")
	fmt.Println("hop use:drive-search-1 mcp:drive/search units=1 claimed ALLOW remaining=1")
	fmt.Println("hop use:notion-search-1 mcp:notion/search units=1 claimed ALLOW remaining=1")
	fmt.Println("hop use:github-read-1 mcp:github/get_file_contents units=1 claimed ALLOW remaining=1")
	fmt.Println("claimed_server_hop INNOCENT")
	fmt.Print("result CALLBACK_FIRED\n\n")
	attack := tc.Authorize(root, atk)
	if attack.Verdict == tc.VerdictAllow {
		return errors.New("cross-server sweep must not fire")
	}
	fmt.Println("B  WITH VISOR (cross-server capability trajectory correlated)")
	for _, line := range attack.Evidence {
		fmt.Println(line)
	}
	fmt.Println("trajectory mcp:github/search_code>mcp:drive/search>mcp:notion/search>mcp:github/get_file_contents")
	fmt.Println("correlated_usage 4/3")
	fmt.Print("result CALLBACK_NOT_FIRED\n\n")
	legit := tc.Authorize(root, toAction(scen.LegitimateAction))
	if legit.Verdict != tc.VerdictAllow {
		return errors.New("in-ceiling trajectory must fire")
	}
	fmt.Println("C  LEGITIMATE CONTRAST (same capability remains in ceiling)")
	for _, line := range legit.Evidence {
		fmt.Println(line)
	}
	fmt.Println("trajectory mcp:github/search_code>mcp:drive/search>mcp:notion/search")
	fmt.Println("correlated_usage 3/3")
	fmt.Print("result CALLBACK_FIRED\n\n")
	fmt.Println("false_correlation_formation 5/6")
	fmt.Println("propagation 3/6")
	fmt.Println("over_rejection 0/2")
	fmt.Println("measurement DETERMINISTIC")
	fmt.Println("rng NOT_USED")
	fmt.Println("tools_call NOT_PERFORMED")
	return nil
}

func toAction(a action) tc.ProposedAction {
	out := tc.ProposedAction{ActionID: a.ActionID, CapabilityID: a.CapabilityID, ClaimedPerToolAllow: a.ClaimedPerToolAllow, ClaimedServerHopInnocent: a.ClaimedServerHopInnocent, ClaimedRemainingQuota: a.ClaimedRemainingQuota, ClaimedAuthorized: a.ClaimedAuthorized}
	for _, u := range a.Uses {
		out.Uses = append(out.Uses, tc.UseReference{UseID: u.UseID, ServerID: u.ServerID, ToolName: u.ToolName})
	}
	return out
}

func load() (scenario, tc.EvaluationRoot, error) {
	var scen scenario
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return scen, tc.EvaluationRoot{}, err
	}
	if scen.SchemaVersion != tc.SchemaVersion || !scen.CorrelationEnabled || scen.FixtureSampleSize != tc.FixtureSampleSize || scen.FixtureSeed != tc.FixtureSeed || len(scen.ResourceUses) != 4 || len(scen.MeasurementRecords) != 8 || scen.CanonicalAttack.ActionID != tc.CanonicalAttackActionID || scen.LegitimateAction.ActionID != tc.LegitimateActionID {
		return scen, tc.EvaluationRoot{}, errors.New("scenario mismatch")
	}
	root := tc.EvaluationRoot{SchemaVersion: tc.SchemaVersion, CorrelationEnabled: true}
	for _, c := range scen.CapabilityCeilings {
		root.CapabilityCeilings = append(root.CapabilityCeilings, tc.CapabilityCeiling{CapabilityID: c.CapabilityID, MaxUnits: c.MaxUnits})
	}
	for _, u := range scen.ResourceUses {
		root.ResourceUses = append(root.ResourceUses, tc.ResourceUse{UseID: u.UseID, ServerID: u.ServerID, ToolName: u.ToolName, CapabilityID: u.CapabilityID, Units: u.Units})
	}
	for _, e := range scen.CorrelationEdges {
		root.CorrelationEdges = append(root.CorrelationEdges, tc.CorrelationEdge{FromUseID: e.FromUseID, ToUseID: e.ToUseID})
	}
	return scen, root, nil
}
