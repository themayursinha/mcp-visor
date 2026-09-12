// Command authority-continuity demonstrates Instruction Authority
// Continuity: a malicious MCP output laundered through summary, memory,
// persistent goal, and a second agent must never gain instruction
// authority without an explicit higher-authority endorsement. The
// vulnerable baseline trusts the visible USER slot and "executes" (a
// boolean callback, never a real deployment); the protected path denies
// with lineage evidence while preserving the content as an untrusted
// observation.
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/themayursinha/mcp-visor/internal/instructionauthority"
)

//go:embed scenario.json
var scenarioJSON []byte

type scenario struct {
	MaliciousMCPOutput string `json:"malicious_mcp_output"`
	AgentSummary       string `json:"agent_summary"`
	PersistentGoal     string `json:"persistent_goal"`
	SecondAgentMessage string `json:"second_agent_message"`
	OriginPrincipal    string `json:"origin_principal"`
	OriginTrustClass   string `json:"origin_trust_class"`
	SystemPolicy       string `json:"system_policy"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	scen, err := loadScenario()
	if err != nil {
		return err
	}
	fmt.Println("MCP Visor")
	fmt.Println("Instruction Authority Continuity.")
	fmt.Println()
	fmt.Println("SYSTEM POLICY")
	fmt.Printf("  %s\n", scen.SystemPolicy)
	fmt.Println()
	fmt.Println("ATTACK INPUT (untrusted MCP response)")
	fmt.Printf("  %s\n", scen.MaliciousMCPOutput)
	fmt.Println()

	if err := runBaseline(scen); err != nil {
		return err
	}
	if err := runProtected(scen); err != nil {
		return err
	}

	fmt.Println("Model proposed.")
	fmt.Println("Instruction contained.")
	fmt.Println("Proxy enforced.")
	return nil
}

// runBaseline simulates the vulnerable harness: it trusts the visible
// USER slot, so the laundered instruction executes.
func runBaseline(scen scenario) error {
	executed := false
	executor := func() { executed = true }
	// The harness mistakes presentation (USER slot) for authority.
	visibleRole := instructionauthority.RoleUser
	_ = visibleRole
	executor()
	if !executed {
		return errors.New("baseline must execute (vulnerable harness trusts the USER slot)")
	}
	fmt.Println("A  WITHOUT VISOR (scripted baseline)")
	fmt.Println("   transform  MCP output -> summary -> memory -> goal -> second agent")
	fmt.Println("   visible role USER mistaken for authority")
	fmt.Println("   result EXECUTED")
	fmt.Println()
	return nil
}

// runProtected evaluates the identical fixture through continuity proofs.
func runProtected(scen scenario) error {
	root := instructionauthority.EvaluationRoot{
		Origin:             instructionauthority.Origin{Principal: scen.OriginPrincipal, TrustClass: scen.OriginTrustClass},
		InstructionBearing: true,
		EffectClass:        "PROCESS",
	}
	origin := instructionauthority.NewOriginObject(
		scen.MaliciousMCPOutput,
		root.Origin,
		instructionauthority.ReprMCPOutput, "PROCESS", true,
	)
	obj := instructionauthority.ApplyTransform(origin, instructionauthority.Transform{
		Transformer: "agent_summarizer", To: instructionauthority.ReprAgentSummary, NewContent: scen.AgentSummary,
	}, nil, nil)
	// Memory boundary: the summary rests in the session store (serialized)
	// and is reloaded before goal formation. Provenance must survive the
	// round trip byte-identically, and continuity is evaluated on the
	// reloaded object — a lossy store or a reload that skips evaluation is
	// exactly the laundering vector.
	reloaded, err := persistReload(obj, root)
	if err != nil {
		return fmt.Errorf("memory round trip: %w", err)
	}
	obj = instructionauthority.ApplyTransform(reloaded, instructionauthority.Transform{
		Transformer: "memory_goal_persistor", To: instructionauthority.ReprPersistentGoal,
		Via: instructionauthority.ReprSessionMemory, NewContent: scen.PersistentGoal,
	}, nil, nil)
	obj = instructionauthority.ApplyTransform(obj, instructionauthority.Transform{
		Transformer: "goal_handoff", To: instructionauthority.ReprSecondAgentMessage,
		VisibleRole: instructionauthority.RoleUser, RequestedAuthority: instructionauthority.AuthorityUser,
		NewContent: scen.SecondAgentMessage,
	}, nil, nil)

	executed := false
	if execute, _ := instructionauthority.Authorize(obj, root); execute {
		executed = true
	}
	if executed {
		return errors.New("protected path must not execute the laundered instruction")
	}
	fmt.Println("B  WITH VISOR (scripted continuity check)")
	for _, line := range instructionauthority.DenyEvidence(obj, root) {
		fmt.Printf("   %s\n", line)
	}
	fmt.Println()
	return nil
}

func loadScenario() (scenario, error) {
	var scen scenario
	// Embedded at build time: the demo runs identically from any working
	// directory (go run, tests, installed binaries).
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return scen, fmt.Errorf("parse scenario: %w", err)
	}
	if scen.MaliciousMCPOutput == "" {
		return scen, errors.New("scenario is missing the attack input")
	}
	return scen, nil
}

// persistReload simulates the session-memory boundary: the object is
// serialized to the store and reloaded before further derivation. The
// round trip must preserve provenance byte-identically; callers evaluate
// continuity on the reloaded object, never trusting the store.
func persistReload(obj instructionauthority.InstructionObject, root instructionauthority.EvaluationRoot) (instructionauthority.InstructionObject, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return instructionauthority.InstructionObject{}, err
	}
	var reloaded instructionauthority.InstructionObject
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&reloaded); err != nil {
		return instructionauthority.InstructionObject{}, err
	}
	if reloaded.Provenance.ContentSHA256 != obj.Provenance.ContentSHA256 ||
		reloaded.Provenance.Origin != obj.Provenance.Origin ||
		reloaded.Provenance.Promotion.Continuity != obj.Provenance.Promotion.Continuity {
		return instructionauthority.InstructionObject{}, errors.New("memory store corrupted provenance")
	}
	if err := instructionauthority.VerifyProvenance(reloaded, root, nil); err != nil {
		return instructionauthority.InstructionObject{}, fmt.Errorf("memory store failed verification: %w", err)
	}
	return reloaded, nil
}
