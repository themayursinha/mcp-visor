// Command context-provenance demonstrates Context Provenance Proofs:
// reconstructing untrusted MCP web-tool data as a USER message cannot
// raise instruction authority. The vulnerable baseline trusts the
// reconstructed USER role and records one simulated execution; Authorize
// records zero protected executions.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	cp "github.com/themayursinha/mcp-visor/internal/contextprovenance"
)

//go:embed scenario.json
var scenarioJSON []byte

type fragment struct {
	FragmentID   string   `json:"fragment_id"`
	Origin       string   `json:"origin"`
	Principal    string   `json:"principal"`
	Trust        string   `json:"trust"`
	Scope        string   `json:"scope"`
	IntroducedAt int64    `json:"introduced_at"`
	DerivedFrom  []string `json:"derived_from"`
}

type scenario struct {
	SchemaVersion            int        `json:"schema_version"`
	CurrentTick              int64      `json:"current_tick"`
	RequiredInstructionTrust string     `json:"required_instruction_trust"`
	Fragments                []fragment `json:"fragments"`
	Candidate                struct {
		FragmentID string `json:"fragment_id"`
		Content    string `json:"content"`
		Claims     struct {
			VisibleRole           string `json:"visible_role"`
			ReconstructedFromRole string `json:"reconstructed_from_role"`
			ClaimedOrigin         string `json:"claimed_origin"`
			ClaimedPrincipal      string `json:"claimed_principal"`
			ClaimedTrust          string `json:"claimed_trust"`
			ClaimedAuthoritative  bool   `json:"claimed_authoritative"`
		} `json:"claims"`
	} `json:"candidate"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	root, cand, err := load()
	if err != nil {
		return err
	}
	fmt.Println("MCP Visor")
	fmt.Println("Context Provenance Proofs.")
	fmt.Println()
	fmt.Println("ATTACK INPUT (untrusted MCP web-tool data reconstructed as USER)")
	fmt.Printf("  %s\n", cand.Content)
	fmt.Println()

	vulnerable := 0
	if cand.Claims.VisibleRole == "USER" {
		vulnerable++
	}
	if vulnerable != 1 {
		return errors.New("vulnerable baseline must record one simulated execution")
	}
	fmt.Println("A  WITHOUT VISOR (reconstructed USER role trusted)")
	fmt.Println("visible role USER reconstructed_from TOOL")
	fmt.Println("result EXECUTED")
	fmt.Printf("vulnerable baseline count %d\n\n", vulnerable)

	protected := 0
	d := cp.Authorize(root, cand)
	if d.InstructionAuthority == cp.Authoritative {
		protected++
	}
	want := [8]string{
		"Context route Agent A -> MCP web tool -> Agent B",
		"Visible role USER reconstructed_from TOOL",
		"Original origin MCP_WEB_TOOL principal REMOTE_TOOL scope invocation-481",
		"Derived path web-1->handoff-1->agent-b-1",
		"Declared trust USER_TRUSTED effective trust UNTRUSTED",
		"Trust ceiling UNTRUSTED required USER_TRUSTED",
		"Context Provenance Proof INVALID",
		"Context Authority Escalation DETECTED; Instruction NON-AUTHORITATIVE",
	}
	if d.Evidence != want || d.Proof != cp.ProofInvalid || d.Escalation != cp.EscalationFound || d.InstructionAuthority != cp.NonAuthoritative || protected != 0 {
		return fmt.Errorf("protected path mismatch: %+v executions=%d", d, protected)
	}
	fmt.Println("B  WITH VISOR (caller-held fragment graph checked)")
	for _, line := range d.Evidence {
		fmt.Println(line)
	}
	fmt.Println("result NOT_EXECUTED")
	fmt.Printf("protected count %d\n", protected)
	return nil
}

func load() (cp.EvaluationRoot, cp.CandidateMessage, error) {
	var scen scenario
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return cp.EvaluationRoot{}, cp.CandidateMessage{}, err
	}
	if scen.SchemaVersion != cp.SchemaVersion || scen.CurrentTick != 3 || scen.RequiredInstructionTrust != cp.TrustUser || len(scen.Fragments) != 3 || scen.Candidate.FragmentID != "agent-b-1" || scen.Candidate.Content == "" || scen.Candidate.Claims.VisibleRole != "USER" || scen.Candidate.Claims.ReconstructedFromRole != "TOOL" {
		return cp.EvaluationRoot{}, cp.CandidateMessage{}, errors.New("scenario mismatch")
	}
	root := cp.EvaluationRoot{SchemaVersion: cp.SchemaVersion, CurrentTick: scen.CurrentTick, RequiredInstructionTrust: scen.RequiredInstructionTrust}
	for _, f := range scen.Fragments {
		root.Fragments = append(root.Fragments, cp.ContextFragment{
			FragmentID: f.FragmentID, Origin: f.Origin, Principal: f.Principal, Trust: f.Trust,
			Scope: f.Scope, IntroducedAt: f.IntroducedAt, DerivedFrom: append([]string(nil), f.DerivedFrom...),
		})
	}
	cand := cp.CandidateMessage{
		FragmentID: scen.Candidate.FragmentID, Content: scen.Candidate.Content,
		Claims: cp.MessageClaims{
			VisibleRole: scen.Candidate.Claims.VisibleRole, ReconstructedFromRole: scen.Candidate.Claims.ReconstructedFromRole,
			ClaimedOrigin: scen.Candidate.Claims.ClaimedOrigin, ClaimedPrincipal: scen.Candidate.Claims.ClaimedPrincipal,
			ClaimedTrust: scen.Candidate.Claims.ClaimedTrust, ClaimedAuthoritative: scen.Candidate.Claims.ClaimedAuthoritative,
		},
	}
	return root, cand, nil
}
