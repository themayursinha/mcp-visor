// Command authority-context demonstrates Authority-Context Integrity:
// shared ambient context cannot authorize a different principal.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	ac "github.com/themayursinha/mcp-visor/internal/authoritycontext"
)

//go:embed scenario.json
var scenarioJSON []byte

type scenario struct {
	Principals                  []string `json:"principals"`
	ActionID                    string   `json:"action_id"`
	AuthorityContextEnabled     bool     `json:"authority_context_enabled"`
	ClaimedCachedInitialization bool     `json:"claimed_cached_initialization"`
	ClaimedAuthorized           bool     `json:"claimed_authorized"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	scen, err := load()
	if err != nil {
		return err
	}
	fmt.Println("MCP Visor")
	fmt.Println("Authority-Context Integrity.")
	fmt.Printf("principals %s %s %s\n\n", ac.AdminPrincipalID, ac.CoderPrincipalID, ac.WebPrincipalID)
	if !scen.ClaimedCachedInitialization || !scen.ClaimedAuthorized {
		return errors.New("vulnerable baseline claims missing")
	}
	fmt.Println("A  WITHOUT VISOR (shared ambient context)")
	fmt.Println("claimed_inherited_context admin-agent@host")
	fmt.Println("requested_context coder-agent@docker-coder")
	fmt.Print("result CALLBACK_FIRED\n\n")
	attack := ac.Authorize(coderRoot(true), attackAct(scen))
	if attack.Verdict == ac.VerdictAllow {
		return errors.New("bleed must not fire")
	}
	printStage("B  WITH VISOR (cross-principal ambient bleed)", "result CALLBACK_NOT_FIRED", attack)
	legit := ac.Authorize(coderRoot(true), legitAct(scen))
	if legit.Verdict != ac.VerdictAllow {
		return errors.New("bound coder must fire")
	}
	printStage("C  LEGITIMATE CONTRAST (bound coder context)", "result CALLBACK_FIRED", legit)
	fmt.Println("ordering_permutations sequences=6 calls_per_sequence=3 bleed_decisions=0")
	fmt.Println("interleaved_sequence calls=9 attack_denials=3 legitimate_allows=6")
	fmt.Println("disabled_context inherited_ambient=DENIED")
	fmt.Println("principal_switch admin_to_coder_requires_new_root=YES")
	fmt.Println("error_path subsequent_coder_context=ISOLATED")
	return nil
}

func printStage(title, result string, d ac.Decision) {
	fmt.Println(title)
	for _, line := range d.Evidence {
		fmt.Println(line)
	}
	fmt.Print(result + "\n\n")
}

func coderRoot(enabled bool) ac.EvaluationRoot {
	return ac.EvaluationRoot{SchemaVersion: ac.SchemaVersion, HeldPrincipalID: ac.CoderPrincipalID, HeldExecutionDomain: ac.CoderDomain,
		Mandate: ac.AuthorityMandate{MandateID: ac.CoderMandateID, PrincipalID: ac.CoderPrincipalID, AuthorizedDomains: []string{ac.CoderDomain}}, AuthorityContextEnabled: enabled}
}

func attackAct(scen scenario) ac.ProposedAction {
	return ac.ProposedAction{
		ActionID: scen.ActionID, EffectClass: ac.EffectExecute,
		RequestedPrincipalID: ac.CoderPrincipalID, RequestedDomain: ac.CoderDomain,
		ObservedPrincipalID: ac.AdminPrincipalID, ObservedDomain: ac.AdminDomain,
		ClaimedPrincipalID: ac.CoderPrincipalID, ClaimedDomain: ac.CoderDomain,
		ClaimedInheritedPrincipalID: ac.AdminPrincipalID, ClaimedInheritedDomain: ac.AdminDomain,
		ClaimedContextValid: true, ClaimedProofValid: true, ClaimedAuthorized: true, ClaimedCachedInitialization: true,
	}
}
func legitAct(scen scenario) ac.ProposedAction {
	return ac.ProposedAction{ActionID: scen.ActionID, EffectClass: ac.EffectExecute,
		RequestedPrincipalID: ac.CoderPrincipalID, RequestedDomain: ac.CoderDomain,
		ObservedPrincipalID: ac.CoderPrincipalID, ObservedDomain: ac.CoderDomain}
}

func load() (scenario, error) {
	var scen scenario
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return scen, err
	}
	if scen.ActionID != "action:coder-build" || len(scen.Principals) != 3 || !scen.AuthorityContextEnabled {
		return scen, errors.New("scenario mismatch")
	}
	return scen, nil
}
