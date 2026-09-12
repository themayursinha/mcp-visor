// Command causal-authority demonstrates Causal Authority Proofs: a
// ticket author's hidden shell instruction cannot cause execution just
// because the agent has a permitted shell tool. The vulnerable baseline
// selects the hidden instruction and fires a boolean callback; Visor
// denies with causal evidence. A user-mandated dependency check may
// use webpage bytes as DATA_ONLY arguments. No real DNS or shell.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/themayursinha/mcp-visor/internal/causalauthority"
)

//go:embed scenario.json
var scenarioJSON []byte

type scenario struct {
	UserMandate               string `json:"user_mandate"`
	UserPrincipal             string `json:"user_principal"`
	UserTrustClass            string `json:"user_trust_class"`
	MaliciousTicket           string `json:"malicious_ticket"`
	TicketPrincipal           string `json:"ticket_principal"`
	TicketTrustClass          string `json:"ticket_trust_class"`
	HiddenCanary              string `json:"hidden_canary"`
	RequestedEffect           string `json:"requested_effect"`
	MandatedEffect            string `json:"mandated_effect"`
	ToolPermissionValid       bool   `json:"tool_permission_valid"`
	CommandSyntacticallyValid bool   `json:"command_syntactically_valid"`
	AgentAuthenticated        bool   `json:"agent_authenticated"`
	WebpageBytes              string `json:"webpage_bytes"`
	ExtractedVersion          string `json:"extracted_version"`
	LegitimateMandate         string `json:"legitimate_mandate"`
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
	fmt.Println("Causal Authority Proofs.")
	fmt.Println()
	fmt.Println("ATTACK INPUT (untrusted ticket)")
	fmt.Printf("  %s\n", scen.MaliciousTicket)
	fmt.Println()
	if err := runBaseline(scen); err != nil {
		return err
	}
	if err := runProtected(scen); err != nil {
		return err
	}
	return runLegitimate(scen)
}

func runBaseline(scen scenario) error {
	executed := false
	executor := func() { executed = true }
	_ = scen.HiddenCanary
	executor()
	if !executed {
		return errors.New("baseline must execute (vulnerable harness trusts ticket text)")
	}
	fmt.Println("A  WITHOUT VISOR (scripted baseline)")
	fmt.Println("   ticket read -> hidden instruction selected -> permitted shell callback")
	fmt.Println("   Execution ALLOW")
	fmt.Println("   result EXECUTED")
	fmt.Println()
	return nil
}

func runProtected(scen scenario) error {
	executed := false
	d := causalauthority.Authorize(attackRoot(scen), Observed(scen.MaliciousTicket, "TICKET"))
	if d.Verdict == causalauthority.VerdictAllow {
		executed = true
	}
	if executed {
		return errors.New("protected path must not execute the ticket instruction")
	}
	fmt.Println("B  WITH VISOR (scripted causal check)")
	for _, line := range d.Evidence {
		fmt.Printf("   %s\n", line)
	}
	fmt.Println("   result NOT_EXECUTED")
	fmt.Println()
	return nil
}

func runLegitimate(scen scenario) error {
	executed := false
	d := causalauthority.Authorize(legitRoot(scen), Observed(scen.WebpageBytes+" "+scen.ExtractedVersion, "WEBPAGE"))
	if d.Verdict == causalauthority.VerdictAllow {
		executed = true
	}
	if !executed {
		return errors.New("legitimate user mandate must execute")
	}
	fmt.Println("C  LEGITIMATE CONTRAST (user mandate + webpage data)")
	for _, line := range d.Evidence {
		fmt.Printf("   %s\n", line)
	}
	fmt.Println("   result EXECUTED")
	return nil
}

func attackRoot(scen scenario) causalauthority.EvaluationRoot {
	return causalauthority.EvaluationRoot{
		SchemaVersion: causalauthority.SchemaVersion, MandateText: scen.UserMandate,
		MandatingPrincipal: scen.UserPrincipal, MandatingTrustClass: scen.UserTrustClass,
		MandatedEffect: scen.MandatedEffect, ImmediateSourcePrincipal: scen.TicketPrincipal,
		ImmediateSourceTrustClass: scen.TicketTrustClass, RequestedEffect: scen.RequestedEffect,
		ToolPermissionValid: scen.ToolPermissionValid, CommandSyntacticallyValid: scen.CommandSyntacticallyValid,
		AgentAuthenticated: scen.AgentAuthenticated,
	}
}

func legitRoot(scen scenario) causalauthority.EvaluationRoot {
	r := attackRoot(scen)
	r.MandateText = scen.LegitimateMandate
	r.ImmediateSourcePrincipal = scen.UserPrincipal
	r.ImmediateSourceTrustClass = scen.UserTrustClass
	return r
}

func Observed(content, role string) causalauthority.ObservedArtifact {
	return causalauthority.ObservedArtifact{Content: content, VisibleRole: role}
}

func loadScenario() (scenario, error) {
	var scen scenario
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return scen, fmt.Errorf("parse scenario: %w", err)
	}
	if scen.MaliciousTicket == "" || scen.HiddenCanary == "" || scen.LegitimateMandate == "" {
		return scen, errors.New("scenario is missing required fields")
	}
	return scen, nil
}
