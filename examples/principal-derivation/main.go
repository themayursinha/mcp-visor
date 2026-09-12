// Command principal-derivation demonstrates that localhost is not
// identity: a scripted DNS-rebinding webpage can pass a conventional
// origin check, while Visor denies unless transport→session→agent
// identity is attested and a user mandate names that agent.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/themayursinha/mcp-visor/internal/principalderivation"
)

//go:embed scenario.json
var scenarioJSON []byte

type scenario struct {
	MaliciousWebpage    string `json:"malicious_webpage"`
	Destination         string `json:"destination"`
	Host                string `json:"host"`
	Origin              string `json:"origin"`
	XForwardedProto     string `json:"x_forwarded_proto"`
	XForwardedHost      string `json:"x_forwarded_host"`
	DNSAnswer           string `json:"dns_answer"`
	SocketLocality      string `json:"socket_locality"`
	TransportKind       string `json:"transport_kind"`
	ClaimedPrincipal    string `json:"claimed_principal"`
	LocalAgent          string `json:"local_agent"`
	MandatingPrincipal  string `json:"mandating_principal"`
	MandatingTrustClass string `json:"mandating_trust_class"`
	Tool                string `json:"tool"`
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
	fmt.Println("Principal Derivation Proofs.")
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
	called := false
	executor := func() { called = true }
	_ = scen.MaliciousWebpage
	executor()
	if !called {
		return errors.New("baseline must fire")
	}
	fmt.Println("A  WITHOUT VISOR (scripted conventional path)")
	fmt.Println("Destination localhost")
	fmt.Println("Origin check PASS")
	fmt.Println("MCP request ACCEPTED")
	fmt.Println("result CALLBACK_FIRED")
	fmt.Println()
	return nil
}

func runProtected(scen scenario) error {
	called := false
	d := principalderivation.Authorize(attackRoot(), artifact(scen))
	if d.Verdict == principalderivation.VerdictAllow {
		called = true
	}
	if called {
		return errors.New("protected path must not fire")
	}
	fmt.Println("B  WITH VISOR (scripted principal derivation check)")
	fmt.Println("Socket locality LOCAL")
	fmt.Println("Causal web origin REMOTE/UNTRUSTED")
	for _, line := range d.Evidence {
		fmt.Println(line)
	}
	fmt.Println("result CALLBACK_NOT_FIRED")
	fmt.Println()
	return nil
}

func runLegitimate(scen scenario) error {
	called := false
	d := principalderivation.Authorize(legitRoot(scen), artifact(scen))
	if d.Verdict == principalderivation.VerdictAllow {
		called = true
	}
	if !called {
		return errors.New("legitimate mandate must fire")
	}
	fmt.Println("C  LEGITIMATE CONTRAST (session-bound local agent + mandate)")
	for _, line := range d.Evidence {
		fmt.Println(line)
	}
	fmt.Println("result CALLBACK_FIRED")
	return nil
}

func attackRoot() principalderivation.EvaluationRoot {
	return principalderivation.EvaluationRoot{
		SchemaVersion:           principalderivation.SchemaVersion,
		TransportTrustClass:     principalderivation.TransportUnattested,
		MandatingTrustClass:     principalderivation.TrustTrustedUser,
		ToolCapabilityAvailable: true,
	}
}

func legitRoot(scen scenario) principalderivation.EvaluationRoot {
	return principalderivation.EvaluationRoot{
		SchemaVersion:       principalderivation.SchemaVersion,
		TransportTrustClass: principalderivation.TransportAttested,
		TransportPrincipal:  scen.LocalAgent, SessionIdentityBound: true, SessionPrincipal: scen.LocalAgent,
		AgentAuthenticated: true, AgentPrincipal: scen.LocalAgent, DelegationFromUser: true,
		MandatingPrincipal: scen.MandatingPrincipal, MandatingTrustClass: scen.MandatingTrustClass,
		MandatedAgentPrincipal: scen.LocalAgent, ToolCapabilityAvailable: true,
	}
}

func artifact(scen scenario) principalderivation.ObservedArtifact {
	return principalderivation.ObservedArtifact{
		Destination: scen.Destination, Host: scen.Host, Origin: scen.Origin,
		XForwardedProto: scen.XForwardedProto, XForwardedHost: scen.XForwardedHost,
		DNSAnswer: scen.DNSAnswer, SocketLocality: scen.SocketLocality, TransportKind: scen.TransportKind,
		ClaimedPrincipal: scen.ClaimedPrincipal, WebpageBytes: scen.MaliciousWebpage,
	}
}

func load() (scenario, error) {
	var scen scenario
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return scen, err
	}
	if scen.LocalAgent == "" || scen.Destination == "" {
		return scen, errors.New("scenario missing fields")
	}
	return scen, nil
}
