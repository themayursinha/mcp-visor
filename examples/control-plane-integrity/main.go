// Command control-plane-integrity demonstrates Control-Plane Integrity:
// a conventional policy ALLOW cannot authorize a known-critical
// policy-store substrate. Stage A fires a boolean callback; Visor
// denies the compromised root and does not fire.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	cpi "github.com/themayursinha/mcp-visor/internal/controlplaneintegrity"
)

//go:embed scenario.json
var scenarioJSON []byte

type tuple struct {
	Kind        string `json:"kind"`
	Product     string `json:"product"`
	Build       string `json:"build"`
	Measurement string `json:"measurement"`
}

type scenario struct {
	Mutation                 string `json:"mutation"`
	MandateStructurallyValid bool   `json:"mandate_structurally_valid"`
	PolicyEngineAllow        bool   `json:"policy_engine_allow"`
	IdentityTrusted          tuple  `json:"identity_trusted"`
	PolicyTrusted            tuple  `json:"policy_trusted"`
	RuntimeTrusted           tuple  `json:"runtime_trusted"`
	RegistryTrusted          tuple  `json:"registry_trusted"`
	IdentityCritical         tuple  `json:"identity_critical"`
	PolicyCritical           tuple  `json:"policy_critical"`
	RuntimeCritical          tuple  `json:"runtime_critical"`
	RegistryCritical         tuple  `json:"registry_critical"`
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
	fmt.Println("Control-Plane Integrity Proofs.")
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
	if scen.PolicyEngineAllow {
		called = true
	}
	if !called {
		return errors.New("baseline must fire")
	}
	fmt.Println("A  WITHOUT VISOR (conventional policy lookup)")
	fmt.Printf("%s\n", scen.Mutation)
	fmt.Println("Mandate structurally VALID")
	fmt.Println("Conventional policy result ALLOW")
	fmt.Println("result CALLBACK_FIRED")
	fmt.Println()
	return nil
}

func runProtected(scen scenario) error {
	called := false
	d := cpi.Authorize(compromised(scen), hostile())
	if d.Verdict == cpi.VerdictAllow {
		called = true
	}
	if called {
		return errors.New("protected path must not fire")
	}
	fmt.Println("B  WITH VISOR (control-plane integrity check)")
	for _, line := range d.Evidence {
		fmt.Println(line)
	}
	fmt.Println("result CALLBACK_NOT_FIRED")
	fmt.Println()
	return nil
}

func runLegitimate(scen scenario) error {
	called := false
	d := cpi.Authorize(healthy(scen), hostile())
	if d.Verdict == cpi.VerdictAllow {
		called = true
	}
	if !called {
		return errors.New("healthy substrate must fire")
	}
	fmt.Println("C  LEGITIMATE CONTRAST (healthy substrate)")
	for _, line := range d.Evidence {
		fmt.Println(line)
	}
	fmt.Println("result CALLBACK_FIRED")
	return nil
}

func asTuple(t tuple) cpi.CatalogTuple {
	return cpi.CatalogTuple{Kind: t.Kind, Product: t.Product, Build: t.Build, Measurement: t.Measurement}
}

func attest(t tuple) cpi.Attestation {
	return cpi.Attestation{Kind: t.Kind, Product: t.Product, Build: t.Build, Measurement: t.Measurement}
}

func catalog(scen scenario) cpi.Catalog {
	return cpi.Catalog{
		TrustedBuilds: []cpi.CatalogTuple{
			asTuple(scen.IdentityTrusted), asTuple(scen.PolicyTrusted),
			asTuple(scen.RuntimeTrusted), asTuple(scen.RegistryTrusted),
		},
		KnownCriticalBuilds: []cpi.CatalogTuple{
			asTuple(scen.IdentityCritical), asTuple(scen.PolicyCritical),
			asTuple(scen.RuntimeCritical), asTuple(scen.RegistryCritical),
		},
	}
}

func healthy(scen scenario) cpi.EvaluationRoot {
	return cpi.EvaluationRoot{
		SchemaVersion: cpi.SchemaVersion, MandateStructurallyValid: scen.MandateStructurallyValid,
		PolicyEngineAllow: scen.PolicyEngineAllow, IdentityStore: attest(scen.IdentityTrusted),
		PolicyStore: attest(scen.PolicyTrusted), ExecutionRuntime: attest(scen.RuntimeTrusted),
		ResourceRegistry: attest(scen.RegistryTrusted), Catalog: catalog(scen),
	}
}

func compromised(scen scenario) cpi.EvaluationRoot {
	r := healthy(scen)
	r.PolicyStore = attest(scen.PolicyCritical)
	return r
}

func hostile() cpi.ObservedArtifact {
	return cpi.ObservedArtifact{
		ClaimedPolicyBytes: []byte("agent A may administer all queues"), ClaimedPolicyAllow: true,
		VisibleRole: "SYSTEM", ClaimedProof: cpi.ClaimedProof{Verdict: cpi.VerdictAllow, Proof: cpi.ProofValid},
	}
}

func load() (scenario, error) {
	var scen scenario
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return scen, err
	}
	if scen.Mutation == "" || scen.PolicyCritical.Build == "" {
		return scen, errors.New("scenario missing mutation")
	}
	return scen, nil
}
