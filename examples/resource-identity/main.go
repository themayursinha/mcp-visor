// Command resource-identity demonstrates Resource Identity Continuity:
// an allowed path name cannot authorize a swapped effect-time object.
// The conventional path-only baseline fires a boolean callback; Visor
// denies when authorized identity A differs from effect-time identity B.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/themayursinha/mcp-visor/internal/resourceidentity"
)

//go:embed scenario.json
var scenarioJSON []byte

type scenario struct {
	RequestedPath       string `json:"requested_path"`
	AllowedPath         string `json:"allowed_path"`
	MandatingPrincipal  string `json:"mandating_principal"`
	MandatingTrustClass string `json:"mandating_trust_class"`
	MandatedIdentity    string `json:"mandated_identity"`
	AuthorizedIdentity  string `json:"authorized_identity"`
	SwappedIdentity     string `json:"swapped_identity"`
	LegitimateIdentity  string `json:"legitimate_identity"`
	PathPermissionValid bool   `json:"path_permission_valid"`
	EffectClassWrite    bool   `json:"effect_class_write"`
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
	fmt.Println("Resource Identity Continuity Proofs.")
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
	_ = scen.RequestedPath
	executor()
	if !called {
		return errors.New("baseline must fire")
	}
	fmt.Println("A  WITHOUT VISOR (path-only authorization)")
	fmt.Printf("Requested path %s\n", scen.RequestedPath)
	fmt.Printf("Allowed path %s\n", scen.AllowedPath)
	fmt.Println("Path permission VALID")
	fmt.Println("result CALLBACK_FIRED")
	fmt.Println()
	return nil
}

func runProtected(scen scenario) error {
	called := false
	d := resourceidentity.Authorize(attackRoot(scen), artifact(scen))
	if d.Verdict == resourceidentity.VerdictAllow {
		called = true
	}
	if called {
		return errors.New("protected path must not fire")
	}
	fmt.Println("B  WITH VISOR (resource identity continuity check)")
	for _, line := range d.Evidence {
		fmt.Println(line)
	}
	fmt.Println("result CALLBACK_NOT_FIRED")
	fmt.Println()
	return nil
}

func runLegitimate(scen scenario) error {
	called := false
	d := resourceidentity.Authorize(legitRoot(scen), artifact(scen))
	if d.Verdict == resourceidentity.VerdictAllow {
		called = true
	}
	if !called {
		return errors.New("legitimate continuity must fire")
	}
	fmt.Println("C  LEGITIMATE CONTRAST (identity unchanged)")
	for _, line := range d.Evidence {
		fmt.Println(line)
	}
	fmt.Println("result CALLBACK_FIRED")
	return nil
}

func attackRoot(scen scenario) resourceidentity.EvaluationRoot {
	return resourceidentity.EvaluationRoot{
		SchemaVersion:      resourceidentity.SchemaVersion,
		IdentityAuthorized: scen.AuthorizedIdentity, IdentityAtEffect: scen.SwappedIdentity,
		MandatingPrincipal: scen.MandatingPrincipal, MandatingTrustClass: scen.MandatingTrustClass,
		MandatedIdentity:    scen.MandatedIdentity,
		PathPermissionValid: scen.PathPermissionValid, EffectClassWrite: scen.EffectClassWrite,
	}
}

func legitRoot(scen scenario) resourceidentity.EvaluationRoot {
	r := attackRoot(scen)
	r.IdentityAtEffect = scen.LegitimateIdentity
	return r
}

func artifact(scen scenario) resourceidentity.ObservedArtifact {
	return resourceidentity.ObservedArtifact{
		RequestedPath: scen.RequestedPath, PresentationName: "result.txt", IsSymlink: true,
		SymlinkTarget: "/outside/mandate",
	}
}

func load() (scenario, error) {
	var scen scenario
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return scen, err
	}
	if scen.AuthorizedIdentity == "" || scen.SwappedIdentity == "" {
		return scen, errors.New("scenario missing identities")
	}
	return scen, nil
}
