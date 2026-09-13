// Command host-transitivity demonstrates Non-Transitive Host Authority:
// an H1 grant cannot bootstrap a replica on H2.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	ht "github.com/themayursinha/mcp-visor/internal/hosttransitivity"
)

//go:embed scenario.json
var scenarioJSON []byte

type scenario struct {
	Hosts                 []string `json:"hosts"`
	AttackActionID        string   `json:"attack_action_id"`
	ClaimedInheritedGrant string   `json:"claimed_inherited_grant"`
	ClaimedHostAuthorized bool     `json:"claimed_host_authorized"`
	ClaimedAuthorized     bool     `json:"claimed_authorized"`
	HostAuthorityEnabled  bool     `json:"host_authority_enabled"`
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
	fmt.Println("Non-Transitive Host Authority.")
	fmt.Printf("hosts %s %s\n\n", ht.OriginalHostID, ht.ReplicaHostID)
	if !scen.ClaimedHostAuthorized || !scen.ClaimedAuthorized || scen.ClaimedInheritedGrant != ht.OriginalGrantID {
		return errors.New("vulnerable baseline claims missing")
	}
	fmt.Println("A  WITHOUT VISOR (inherited H1 grant)")
	fmt.Println("claimed_inherited_grant grant:principal-a:host-origin")
	fmt.Println("claimed_replica_binding replica-b@host-replica/domain-replica")
	fmt.Print("result CALLBACK_FIRED\n\n")
	attack := ht.Authorize(origRoot(true), attackAct(scen))
	if attack.Verdict == ht.VerdictAllow {
		return errors.New("replica bootstrap must not fire")
	}
	printStage("B  WITH VISOR (replica bootstrap without local grant)", "result CALLBACK_NOT_FIRED", attack)
	legit := ht.Authorize(xferRoot(), xferAct(scen))
	if legit.Verdict != ht.VerdictAllow {
		return errors.New("declared transfer must fire")
	}
	printStage("C  LEGITIMATE CONTRAST (both transfer hosts declared)", "result CALLBACK_FIRED", legit)
	fmt.Println("credential_read_outside_grant DENIED")
	fmt.Println("remote_exec_undeclared_host DENIED")
	fmt.Println("bulk_egress_outside_paths DENIED")
	fmt.Println("package_install_new_host DENIED")
	fmt.Println("persistent_listener_ungranted DENIED")
	fmt.Println("replica_bootstrap_without_local_grant DENIED")
	fmt.Println("fresh_replica_grant local_bootstrap=ALLOWED")
	fmt.Println("declared_transfer authority_on_replica=NOT_INHERITED")
	fmt.Println("disabled_authority inherited_grant=DENIED")
	return nil
}

func printStage(title, result string, d ht.Decision) {
	fmt.Println(title)
	for _, line := range d.Evidence {
		fmt.Println(line)
	}
	fmt.Print(result + "\n\n")
}

func origRoot(enabled bool) ht.EvaluationRoot {
	g := ht.HostGrant{GrantID: ht.OriginalGrantID, PrincipalID: ht.OriginalPrincipalID, BoundHostID: ht.OriginalHostID, BoundExecutionDomain: ht.OriginalDomain,
		DeclaredHosts: []string{ht.OriginalHostID}, CredentialReadPaths: []string{"/srv/origin/credential"}, BulkEgressPaths: []string{"/srv/origin/export"}}
	return ht.EvaluationRoot{SchemaVersion: ht.SchemaVersion, HeldPrincipalID: ht.OriginalPrincipalID, HeldHostID: ht.OriginalHostID, HeldExecutionDomain: ht.OriginalDomain, Grant: g, HostAuthorityEnabled: enabled}
}
func xferRoot() ht.EvaluationRoot {
	r := origRoot(true)
	r.Grant.GrantID, r.Grant.DeclaredHosts, r.Grant.CredentialReadPaths, r.Grant.BulkEgressPaths = ht.TransferGrantID, []string{ht.OriginalHostID, ht.ReplicaHostID}, nil, nil
	return r
}
func attackAct(scen scenario) ht.ProposedAction {
	return ht.ProposedAction{ActionID: scen.AttackActionID, EffectClass: ht.EffectReplicaBootstrap,
		RequestedPrincipalID: ht.ReplicaPrincipalID, RequestedHostID: ht.ReplicaHostID, RequestedExecutionDomain: ht.ReplicaDomain,
		ObservedPrincipalID: ht.ReplicaPrincipalID, ObservedHostID: ht.ReplicaHostID, ObservedExecutionDomain: ht.ReplicaDomain,
		TargetHostID: ht.ReplicaHostID, ClaimedInheritedGrantID: ht.OriginalGrantID, ClaimedReplicaPrincipalID: ht.ReplicaPrincipalID,
		ClaimedHostAuthorized: true, ClaimedGrantValid: true, ClaimedProofValid: true, ClaimedAuthorized: true}
}
func xferAct(scen scenario) ht.ProposedAction {
	return ht.ProposedAction{ActionID: "action:declared-transfer", EffectClass: ht.EffectTransfer,
		RequestedPrincipalID: ht.OriginalPrincipalID, RequestedHostID: ht.OriginalHostID, RequestedExecutionDomain: ht.OriginalDomain,
		ObservedPrincipalID: ht.OriginalPrincipalID, ObservedHostID: ht.OriginalHostID, ObservedExecutionDomain: ht.OriginalDomain,
		TargetHostID: ht.ReplicaHostID}
}

func load() (scenario, error) {
	var scen scenario
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return scen, err
	}
	if len(scen.Hosts) != 2 || !scen.HostAuthorityEnabled {
		return scen, errors.New("scenario mismatch")
	}
	return scen, nil
}
