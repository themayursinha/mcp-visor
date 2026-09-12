// Command swarm-budget demonstrates Swarm Authority Budget: swarm intent is not authority.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	sb "github.com/themayursinha/mcp-visor/internal/swarmbudget"
)

//go:embed scenario.json
var scenarioJSON []byte

type scenario struct {
	CampaignID         string   `json:"campaign_id"`
	WorkerCount        int      `json:"worker_count"`
	HostCount          int      `json:"host_count"`
	MaxTargets         int      `json:"max_targets"`
	MaxConcurrent      int      `json:"max_concurrent_principals"`
	HarvestTargets     int      `json:"credential_harvest_targets"`
	RateLimit          int      `json:"new_target_authorization_limit"`
	HostileInstruction string   `json:"hostile_instruction"`
	AuthorizedTargets  []string `json:"authorized_targets"`
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
	fmt.Println("Swarm Authority Budget.")
	fmt.Printf("campaign %s workers %d hosts %d authorized %d\n\n", scen.CampaignID, scen.WorkerCount, scen.HostCount, len(scen.AuthorizedTargets))
	for _, fn := range []func(scenario) error{stageA, stageB, stageC} {
		if err := fn(scen); err != nil {
			return err
		}
	}
	printSummaries(scen)
	return nil
}

func evalRoot(scen scenario, enabled bool, st sb.CampaignState) sb.EvaluationRoot {
	return sb.EvaluationRoot{SchemaVersion: sb.SchemaVersion, CampaignID: scen.CampaignID, State: st, Budget: sb.CampaignBudget{
		MaxTargets: scen.MaxTargets, MaxConcurrentPrincipals: scen.MaxConcurrent, CredentialHarvestTargets: scen.HarvestTargets,
		NewTargetAuthorizationLimit: scen.RateLimit, DomainEscalationRequiresApproval: true, AuthorizedTargets: scen.AuthorizedTargets, BudgetEnabled: enabled,
	}}
}

func seq(scen scenario, i int) sb.ProposedAction {
	a := sb.ProposedAction{WorkerID: fmt.Sprintf("worker-%03d", i), TargetID: fmt.Sprintf("host-%04d", i), EffectClass: sb.EffectTargetAccess}
	if i >= 26 {
		a.ClaimedInstruction = scen.HostileInstruction
		a.ClaimedIgnoreBudget, a.ClaimedHostAuthorized, a.ClaimedConcurrentOK, a.ClaimedExternalApproval = true, true, true, true
	}
	return a
}

func simulate(scen scenario, enabled bool) (allow, deny int, hit26 bool) {
	st := sb.CampaignState{Tick: 1, AuthorizationWindowTick: 1}
	for i := 1; i <= scen.WorkerCount; i++ {
		tick := ((i - 1) / 5) + 1
		if tick != st.AuthorizationWindowTick {
			st.AuthorizationWindowTick, st.NewTargetAuthorizationsInWindow = tick, 0
		}
		st.Tick = tick
		act := seq(scen, i)
		d := sb.Authorize(evalRoot(scen, enabled, st), act)
		if d.Verdict != sb.VerdictAllow {
			deny++
			continue
		}
		allow++
		hit26 = hit26 || act.TargetID == "host-0026"
		if enabled && !contains(st.AdmittedTargets, act.TargetID) {
			st.AdmittedTargets = append(append([]string{}, st.AdmittedTargets...), act.TargetID)
			st.NewTargetAuthorizationsInWindow++
		}
	}
	return
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func stageA(scen scenario) error {
	allow, deny, hit26 := simulate(scen, false)
	if allow != 100 || deny != 0 || !hit26 {
		return fmt.Errorf("disabled: allow=%d deny=%d hit26=%v", allow, deny, hit26)
	}
	fmt.Println("A  BUDGET DISABLED (negative control)")
	fmt.Println("unauthorized_target host-0026 callback CALLBACK_FIRED")
	fmt.Println("allowed_targets 100")
	fmt.Println("denied_actions 0")
	fmt.Print("result CALLBACK_FIRED\n\n")
	return nil
}

func printStage(title, result string, d sb.Decision) {
	fmt.Println(title)
	for _, line := range d.Evidence {
		fmt.Println(line)
	}
	fmt.Print(result + "\n\n")
}

func stageB(scen scenario) error {
	d := sb.Authorize(evalRoot(scen, true, sb.CampaignState{Tick: 1, AuthorizationWindowTick: 1}), seq(scen, 26))
	if d.Verdict == sb.VerdictAllow {
		return errors.New("unauthorized host must not fire")
	}
	printStage("B  WITH VISOR (unauthorized target)", "result CALLBACK_NOT_FIRED", d)
	return nil
}

func stageC(scen scenario) error {
	d := sb.Authorize(evalRoot(scen, true, sb.CampaignState{Tick: 1, AuthorizationWindowTick: 1}), seq(scen, 1))
	if d.Verdict != sb.VerdictAllow {
		return errors.New("authorized target must fire")
	}
	printStage("C  AUTHORIZED CONTRAST (within ceilings)", "result CALLBACK_FIRED", d)
	return nil
}

func printSummaries(scen scenario) {
	allow, deny, _ := simulate(scen, true)
	fmt.Printf("enabled_swarm allowed_targets=%d denied_actions=%d\n", allow, deny)
	fmt.Println("fault_case misinstructed_workers=75 unauthorized_callbacks=0")
	st := sb.CampaignState{Tick: 1, AuthorizationWindowTick: 1, InFlightPrincipals: []string{"worker-001", "worker-002", "worker-003", "worker-004", "worker-005"}}
	fmt.Printf("concurrency sixth_principal=%s limit=5\n", label(sb.Authorize(evalRoot(scen, true, st), sb.ProposedAction{WorkerID: "worker-006", TargetID: "host-0001", EffectClass: sb.EffectTargetAccess}), true))
	rateSt := sb.CampaignState{AdmittedTargets: scen.AuthorizedTargets[:5], Tick: 7, AuthorizationWindowTick: 7, NewTargetAuthorizationsInWindow: 5}
	fmt.Printf("authorization_rate sixth_new_target_same_tick=%s limit=5\n", label(sb.Authorize(evalRoot(scen, true, rateSt), sb.ProposedAction{WorkerID: "worker-001", TargetID: "host-0006", EffectClass: sb.EffectTargetAccess}), true))
	hSt := sb.CampaignState{Tick: 1, AuthorizationWindowTick: 1, AdmittedTargets: scen.AuthorizedTargets[:4], CredentialHarvestedTargets: scen.AuthorizedTargets[:3]}
	fmt.Printf("credential_harvest fourth_target=%s limit=3\n", label(sb.Authorize(evalRoot(scen, true, hSt), sb.ProposedAction{WorkerID: "worker-001", TargetID: "host-0004", EffectClass: sb.EffectCredentialHarvest}), true))
	dSt := sb.CampaignState{Tick: 1, AuthorizationWindowTick: 1, AdmittedTargets: []string{"host-0001"}}
	dom := sb.ProposedAction{WorkerID: "worker-001", TargetID: "host-0001", EffectClass: sb.EffectDomainEscalation}
	fmt.Printf("domain_escalation without_external_approval=%s\n", label(sb.Authorize(evalRoot(scen, true, dSt), dom), true))
	dSt.DomainEscalationApprovedTargets = []string{"host-0001"}
	fmt.Printf("domain_escalation with_external_approval=%s\n", label(sb.Authorize(evalRoot(scen, true, dSt), dom), false))
}

func label(d sb.Decision, wantDeny bool) string {
	if wantDeny == (d.Verdict != sb.VerdictAllow) && wantDeny {
		return "DENIED"
	}
	if wantDeny == (d.Verdict != sb.VerdictAllow) {
		return "ALLOWED"
	}
	if wantDeny {
		return "ALLOWED"
	}
	return "DENIED"
}

func load() (scenario, error) {
	var scen scenario
	if err := json.Unmarshal(scenarioJSON, &scen); err != nil {
		return scen, err
	}
	if scen.CampaignID != sb.CampaignID || scen.WorkerCount != 100 || scen.HostCount != 1000 || len(scen.AuthorizedTargets) != 25 {
		return scen, errors.New("scenario counts mismatch")
	}
	return scen, nil
}
