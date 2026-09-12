//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestSwarmAuthorityBudgetDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/swarm-budget")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("swarm-budget failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"Swarm Authority Budget.",
		"campaign campaign:swarm-budget-demo workers 100 hosts 1000 authorized 25",
		"A  BUDGET DISABLED (negative control)",
		"unauthorized_target host-0026 callback CALLBACK_FIRED",
		"allowed_targets 100",
		"denied_actions 0",
		"result CALLBACK_FIRED",
		"B  WITH VISOR (unauthorized target)",
		"Target host-0026",
		"Target authority ABSENT",
		"Swarm Authority Budget Proof INVALID",
		"TARGET EFFECT DENIED",
		"result CALLBACK_NOT_FIRED",
		"C  AUTHORIZED CONTRAST (within ceilings)",
		"Target host-0001",
		"Target authority PRESENT",
		"Swarm Authority Budget Proof VALID",
		"TARGET EFFECT ALLOWED",
		"enabled_swarm allowed_targets=25 denied_actions=75",
		"fault_case misinstructed_workers=75 unauthorized_callbacks=0",
		"concurrency sixth_principal=DENIED limit=5",
		"authorization_rate sixth_new_target_same_tick=DENIED limit=5",
		"credential_harvest fourth_target=DENIED limit=3",
		"domain_escalation without_external_approval=DENIED",
		"domain_escalation with_external_approval=ALLOWED",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing %q\n%s", frag, output)
		}
	}
}
