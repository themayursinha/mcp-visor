//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestSelfEscalationInvariantDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/self-escalation")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("self-escalation failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"Self-Escalation Invariant.",
		"fixture sample_size=8 seed=43043",
		"A  WITHOUT VISOR (self-asserted authority claims)",
		"surface surface:loopback-policy-api claimed reachable",
		"host localhost claimed trusted",
		"attribution USER claimed",
		"danger_full_access true",
		"policy_rewrite true",
		"claimed_authorization true",
		"B  WITH VISOR (parent delegation and typed proof checked)",
		"Authority root delegation=delegation:confined-agent child=agent:confined allowed=1 meta_grants=0 surfaces=4",
		"Requested action action:self-authority-modification actor=agent:confined authority=authority.modify(self)",
		"Management surface surface:loopback-policy-api reachability=PRESENT",
		"Claims host=localhost attribution=USER danger_full_access=true policy_rewrite=true authorized=true",
		"Authority delegation=ABSENT meta=MISSING attribution=AGENT",
		"Missing proof authority.modify(self)",
		"reason meta-authority proof missing",
		"ACTION DENIED",
		"C  LEGITIMATE CONTRAST (in-delegation workspace write)",
		"Requested action action:workspace-write actor=agent:confined authority=workspace.write",
		"Management surface <none> reachability=ABSENT",
		"Claims host=<none> attribution=<none> danger_full_access=false policy_rewrite=false authorized=false",
		"Authority delegation=PRESENT meta=NOT_REQUIRED attribution=AGENT",
		"Authority Proof VALID workspace.write",
		"reason authorized",
		"ACTION ALLOWED",
		"result CALLBACK_FIRED",
		"result CALLBACK_NOT_FIRED",
		"policy_self_modify DENIED",
		"false_escalation_formation 5/6",
		"propagation 3/6",
		"over_rejection 0/2",
		"measurement DETERMINISTIC",
		"rng NOT_USED",
		"management_surface NOT_CONTACTED",
		"escalation_executor NOT_IMPLEMENTED",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing %q\n%s", frag, output)
		}
	}
	for _, banned := range []string{"CVE-2026-82533", "DeepSeek", "Hermes", "exploit", "HTTP", "POST", "GET", "127.0.0.1", "0.0.0.0", "tools/call", "result file", "policy rewritten", "authority modified", "production prevented", "CVE fixed"} {
		if strings.Contains(output, banned) {
			t.Errorf("banned %q", banned)
		}
	}
}
