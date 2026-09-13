//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestAuthorizationStateFidelityDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/auth-state-fidelity")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("auth-state-fidelity failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"Authorization-State Fidelity.",
		"fixture sample_size=8 seed=40040",
		"A  WITHOUT VISOR (model memory treated as authority)",
		"memory_permission agent:worker|deploy:production",
		"cited_grant event:grant-production",
		"B  WITH VISOR (exact state recomputed from event log)",
		"Authorization root tick=30 events=6",
		"Requested pair agent:worker|deploy:production",
		"Memory claim permission=PRESENT grant=event:grant-production",
		"Source event event:grant-production principal=operator:alice status=REVOKED",
		"Authority principal=PRESENT exact_state=UNAUTHORIZED",
		"Authorization-State Fidelity Proof INVALID",
		"reason cited grant revoked",
		"ACTION DENIED",
		"repair_mode RECOMPUTE_ONLY",
		"active_bindings 2",
		"C  LEGITIMATE CONTRAST (active grant source)",
		"Requested pair agent:worker|reports:read",
		"Memory claim permission=ABSENT grant=event:grant-reports",
		"Source event event:grant-reports principal=operator:alice status=VALID",
		"Authority principal=PRESENT exact_state=AUTHORIZED",
		"Authorization-State Fidelity Proof VALID",
		"reason authorized",
		"ACTION ALLOWED",
		"result CALLBACK_FIRED",
		"result CALLBACK_NOT_FIRED",
		"false_authority_formation 5/6",
		"propagation_would_fire 3/6",
		"over_rejection 0/2",
		"measurement DETERMINISTIC",
		"rng NOT_USED",
		"memory_store NOT_MUTATED",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing %q\n%s", frag, output)
		}
	}
	for _, banned := range []string{"EAL-Bench executed", "LLM judge", "HMAC", "receipt verified", "tools/call", "proxy protected", "production prevented", "memory updated", "0.0.0.0"} {
		if strings.Contains(output, banned) {
			t.Errorf("banned %q", banned)
		}
	}
}
