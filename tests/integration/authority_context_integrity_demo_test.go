//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestAuthorityContextIntegrityDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/authority-context")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("authority-context failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"Authority-Context Integrity.",
		"principals admin-agent coder-agent web-agent",
		"A  WITHOUT VISOR (shared ambient context)",
		"claimed_inherited_context admin-agent@host",
		"requested_context coder-agent@docker-coder",
		"B  WITH VISOR (cross-principal ambient bleed)",
		"Observed context admin-agent@host",
		"Principal binding INVALID",
		"Observed-domain authority ABSENT",
		"Authority-Context Integrity Proof INVALID",
		"CONTEXT EFFECT DENIED",
		"result CALLBACK_NOT_FIRED",
		"C  LEGITIMATE CONTRAST (bound coder context)",
		"Observed context coder-agent@docker-coder",
		"Authority-Context Integrity Proof VALID",
		"CONTEXT EFFECT ALLOWED",
		"result CALLBACK_FIRED",
		"ordering_permutations sequences=6 calls_per_sequence=3 bleed_decisions=0",
		"interleaved_sequence calls=9 attack_denials=3 legitimate_allows=6",
		"disabled_context inherited_ambient=DENIED",
		"principal_switch admin_to_coder_requires_new_root=YES",
		"error_path subsequent_coder_context=ISOLATED",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing %q\n%s", frag, output)
		}
	}
	for _, banned := range []string{"TERMINAL_ENV", "os.Getenv", "Docker", "production protected"} {
		if strings.Contains(output, banned) {
			t.Errorf("banned %q", banned)
		}
	}
}
