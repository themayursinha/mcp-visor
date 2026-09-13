//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestContextProvenanceDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/context-provenance")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("context-provenance failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"Context Provenance Proofs.",
		"A  WITHOUT VISOR (reconstructed USER role trusted)",
		"visible role USER reconstructed_from TOOL",
		"result EXECUTED",
		"vulnerable baseline count 1",
		"B  WITH VISOR (caller-held fragment graph checked)",
		"Context route Agent A -> MCP web tool -> Agent B",
		"Visible role USER reconstructed_from TOOL",
		"Original origin MCP_WEB_TOOL principal REMOTE_TOOL scope invocation-481",
		"Derived path web-1->handoff-1->agent-b-1",
		"Declared trust USER_TRUSTED effective trust UNTRUSTED",
		"Trust ceiling UNTRUSTED required USER_TRUSTED",
		"Context Provenance Proof INVALID",
		"Context Authority Escalation DETECTED; Instruction NON-AUTHORITATIVE",
		"result NOT_EXECUTED",
		"protected count 0",
		"INVALID",
		"DETECTED",
		"NON-AUTHORITATIVE",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing %q\n%s", frag, output)
		}
	}
	for _, banned := range []string{"production prevented", "CVE fixed", "instructionauthority", "causalauthority", "tools/call", "LLM", "proxy protected", "0.0.0.0"} {
		if strings.Contains(output, banned) {
			t.Errorf("banned %q", banned)
		}
	}
}
