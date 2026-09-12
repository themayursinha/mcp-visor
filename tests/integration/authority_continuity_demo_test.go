//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInstructionAuthorityContinuityDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/authority-continuity")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("authority-continuity failed: %v\n%s", err, out)
	}
	output := string(out)

	for _, frag := range []string{
		"Instruction Authority Continuity.",
		"A  WITHOUT VISOR (scripted baseline)",
		"result EXECUTED",
		"B  WITH VISOR (scripted continuity check)",
		"policy_decision=deny  policy_rule=instruction_authority_continuity",
		"reason=authority-expanding instruction",
		"argument class INSTRUCTION  effect class PROCESS",
		"visible role USER  original principal untrusted MCP response",
		"authority transition DATA_ONLY->USER",
		"lineage DATA_ONLY->DATA_ONLY->DATA_ONLY",
		"attempted promotion YES  authorized promoter NONE",
		"continuity FAILED",
		"observation preserved  authority DATA_ONLY",
		"result NOT_EXECUTED",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing required output fragment: %q\nfull output:\n%s", frag, output)
		}
	}
}
