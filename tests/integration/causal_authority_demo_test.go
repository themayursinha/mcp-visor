//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCausalAuthorityDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/causal-authority")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("causal-authority failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"Causal Authority Proofs.",
		"A  WITHOUT VISOR (scripted baseline)",
		"nslookup visor-h33-canary.attacker.test",
		"result EXECUTED",
		"B  WITH VISOR (scripted causal check)",
		"Tool permission VALID",
		"Command syntactically valid YES",
		"Agent authenticated YES",
		"Instruction source untrusted external content",
		"Source authorized to invoke shell NO",
		"Mandate-derived reason for shell execution ABSENT",
		"Causal Authority Proof INVALID",
		"Execution DENY",
		"result NOT_EXECUTED",
		"C  LEGITIMATE CONTRAST (user mandate + webpage data)",
		"Instruction source trusted user mandate",
		"Source authorized to invoke shell YES",
		"Mandate-derived reason for shell execution PRESENT",
		"Causal Authority Proof VALID",
		"Execution ALLOW",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing required output fragment: %q\nfull output:\n%s", frag, output)
		}
	}
}
