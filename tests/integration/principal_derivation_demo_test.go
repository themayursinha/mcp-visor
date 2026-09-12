//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPrincipalDerivationDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/principal-derivation")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("principal-derivation failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"Principal Derivation Proofs.",
		"A  WITHOUT VISOR (scripted conventional path)",
		"Destination localhost",
		"Origin check PASS",
		"MCP request ACCEPTED",
		"result CALLBACK_FIRED",
		"B  WITH VISOR (scripted principal derivation check)",
		"Socket locality LOCAL",
		"Causal web origin REMOTE/UNTRUSTED",
		"Transport identity UNATTESTED",
		"Transport identity -> session identity DENIED (session identity ABSENT)",
		"Session identity -> agent identity DENIED (authenticated MCP principal ABSENT)",
		"Agent identity -> mandate DENIED (delegation from user ABSENT)",
		"Caller authority ZERO",
		"Principal Derivation Proof INVALID",
		"Request DENY",
		"result CALLBACK_NOT_FIRED",
		"C  LEGITIMATE CONTRAST (session-bound local agent + mandate)",
		"Transport identity ATTESTED agent:local-agent",
		"Transport identity -> session identity JUSTIFIED agent:local-agent",
		"Session identity -> agent identity JUSTIFIED agent:local-agent",
		"Agent identity -> mandate JUSTIFIED user:operator=>agent:local-agent",
		"Caller authority USER",
		"Principal Derivation Proof VALID",
		"Request ALLOW",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing %q\n%s", frag, output)
		}
	}
}
