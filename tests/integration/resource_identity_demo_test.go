//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestResourceIdentityDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/resource-identity")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("resource-identity failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"Resource Identity Continuity Proofs.",
		"A  WITHOUT VISOR (path-only authorization)",
		"Requested path /workspace/output/result.txt",
		"Allowed path /workspace/output/**",
		"Path permission VALID",
		"result CALLBACK_FIRED",
		"B  WITH VISOR (resource identity continuity check)",
		"Authorized resource identity object:workspace-output-result-A",
		"Effect-time resource identity object:outside-mandate-B",
		"Identity continuity FAILED",
		"Mandate for effect-time identity ABSENT",
		"Resource Identity Proof INVALID",
		"WRITE DENIED",
		"result CALLBACK_NOT_FIRED",
		"C  LEGITIMATE CONTRAST (identity unchanged)",
		"Effect-time resource identity object:workspace-output-result-A",
		"Identity continuity PRESERVED",
		"Mandate for effect-time identity PRESENT",
		"Resource Identity Proof VALID",
		"WRITE ALLOWED",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing %q\n%s", frag, output)
		}
	}
}
