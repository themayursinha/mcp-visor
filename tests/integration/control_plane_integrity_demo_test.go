//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestControlPlaneIntegrityDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/control-plane-integrity")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("control-plane-integrity failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"Control-Plane Integrity Proofs.",
		"A  WITHOUT VISOR (conventional policy lookup)",
		"mutation:update-policy-record",
		"Mandate structurally VALID",
		"Conventional policy result ALLOW",
		"result CALLBACK_FIRED",
		"B  WITH VISOR (control-plane integrity check)",
		"identity-store integrity VALID",
		"policy-store integrity UNPROVEN",
		"execution-runtime integrity VALID",
		"resource-registry integrity VALID",
		"Control-Plane Integrity Proof INVALID",
		"CONTROL-PLANE EFFECT DENIED",
		"result CALLBACK_NOT_FIRED",
		"C  LEGITIMATE CONTRAST (healthy substrate)",
		"policy-store integrity VALID",
		"Control-Plane Integrity Proof VALID",
		"CONTROL-PLANE EFFECT ALLOWED",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing %q\n%s", frag, output)
		}
	}
}
