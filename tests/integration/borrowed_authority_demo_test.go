//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestBorrowedAuthorityDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/borrowed-authority")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("borrowed-authority failed: %v\n%s", err, out)
	}
	output := string(out)

	for _, frag := range []string{
		"Borrowed authority is not authority.",
		"A  UNMEDIATED (permissive router)",
		"t+0    SERVER OBSERVED  yes  (EXECUTED)",
		"B  VISOR as tenant-A (ownership proofs)",
		"t+0    DENY  cross-principal authority acquisition",
		"argument class PRINCIPAL  effect class THIRD_PARTY",
		"t+0    SERVER OBSERVED  no",
		"t+0    ALLOW  narrow B-to-A delegation",
		"Proxy enforced.",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing required output fragment: %q\nfull output:\n%s", frag, output)
		}
	}
}
