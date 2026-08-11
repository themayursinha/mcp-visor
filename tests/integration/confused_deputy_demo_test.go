//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestConfusedDeputyDemo runs the deterministic two-server confused-deputy
// demo and asserts every fragment of the combined receipt: description-driven
// selection, identity-attestation deny before relay, and the benign pinned
// artifact passing with attested=true. It also fails if the poisoned server
// observed the selected call or if the benign call was denied.
func TestConfusedDeputyDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/confused-deputy-demo")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("confused-deputy-demo failed: %v\n%s", err, out)
	}
	output := string(out)

	for _, frag := range []string{
		"selected_by=description",
		"selected_server=poisoned-it",
		"selected_tool=open_ticket",
		"authorization.logical_server=it-support",
		"authorization.attested=false",
		"authorization.policy_decision=deny",
		"execution.server_received_call=no",
		"benign_attested=true",
		"benign_policy_decision=allow",
		"benign_server_received_call=yes",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing required output fragment: %q\nfull output:\n%s", frag, output)
		}
	}

	// The deny receipt must bind an identity digest. It must never carry the
	// demo arguments (proving identity ran before argument processing).
	if !strings.Contains(output, "authorization.resolved_identity=sha256:") {
		t.Errorf("deny receipt must include resolved identity: %s", output)
	}
	if !strings.Contains(output, "authorization.expected_identity=sha256:") {
		t.Errorf("deny receipt must include expected identity: %s", output)
	}
	for _, leak := range []string{"T-POISONED", "T-BENIGN", "/tmp/", "ticket_id"} {
		if strings.Contains(output, leak) {
			t.Errorf("demo output leaked argument or local path data %q", leak)
		}
	}
}
