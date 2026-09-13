//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestHostTransitivityDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/host-transitivity")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("host-transitivity failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"Non-Transitive Host Authority.",
		"hosts host-origin host-replica",
		"A  WITHOUT VISOR (inherited H1 grant)",
		"claimed_inherited_grant grant:principal-a:host-origin",
		"claimed_replica_binding replica-b@host-replica/domain-replica",
		"B  WITH VISOR (replica bootstrap without local grant)",
		"Requested binding replica-b@host-replica/domain-replica",
		"Host Transitivity Proof INVALID",
		"HOST EFFECT DENIED",
		"result CALLBACK_NOT_FIRED",
		"C  LEGITIMATE CONTRAST (both transfer hosts declared)",
		"Grant grant:declared-transfer",
		"Host Transitivity Proof VALID",
		"HOST EFFECT ALLOWED",
		"credential_read_outside_grant DENIED",
		"remote_exec_undeclared_host DENIED",
		"bulk_egress_outside_paths DENIED",
		"package_install_new_host DENIED",
		"persistent_listener_ungranted DENIED",
		"replica_bootstrap_without_local_grant DENIED",
		"fresh_replica_grant local_bootstrap=ALLOWED",
		"declared_transfer authority_on_replica=NOT_INHERITED",
		"disabled_authority inherited_grant=DENIED",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing %q\n%s", frag, output)
		}
	}
	for _, banned := range []string{"ssh", "Palisade", "119GB", "kill-switch", "production protected", "0.0.0.0"} {
		if strings.Contains(output, banned) {
			t.Errorf("banned %q", banned)
		}
	}
}
