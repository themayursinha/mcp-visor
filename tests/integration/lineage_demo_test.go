//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestLineageDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/lineage-demo")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("lineage-demo failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"== Who did this? ==",
		"lineage: human_principal=mayur",
		"lineage: planner_agent=planner-agent-1",
		"lineage: coding_agent=coding-agent-1",
		"lineage: grant_chain=grant-planner-1 -> grant-coding-1",
		"lineage: capability=github.repo.write",
		"lineage: resource=repo:themayursinha/mcp-visor",
		"lineage: decision=allow",
		"lineage: audit=sha256:",
		"lineage: server_received_call=yes",
		"== Same write from an unregistered agent ==",
		"lineage: agent=orphan-1",
		"lineage: registered_principal=no",
		"lineage: delegation_lineage=none",
		"lineage: decision=deny",
		"lineage: reason=lineage:unregistered-principal",
		"lineage: server_received_call=no",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing required output fragment: %q\nfull output:\n%s", frag, output)
		}
	}
}
