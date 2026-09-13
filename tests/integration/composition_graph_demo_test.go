//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCapabilityCompositionGraphDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/composition-graph")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("composition-graph failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"Capability Composition Graph.",
		"fixture sample_size=8 seed=41041",
		"A  WITHOUT VISOR (individual capability claims composed)",
		"step skill:credential-discovery/edge:discover-credentials claimed ALLOW",
		"step skill:context-normalizer/edge:normalize-credential claimed ALLOW",
		"step skill:mcp-submitter/edge:submit-external claimed ALLOW",
		"claimed_composition VALID",
		"B  WITH VISOR (complete trajectory checked against mandate)",
		"Composition root mandate=mandate:report-export skills=6 edges=6",
		"Requested flow CREDENTIAL_SOURCE|EXTERNAL_DISCLOSURE destination=mcp:external",
		"Declared path skill:credential-discovery/edge:discover-credentials>skill:context-normalizer/edge:normalize-credential>skill:mcp-submitter/edge:submit-external",
		"Claims signatures=true individual_allow=true composition_valid=true authorized=true",
		"Authority graph=PRESENT continuity=VALID effects=PRESENT destination=PRESENT artifacts=ABSENT composition=INVALID",
		"Capability Composition Proof INVALID",
		"reason composed artifact trajectory outside mandate",
		"ACTION DENIED",
		"trajectory CREDENTIAL_SOURCE>CREDENTIAL_ARTIFACT>CONTEXT_ARTIFACT>EXTERNAL_DISCLOSURE",
		"C  LEGITIMATE CONTRAST (in-mandate read-transform-send)",
		"Requested flow REPORT_SOURCE|EXTERNAL_DELIVERY destination=mcp:external",
		"Declared path skill:report-reader/edge:read-report>skill:report-transformer/edge:transform-report>skill:report-sender/edge:send-report",
		"Claims signatures=false individual_allow=false composition_valid=false authorized=false",
		"Authority graph=PRESENT continuity=VALID effects=PRESENT destination=PRESENT artifacts=PRESENT composition=VALID",
		"Capability Composition Proof VALID",
		"reason authorized",
		"ACTION ALLOWED",
		"trajectory REPORT_SOURCE>REPORT_ARTIFACT>REPORT_CONTEXT>EXTERNAL_DELIVERY",
		"result CALLBACK_FIRED",
		"result CALLBACK_NOT_FIRED",
		"false_composition_formation 5/6",
		"propagation_would_fire 3/6",
		"over_rejection 0/2",
		"measurement DETERMINISTIC",
		"rng NOT_USED",
		"skill_execution NOT_PERFORMED",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing %q\n%s", frag, output)
		}
	}
	for _, banned := range []string{"signed skill", "signature verified", "receipt verified", "HMAC", "tools/call", "LLM", "proxy protected", "production prevented", "composition prevented in production", "0.0.0.0"} {
		if strings.Contains(output, banned) {
			t.Errorf("banned %q", banned)
		}
	}
}
