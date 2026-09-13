//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCrossToolCorrelationDemo(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/tool-correlation")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("tool-correlation failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, frag := range []string{
		"Cross-Tool Correlation.",
		"fixture sample_size=8 seed=42042",
		"A  WITHOUT VISOR (per-tool limits viewed independently)",
		"hop use:github-search-1 mcp:github/search_code units=1 claimed ALLOW remaining=1",
		"hop use:drive-search-1 mcp:drive/search units=1 claimed ALLOW remaining=1",
		"hop use:notion-search-1 mcp:notion/search units=1 claimed ALLOW remaining=1",
		"hop use:github-read-1 mcp:github/get_file_contents units=1 claimed ALLOW remaining=1",
		"claimed_server_hop INNOCENT",
		"B  WITH VISOR (cross-server capability trajectory correlated)",
		"Correlation root ceilings=1 uses=4 edges=3",
		"Requested capability capability:repository-read total_units=4 ceiling_units=3",
		"Requested uses use:github-search-1@mcp:github/search_code>use:drive-search-1@mcp:drive/search>use:notion-search-1@mcp:notion/search>use:github-read-1@mcp:github/get_file_contents",
		"Claims per_tool_allow=true server_hop_innocent=true remaining_quota=1 authorized=true",
		"Authority graph=PRESENT trajectory=VALID capability=PRESENT ceiling=PRESENT usage=EXCEEDED correlation=INVALID",
		"Cross-Tool Correlation Proof INVALID",
		"reason correlated capability ceiling exceeded",
		"ACTION DENIED",
		"trajectory mcp:github/search_code>mcp:drive/search>mcp:notion/search>mcp:github/get_file_contents",
		"correlated_usage 4/3",
		"C  LEGITIMATE CONTRAST (same capability remains in ceiling)",
		"Requested capability capability:repository-read total_units=3 ceiling_units=3",
		"Requested uses use:github-search-1@mcp:github/search_code>use:drive-search-1@mcp:drive/search>use:notion-search-1@mcp:notion/search",
		"Claims per_tool_allow=false server_hop_innocent=false remaining_quota=0 authorized=false",
		"Authority graph=PRESENT trajectory=VALID capability=PRESENT ceiling=PRESENT usage=WITHIN correlation=VALID",
		"Cross-Tool Correlation Proof VALID",
		"reason authorized",
		"ACTION ALLOWED",
		"trajectory mcp:github/search_code>mcp:drive/search>mcp:notion/search",
		"correlated_usage 3/3",
		"result CALLBACK_FIRED",
		"result CALLBACK_NOT_FIRED",
		"false_correlation_formation 5/6",
		"propagation 3/6",
		"over_rejection 0/2",
		"measurement DETERMINISTIC",
		"rng NOT_USED",
		"tools_call NOT_PERFORMED",
	} {
		if !strings.Contains(output, frag) {
			t.Errorf("missing %q\n%s", frag, output)
		}
	}
	for _, banned := range []string{"HMAC", "receipt", "signature verified", "tools/call", "LLM", "proxy protected", "production prevented", "hopping prevented in production", "0.0.0.0"} {
		if strings.Contains(output, banned) {
			t.Errorf("banned %q", banned)
		}
	}
}
