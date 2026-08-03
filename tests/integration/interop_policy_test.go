//go:build interop

package main_test

import (
	"path/filepath"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/policy"
)

// TestInteropPoliciesLoad verifies every interop example policy parses with the
// real loader and carries the expected enforcement shape.
func TestInteropPoliciesLoad(t *testing.T) {
	cases := []struct {
		path        string
		defaultDeny bool
		wantTools   int
		wantTaints  int
		wantEgress  int
	}{
		{path: filepath.Join("..", "..", "examples", "policies", "interop", "filesystem-sandbox.yaml"), defaultDeny: true, wantTools: 10, wantTaints: 1, wantEgress: 1},
		{path: filepath.Join("..", "..", "examples", "policies", "interop", "fetch-egress.yaml"), defaultDeny: true, wantTools: 1, wantTaints: 1, wantEgress: 1},
		{path: filepath.Join("..", "..", "examples", "policies", "interop", "remote-mock.yaml"), defaultDeny: true, wantTools: 2, wantTaints: 0, wantEgress: 0},
	}
	for _, c := range cases {
		pol, err := policy.LoadFile(c.path)
		if err != nil {
			t.Fatalf("load %s: %v", c.path, err)
		}
		if (pol.DefaultAction == policy.ActionDeny) != c.defaultDeny {
			t.Errorf("%s: default_action deny = %v, want %v", c.path, pol.DefaultAction == policy.ActionDeny, c.defaultDeny)
		}
		var tools int
		for _, s := range pol.Servers {
			tools += len(s.Tools)
		}
		if tools != c.wantTools {
			t.Errorf("%s: tools = %d, want %d", c.path, tools, c.wantTools)
		}
		if len(pol.Taints) != c.wantTaints {
			t.Errorf("%s: taints = %d, want %d", c.path, len(pol.Taints), c.wantTaints)
		}
		if len(pol.EgressControls) != c.wantEgress {
			t.Errorf("%s: egress controls = %d, want %d", c.path, len(pol.EgressControls), c.wantEgress)
		}
	}
}
