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
		taintNames  []string
		egressNames []string
	}{
		{path: filepath.Join("..", "..", "examples", "policies", "interop", "filesystem-sandbox.yaml"), defaultDeny: true, wantTools: 10, wantTaints: 1, wantEgress: 1,
			taintNames: []string{"sensitive_file_accessed"}, egressNames: []string{"block_egress_after_sensitive_read"}},
		{path: filepath.Join("..", "..", "examples", "policies", "interop", "fetch-egress.yaml"), defaultDeny: true, wantTools: 1, wantTaints: 1, wantEgress: 1,
			taintNames: []string{"sensitive_url_fetched"}, egressNames: []string{"block_fetch_after_sensitive_fetch"}},
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
		if c.taintNames != nil {
			for _, name := range c.taintNames {
				found := false
				for _, t := range pol.Taints {
					if t.Name == name {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s: missing taint %q", c.path, name)
				}
			}
		}
		if c.egressNames != nil {
			for _, name := range c.egressNames {
				found := false
				for _, e := range pol.EgressControls {
					if e.Name == name {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s: missing egress control %q", c.path, name)
				}
			}
		}
	}
}
