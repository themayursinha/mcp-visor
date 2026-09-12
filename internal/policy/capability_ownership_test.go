package policy

import (
	"strings"
	"testing"
)

const ownershipBaseYAML = `
version: "1.0"
default_action: deny
servers:
  - name: "mcp-server-A"
    allowed: true
    tools:
      - name: "calculator"
        allowed: true
  - name: "mcp-server-B"
    allowed: true
    tools:
      - name: "read_secret"
        allowed: true
      - name: "internal_fetch"
        allowed: true
capability_ownership:
  endpoints:
    - server: mcp-server-A
      owner: tenant-A
      capabilities:
        - tool: calculator
          effect_class: COMPUTE
    - server: mcp-server-B
      owner: tenant-B
      capabilities:
        - tool: read_secret
          effect_class: CREDENTIAL
        - tool: internal_fetch
          effect_class: NETWORK
          scope_argument: resource
  delegations:
    - id: b-to-a-fetch-x
      owner: tenant-B
      delegate: tenant-A
      server: mcp-server-B
      tool: internal_fetch
      effect_class: NETWORK
      resource_scope:
        argument: resource
        exact_values: ["X"]
      issued_at: "2026-09-11T10:00:00Z"
      expires_at: "2026-09-11T10:15:00Z"
`

func TestLoadCapabilityOwnershipValid(t *testing.T) {
	p, err := Load([]byte(ownershipBaseYAML))
	if err != nil {
		t.Fatalf("valid ownership policy rejected: %v", err)
	}
	if p.CapabilityOwnership == nil || len(p.CapabilityOwnership.Endpoints) != 2 {
		t.Fatalf("ownership block not loaded: %+v", p.CapabilityOwnership)
	}
}

func TestLoadCapabilityOwnershipAbsent(t *testing.T) {
	p, err := Load([]byte(`
version: "1.0"
default_action: deny
servers:
  - name: "s"
    allowed: true
    tools:
      - name: "t"
        allowed: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if p.CapabilityOwnership != nil {
		t.Fatal("absent block must stay nil (zero delta)")
	}
}

func TestLoadCapabilityOwnershipViolations(t *testing.T) {
	cases := []struct {
		name string
		from string
		to   string
		want string
	}{
		{"duplicate endpoint", "      capabilities:\n        - tool: calculator\n          effect_class: COMPUTE", "      capabilities:\n        - tool: calculator\n          effect_class: COMPUTE\n    - server: mcp-server-A\n      owner: tenant-A\n      capabilities:\n        - tool: calculator\n          effect_class: COMPUTE", "duplicate endpoint"},
		{"owner mismatch", "owner: tenant-B\n      delegate: tenant-A", "owner: tenant-X\n      delegate: tenant-A", "is not the endpoint owner"},
		{"expiry inversion", "expires_at: \"2026-09-11T10:15:00Z\"", "expires_at: \"2026-09-11T09:00:00Z\"", "must be after issued_at"},
		{"malformed timestamp", "issued_at: \"2026-09-11T10:00:00Z\"", "issued_at: \"yesterday\"", "malformed issued_at"},
	}
	for _, tc := range cases {
		doc := strings.Replace(ownershipBaseYAML, tc.from, tc.to, 1)
		if _, err := Load([]byte(doc)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", tc.name, tc.want, err)
		}
	}
	// Incomplete declaration: drop read_secret from the endpoint while the
	// tool stays allowed.
	doc := strings.Replace(ownershipBaseYAML, "        - tool: read_secret\n          effect_class: CREDENTIAL\n", "", 1)
	if _, err := Load([]byte(doc)); err == nil || !strings.Contains(err.Error(), "lacks a capability declaration") {
		t.Errorf("incomplete: got %v", err)
	}
}
