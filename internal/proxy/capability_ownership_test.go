package proxy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

// Borrowed-authority fixture: tenant-A (calculator) and tenant-B
// (read_secret, internal_fetch) behind one routing layer, enforced by
// --client-id tenant-A.
func borrowedAuthorityYAML() string {
	return `
version: "1.0"
description: "Borrowed authority lab"
default_action: deny
servers:
  - name: "mcp-server-A"
    allowed: true
    tools:
      - name: "calculator"
        allowed: true
        risk: low
  - name: "mcp-server-B"
    allowed: true
    tools:
      - name: "read_secret"
        allowed: true
        risk: high
      - name: "internal_fetch"
        allowed: true
        risk: high
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
}

// TestCapabilityOwnershipCrossTenantDeniedBeforeRelay is the former RED
// gate test: with no ownership enforcement this forwarded; the gate must
// deny it before relay.
func TestCapabilityOwnershipCrossTenantDeniedBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	out := &bytes.Buffer{}
	p := New(Config{
		ServerName:   "mcp-server-B",
		SessionID:    "sess-borrowed-red",
		ClientID:     "tenant-A",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, borrowedAuthorityYAML()),
	})
	defer p.audit.Close()
	client := mcp.NewParser(nil, out)

	_, action := p.interceptAndModify(toolCallRaw(1, "read_secret", map[string]any{}), client)
	if action != "denied" {
		t.Fatalf("cross-tenant read_secret must deny before relay, got %s", action)
	}
	if !strings.Contains(out.String(), "capability ownership proof invalid") {
		t.Fatalf("denial must name the invalid proof, got %s", out.String())
	}
}

func TestCapabilityOwnershipDirectOwnerAllowed(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	out := &bytes.Buffer{}
	p := New(Config{
		ServerName:   "mcp-server-A",
		SessionID:    "sess-direct",
		ClientID:     "tenant-A",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, borrowedAuthorityYAML()),
	})
	defer p.audit.Close()
	client := mcp.NewParser(nil, out)

	if _, action := p.interceptAndModify(toolCallRaw(1, "calculator", map[string]any{}), client); action != "forward" {
		t.Fatalf("direct owner call must forward, got %s", action)
	}
}

func TestCapabilityOwnershipNarrowDelegationAllowed(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	out := &bytes.Buffer{}
	p := New(Config{
		ServerName:   "mcp-server-B",
		SessionID:    "sess-deleg",
		ClientID:     "tenant-A",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, borrowedAuthorityYAML()),
	})
	p.nowFunc = func() time.Time { return time.Date(2026, 9, 11, 10, 5, 0, 0, time.UTC) }
	defer p.audit.Close()
	client := mcp.NewParser(nil, out)

	out.Reset()
	if _, action := p.interceptAndModify(toolCallRaw(1, "internal_fetch", map[string]any{"resource": "X"}), client); action != "forward" {
		t.Fatalf("narrow delegation must forward, got %s; response=%s", action, out.String())
	}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"sibling tool", map[string]any{}},
		{"scope mismatch", map[string]any{"resource": "Y"}},
		{"missing scope", map[string]any{}},
	} {
		out.Reset()
		call := "internal_fetch"
		if tc.name == "sibling tool" {
			call = "read_secret"
		}
		if _, action := p.interceptAndModify(toolCallRaw(2, call, tc.args), client); action != "denied" {
			t.Fatalf("%s must deny, got %s", tc.name, action)
		}
	}
}

func TestCapabilityOwnershipAuditCarriesReceipt(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	out := &bytes.Buffer{}
	p := New(Config{
		ServerName:   "mcp-server-B",
		SessionID:    "sess-receipt",
		ClientID:     "tenant-A",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, borrowedAuthorityYAML()),
	})
	defer p.audit.Close()
	client := mcp.NewParser(nil, out)

	if _, action := p.interceptAndModify(toolCallRaw(1, "read_secret", map[string]any{}), client); action != "denied" {
		t.Fatalf("must deny, got %s", action)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.EventType == audit.EventToolDenied && ev.Tool == "read_secret" {
			found = true
			if ev.OwnershipReceiptHash == "" || ev.OwnershipReceipt == nil {
				t.Fatal("deny event must carry the ownership receipt")
			}
			if !strings.Contains(ev.Reason, "capability ownership proof invalid") {
				t.Fatalf("reason must name the invalid proof: %q", ev.Reason)
			}
		}
	}
	if !found {
		t.Fatal("no read_secret deny event in audit log")
	}
}
