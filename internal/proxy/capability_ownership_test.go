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
	"github.com/themayursinha/mcp-visor/internal/receipt"
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
	p.setNowFunc(func() time.Time { return time.Date(2026, 9, 11, 10, 5, 0, 0, time.UTC) })
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

func TestCapabilityOwnershipUndeclaredToolDeniedUnderPermissiveDefault(t *testing.T) {
	// Under default_action: allow, a tool with no declaration on a listed
	// endpoint must fail closed, not bypass ownership.
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	out := &bytes.Buffer{}
	p := New(Config{
		ServerName:   "mcp-server-B",
		SessionID:    "sess-permissive",
		ClientID:     "tenant-A",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: allow
servers:
  - name: "mcp-server-B"
    allowed: true
    tools: []
capability_ownership:
  endpoints:
    - server: mcp-server-B
      owner: tenant-B
      capabilities:
        - tool: read_secret
          effect_class: CREDENTIAL
`),
	})
	p.setNowFunc(func() time.Time { return time.Date(2026, 9, 11, 10, 5, 0, 0, time.UTC) })
	defer p.audit.Close()
	client := mcp.NewParser(nil, out)

	if _, action := p.interceptAndModify(toolCallRaw(1, "read_secret", map[string]any{}), client); action != "denied" {
		t.Fatalf("declared tool without grant must deny, got %s", action)
	}
	out.Reset()
	if _, action := p.interceptAndModify(toolCallRaw(2, "brand_new_tool", map[string]any{}), client); action != "denied" {
		t.Fatalf("undeclared tool on owned endpoint must fail closed, got %s", action)
	}
	if !strings.Contains(out.String(), "capability ownership proof invalid") {
		t.Fatalf("denial must name the invalid proof, got %s", out.String())
	}
}

func TestCapabilityOwnershipGrantRecheckedAfterApproval(t *testing.T) {
	// Grant valid at request time, expired mid-wait: the grant-site recheck
	// must deny with a fresh expired verdict, never the stale pre-wait allow.
	dir := t.TempDir()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	out := &bytes.Buffer{}
	p := New(Config{
		ServerName:   "mcp-server-B",
		SessionID:    "sess-expiry-race",
		ClientID:     "tenant-A",
		AuditLogPath: auditPath,
		ApprovalDir:  dir,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "mcp-server-B"
    allowed: true
    tools:
      - name: "internal_fetch"
        allowed: true
        approval_required: true
capability_ownership:
  endpoints:
    - server: mcp-server-B
      owner: tenant-B
      capabilities:
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
`),
	})
	inWindow := time.Date(2026, 9, 11, 10, 5, 0, 0, time.UTC)
	p.setNowFunc(func() time.Time { return inWindow })
	defer p.audit.Close()
	client := mcp.NewParser(nil, out)

	done := make(chan string, 1)
	go func() {
		_, action := p.interceptAndModify(toolCallRaw(1, "internal_fetch", map[string]any{"resource": "X"}), client)
		done <- action
	}()
	// Wait for the approval request, lapse the grant, then approve.
	deadline := time.Now().Add(30 * time.Second)
	for {
		matches, _ := filepath.Glob(filepath.Join(dir, "req-*.json"))
		if len(matches) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("approval request never appeared")
		}
		time.Sleep(25 * time.Millisecond)
	}
	p.setNowFunc(func() time.Time { return time.Date(2026, 9, 11, 10, 16, 0, 0, time.UTC) })
	matches, _ := filepath.Glob(filepath.Join(dir, "req-*.json"))
	base := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
	if err := os.WriteFile(filepath.Join(dir, base+".ok"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case action := <-done:
		if action != "denied" {
			t.Fatalf("lapsed grant must deny at grant site, got %s", action)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("call never resolved")
	}
	if !strings.Contains(out.String(), "expired") {
		t.Fatalf("denial must record expiry, got %s", out.String())
	}
}

func TestCapabilityOwnershipEmptyEndpointFailsClosed(t *testing.T) {
	// Listed endpoint with zero capabilities: any tool there denies.
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	out := &bytes.Buffer{}
	p := New(Config{
		ServerName:   "mcp-server-B",
		SessionID:    "sess-empty-ep",
		ClientID:     "tenant-A",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: allow
servers:
  - name: "mcp-server-B"
    allowed: true
    tools: []
capability_ownership:
  endpoints:
    - server: mcp-server-B
      owner: tenant-B
      capabilities: []
`),
	})
	p.setNowFunc(func() time.Time { return time.Date(2026, 9, 11, 10, 5, 0, 0, time.UTC) })
	defer p.audit.Close()
	client := mcp.NewParser(nil, out)

	if _, action := p.interceptAndModify(toolCallRaw(1, "read_secret", map[string]any{}), client); action != "denied" {
		t.Fatalf("tool on empty owned endpoint must fail closed, got %s", action)
	}
}

func TestCapabilityOwnershipScopeMatchedPreRedaction(t *testing.T) {
	// The granted scope value matches a built-in redaction pattern
	// (internal IP): the grant must match the ORIGINAL argument, not the
	// redacted placeholder.
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	out := &bytes.Buffer{}
	p := New(Config{
		ServerName:   "mcp-server-B",
		SessionID:    "sess-redact-scope",
		ClientID:     "tenant-A",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "mcp-server-B"
    allowed: true
    tools:
      - name: "internal_fetch"
        allowed: true
capability_ownership:
  endpoints:
    - server: mcp-server-B
      owner: tenant-B
      capabilities:
        - tool: internal_fetch
          effect_class: NETWORK
          scope_argument: resource
  delegations:
    - id: b-to-a-fetch-ip
      owner: tenant-B
      delegate: tenant-A
      server: mcp-server-B
      tool: internal_fetch
      effect_class: NETWORK
      resource_scope:
        argument: resource
        exact_values: ["10.0.0.1"]
      issued_at: "2026-09-11T10:00:00Z"
      expires_at: "2026-09-11T10:15:00Z"
`),
	})
	p.setNowFunc(func() time.Time { return time.Date(2026, 9, 11, 10, 5, 0, 0, time.UTC) })
	defer p.audit.Close()
	client := mcp.NewParser(nil, out)

	if _, action := p.interceptAndModify(toolCallRaw(1, "internal_fetch", map[string]any{"resource": "10.0.0.1"}), client); action != "forward" {
		t.Fatalf("exact grant on redaction-shaped value must forward, got %s; response=%s", action, out.String())
	}
}

func TestOwnershipReceiptNanosSurviveEmbed(t *testing.T) {
	// Unix-nano integers exceed float64 exact range: the embedded bytes
	// must equal the signed bytes exactly, and re-parsing must verify.
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec := &receipt.CapabilityOwnershipReceipt{
		Schema: "capability_ownership_v1", Requester: "tenant-A",
		Server: "mcp-server-B", Tool: "internal_fetch", Owner: "tenant-B",
		EffectClass: "NETWORK", Status: receipt.OwnershipStatusMatched,
		Verdict:     "allow",
		EvaluatedAt: time.Date(2026, 9, 11, 10, 15, 0, 500000000, time.UTC).UnixNano(),
	}
	if err := rec.Sign(kp); err != nil {
		t.Fatal(err)
	}
	signed, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ev := audit.Event{EventType: audit.EventToolAllowed}
	attachOwnershipReceipt(&ev, rec)
	if ev.OwnershipReceiptHash == "" || ev.OwnershipReceipt == nil {
		t.Fatal("receipt not attached")
	}
	if !bytes.Equal([]byte(ev.OwnershipReceipt), signed) {
		t.Fatal("embedded bytes differ from signed bytes")
	}
	rt, err := receipt.UnmarshalOwnershipReceipt(ev.OwnershipReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if rt.EvaluatedAt != rec.EvaluatedAt {
		t.Fatalf("nanos mangled: %d != %d", rt.EvaluatedAt, rec.EvaluatedAt)
	}
	if err := rt.Verify(kp.PublicKey); err != nil {
		t.Fatalf("embedded receipt fails verify: %v", err)
	}
}
