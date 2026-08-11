package proxy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/serveridentity"
)

func pinnedDigest(hexDigit string) string {
	return "sha256:" + strings.Repeat(hexDigit, 64)
}

func attestationPolicy(t *testing.T, digest string) *policy.Policy {
	t.Helper()
	return mustLoadPolicy(t, fmt.Sprintf(`version: "1.0"
default_action: deny
servers:
  - name: "it-support"
    allowed: true
    attestation:
      kind: "stdio_executable_sha256"
      digest: "%s"
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
`, digest))
}

func TestServerIdentityMismatchDeniesBeforeArgumentPolicy(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:       "it-support",
		SessionID:        "sess-identity-mismatch",
		ClientID:         "agent-identity",
		AuditLogPath:     auditPath,
		Policy:           attestationPolicy(t, pinnedDigest("a")),
		ResolvedIdentity: &serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: pinnedDigest("b")},
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{
		"ticket_id": "T-42",
		"note":      "would be redacted or policy-evaluated by a later gate",
	}), client)
	if action != "denied" {
		t.Fatalf("expected identity mismatch to deny before argument policy, got %q; response=%s", action, out.String())
	}
	if resp := out.String(); !strings.Contains(resp, "server identity attestation failed") {
		t.Fatalf("expected attestation failure reason in response, got %s", resp)
	}

	ev := findAuditEvent(t, auditPath, audit.EventToolDenied, "open_ticket")
	if ev.Server != "it-support" {
		t.Fatalf("expected logical server in deny event, got %+v", ev)
	}
	if ev.Decision != "deny" {
		t.Fatalf("expected deny decision, got %+v", ev)
	}
	if ev.ServerIdentityKind != "stdio_executable_sha256" {
		t.Fatalf("expected identity kind, got %+v", ev)
	}
	if ev.ServerIdentityExpected != pinnedDigest("a") {
		t.Fatalf("expected configured digest in deny event, got %+v", ev)
	}
	if ev.ServerIdentityResolved != pinnedDigest("b") {
		t.Fatalf("expected resolved digest in deny event, got %+v", ev)
	}
	if ev.ServerAttested == nil || *ev.ServerAttested {
		t.Fatalf("expected attested=false in deny event, got %+v", ev.ServerAttested)
	}
	if ev.Arguments != nil {
		t.Fatalf("identity denial event must omit arguments, got %+v", ev.Arguments)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "T-42") || strings.Contains(string(data), "would be redacted") {
		t.Fatalf("argument data leaked into identity denial event: %s", data)
	}
}

func TestServerIdentityMatchAllowsToolCall(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:       "it-support",
		SessionID:        "sess-identity-match",
		ClientID:         "agent-identity",
		AuditLogPath:     auditPath,
		Policy:           attestationPolicy(t, pinnedDigest("a")),
		ResolvedIdentity: &serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: pinnedDigest("a")},
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{"ticket_id": "T-1"}), client)
	if action != "forward" {
		t.Fatalf("expected matching identity to allow, got %q; response=%s", action, out.String())
	}

	ev := findAuditEvent(t, auditPath, audit.EventToolAllowed, "open_ticket")
	if ev.Decision != "allow" {
		t.Fatalf("expected allow decision, got %+v", ev)
	}
	if ev.ServerAttested == nil || !*ev.ServerAttested {
		t.Fatalf("expected attested=true in allow event, got %+v", ev.ServerAttested)
	}
	if ev.ServerIdentityExpected != pinnedDigest("a") {
		t.Fatalf("expected configured digest in allow event, got %+v", ev)
	}
	if ev.ServerIdentityResolved != pinnedDigest("a") {
		t.Fatalf("expected resolved digest in allow event, got %+v", ev)
	}
}

func TestServerIdentityConfiguredButUnresolvedFailsClosed(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "it-support",
		SessionID:    "sess-identity-unresolved",
		ClientID:     "agent-identity",
		AuditLogPath: auditPath,
		Policy:       attestationPolicy(t, pinnedDigest("a")),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{"ticket_id": "T-9"}), client)
	if action != "denied" {
		t.Fatalf("expected configured-but-unresolved attestation to fail closed, got %q; response=%s", action, out.String())
	}
	ev := findAuditEvent(t, auditPath, audit.EventToolDenied, "open_ticket")
	if ev.ServerAttested == nil || *ev.ServerAttested {
		t.Fatalf("expected attested=false when unresolved, got %+v", ev.ServerAttested)
	}
	if ev.ServerIdentityResolved != "" {
		t.Fatalf("unresolved identity must omit resolved digest, got %+v", ev)
	}
}

func TestServerIdentityAbsentPreservesLegacyBehaviorAndOmitsVerdict(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "it-support",
		SessionID:    "sess-identity-legacy",
		ClientID:     "agent-identity",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `version: "1.0"
default_action: deny
servers:
  - name: "it-support"
    allowed: true
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
`),
		ResolvedIdentity: &serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: pinnedDigest("a")},
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{"ticket_id": "T-1"}), client)
	if action != "forward" {
		t.Fatalf("legacy policy without attestation must preserve allow behavior, got %q; response=%s", action, out.String())
	}
	ev := findAuditEvent(t, auditPath, audit.EventToolAllowed, "open_ticket")
	if ev.ServerAttested != nil {
		t.Fatalf("legacy policy must omit attestation verdict, got %+v", ev.ServerAttested)
	}
	if ev.ServerIdentityKind != "" || ev.ServerIdentityExpected != "" || ev.ServerIdentityResolved != "" {
		t.Fatalf("legacy policy must omit identity fields, got %+v", ev)
	}
}

func TestServerIdentityUsesCurrentPolicyAfterHotReload(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	resolved := serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: pinnedDigest("a")}

	initial := fmt.Sprintf(`version: "1.0"
default_action: deny
servers:
  - name: "it-support"
    allowed: true
    attestation:
      kind: "stdio_executable_sha256"
      digest: "%s"
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
`, pinnedDigest("a"))
	if err := os.WriteFile(policyPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer w.Close()
	eng := policy.NewEngineWithWatcher(w)
	p := New(Config{
		ServerName:       "it-support",
		SessionID:        "sess-identity-reload",
		ClientID:         "agent-identity",
		AuditLogPath:     auditPath,
		Policy:           w.Policy(),
		Engine:           eng,
		ResolvedIdentity: &resolved,
	})
	defer p.audit.Close()

	call := func(id int) string {
		out := &bytes.Buffer{}
		client := mcp.NewParser(nil, out)
		_, action := p.interceptAndModify(toolCallRaw(id, "open_ticket", map[string]any{"ticket_id": fmt.Sprintf("T-%d", id)}), client)
		return action
	}

	if action := call(1); action != "forward" {
		t.Fatalf("matching digest should allow before reload, got %q", action)
	}

	updated := fmt.Sprintf(`version: "1.0"
default_action: deny
servers:
  - name: "it-support"
    allowed: true
    attestation:
      kind: "stdio_executable_sha256"
      digest: "%s"
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
`, pinnedDigest("b"))
	if err := os.WriteFile(policyPath, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	if action := call(2); action != "denied" {
		t.Fatalf("reload mismatch should deny, got %q", action)
	}

	if err := os.WriteFile(policyPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	if action := call(3); action != "forward" {
		t.Fatalf("reload back to matching digest should allow, got %q", action)
	}
}
