package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/serveridentity"
)

// attestationLimitPolicy pins a matching identity and sets a runtime limit so
// the identity gate passes but a LATER terminal gate denies.
func attestationLimitPolicy(t *testing.T, digest string, maxTools int) *policy.Policy {
	t.Helper()
	return mustLoadPolicy(t, fmt.Sprintf(`version: "1.0"
default_action: deny
settings:
  session_max_tools: %d
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
`, maxTools, digest))
}

// P2 RED: a runtime-limit deny AFTER a matched identity gate must carry the
// attestation evidence (kind, expected, resolved, attested=true) on the
// terminal deny event. Codex P2: terminal denials from runtime limits omit
// server_attested and both digests.
func TestServerIdentityAttachedOnRuntimeLimitDeny(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:       "it-support",
		SessionID:        "sess-identity-rt-limit",
		ClientID:         "agent-identity",
		AuditLogPath:     auditPath,
		Policy:           attestationLimitPolicy(t, pinnedDigest("a"), 1),
		ResolvedIdentity: &serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: pinnedDigest("a")},
	})
	defer p.audit.Close()

	call := func(id int) string {
		out := &bytes.Buffer{}
		client := mcp.NewParser(nil, out)
		_, action := p.interceptAndModify(toolCallRaw(id, "open_ticket", map[string]any{"ticket_id": fmt.Sprintf("T-%d", id)}), client)
		return action
	}

	// Pre-record one call so the next interception hits session_max_tools=1
	// (matches the proven pattern in runtime_hardening_test.go).
	p.session.RecordToolCall("it-support", mcp.ToolsCallRequest{Name: "open_ticket", Arguments: json.RawMessage(`{}`)}, "")
	if action := call(1); action != "denied" {
		t.Fatalf("expected runtime-limit deny after pre-record, got %q", action)
	}

	ev := findAuditEvent(t, auditPath, audit.EventToolDenied, "open_ticket")
	if ev.ServerAttested == nil || !*ev.ServerAttested {
		t.Fatalf("P2: runtime-limit deny must carry attested=true, got %+v", ev.ServerAttested)
	}
	if ev.ServerIdentityKind != "stdio_executable_sha256" {
		t.Fatalf("P2: expected identity kind on runtime-limit deny, got %+v", ev)
	}
	if ev.ServerIdentityExpected != pinnedDigest("a") {
		t.Fatalf("P2: expected configured digest on runtime-limit deny, got %+v", ev)
	}
	if ev.ServerIdentityResolved != pinnedDigest("a") {
		t.Fatalf("P2: expected resolved digest on runtime-limit deny, got %+v", ev)
	}
}

// P2 RED: a sensitive-path deny AFTER a matched identity gate must carry the
// attestation evidence on the terminal deny event.
func TestServerIdentityAttachedOnSensitivePathDeny(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	dir := t.TempDir()
	sensitivePath := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(sensitivePath, []byte("TOKEN=sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New(Config{
		ServerName:   "it-support",
		SessionID:    "sess-identity-sensitive",
		ClientID:     "agent-identity",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, fmt.Sprintf(`version: "1.0"
default_action: deny
redaction:
  sensitive_files:
    - "**/secrets.env"
servers:
  - name: "it-support"
    allowed: true
    attestation:
      kind: "stdio_executable_sha256"
      digest: "%s"
    tools:
      - name: "read_file"
        allowed: true
        risk: medium
`, pinnedDigest("a"))),
		ResolvedIdentity: &serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: pinnedDigest("a")},
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "read_file", map[string]any{"path": sensitivePath}), client)
	if action != "denied" {
		t.Fatalf("expected sensitive-path deny, got %q; response=%s", action, out.String())
	}

	ev := findAuditEvent(t, auditPath, audit.EventToolDenied, "read_file")
	if ev.ServerAttested == nil || !*ev.ServerAttested {
		t.Fatalf("P2: sensitive-path deny must carry attested=true, got %+v", ev.ServerAttested)
	}
	if ev.ServerIdentityKind != "stdio_executable_sha256" || ev.ServerIdentityExpected != pinnedDigest("a") || ev.ServerIdentityResolved != pinnedDigest("a") {
		t.Fatalf("P2: expected identity evidence on sensitive-path deny, got %+v", ev)
	}
}
