package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

// legacyInvocationDigest reproduces the pre-repair resolver framing for a
// launcher with literal non-file args: SHA-256 over the launcher artifact
// bytes followed by each 0x00-separated literal arg. It proves the vulnerable
// resolver would have matched this pin even though a dynamic registry package
// spec does not content-bind the artifact that will execute.
func legacyInvocationDigest(t *testing.T, launcher string, args []string) string {
	t.Helper()
	h := sha256.New()
	f, err := os.Open(launcher)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	for _, arg := range args {
		h.Write([]byte{0x00})
		h.Write([]byte(arg))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
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

// P1 RED: a configured attestation for a dynamic registry launcher (npx) must
// fail closed even when the literal package spec matches the old digest. The
// vulnerable resolver returned a digest for the literal spec, so this call
// would have been attested=true and relayed; the repair must deny before
// relay with server_attested=false, no resolved digest, and no argument leak.
func TestServerIdentityUnpinnableRegistryLauncherFailsClosed(t *testing.T) {
	launcher := filepath.Join(t.TempDir(), "npx")
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\nprintf 'npx launcher'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec := "@example/mcp-server@1.0.0"
	pin := legacyInvocationDigest(t, launcher, []string{spec})

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:    "it-support",
		SessionID:     "sess-identity-unpinnable",
		ClientID:      "agent-identity",
		AuditLogPath:  auditPath,
		Policy:        attestationPolicy(t, pin),
		ServerCommand: launcher,
		ServerArgs:    []string{spec},
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{"ticket_id": "T-60"}), client)
	if action != "denied" {
		t.Fatalf("P1: attested npx package-spec invocation must fail closed before relay, got %q; response=%s", action, out.String())
	}

	ev := findAuditEvent(t, auditPath, audit.EventToolDenied, "open_ticket")
	if ev.ServerAttested == nil || *ev.ServerAttested {
		t.Fatalf("P1: expected attested=false for unpinnable launcher, got %+v", ev.ServerAttested)
	}
	if ev.ServerIdentityKind != "stdio_executable_sha256" {
		t.Fatalf("expected identity kind, got %+v", ev)
	}
	if ev.ServerIdentityExpected != pin {
		t.Fatalf("expected configured digest in deny event, got %+v", ev)
	}
	if ev.ServerIdentityResolved != "" {
		t.Fatalf("unpinnable launcher must omit resolved digest, got %+v", ev)
	}
	if ev.Arguments != nil {
		t.Fatalf("identity denial event must omit arguments, got %+v", ev.Arguments)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "T-60") || strings.Contains(string(data), spec) {
		t.Fatalf("argument data leaked into identity denial event: %s", data)
	}
}

// P1 RED: every documented canonical registry-runner form must fail closed
// before relay when an attestation is configured, even when the configured
// pin matches the vulnerable legacy launcher+literal-argv digest. The
// vulnerable resolver returned that digest for the unrecognized forms (npm x,
// yarn dlx, pnpm dlx, bunx, bun x, uv tool run, pnpx, pnx), so those calls
// were attested=true and relayed; the repair must deny with attested=false,
// no resolved digest, no argument/package leak, and never forward.
func TestServerIdentityDocumentedRegistryRunnersFailClosed(t *testing.T) {
	tests := []struct {
		name     string
		launcher string
		args     []string
		spec     string
	}{
		{"npx", "npx", []string{"@example/npx-server@1.0.0"}, "@example/npx-server@1.0.0"},
		{"uvx", "uvx", []string{"uvx-server==1.0.0"}, "uvx-server==1.0.0"},
		{"npm exec", "npm", []string{"exec", "--", "@example/npm-exec-server@1.0.0"}, "@example/npm-exec-server@1.0.0"},
		{"npm x", "npm", []string{"x", "@example/npm-x-server@1.0.0"}, "@example/npm-x-server@1.0.0"},
		{"yarn dlx", "yarn", []string{"dlx", "@example/yarn-dlx-server@1.0.0"}, "@example/yarn-dlx-server@1.0.0"},
		{"pnpm dlx", "pnpm", []string{"dlx", "@example/pnpm-dlx-server@1.0.0"}, "@example/pnpm-dlx-server@1.0.0"},
		{"bunx", "bunx", []string{"@example/bunx-server@1.0.0"}, "@example/bunx-server@1.0.0"},
		{"bun x", "bun", []string{"x", "@example/bun-x-server@1.0.0"}, "@example/bun-x-server@1.0.0"},
		{"uv tool run", "uv", []string{"tool", "run", "uv-tool-run-server==1.0.0"}, "uv-tool-run-server==1.0.0"},
		{"pnpx", "pnpx", []string{"@example/pnpx-server@1.0.0"}, "@example/pnpx-server@1.0.0"},
		{"pnx", "pnx", []string{"@example/pnx-server@1.0.0"}, "@example/pnx-server@1.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launcher := filepath.Join(t.TempDir(), tt.launcher)
			if err := os.WriteFile(launcher, []byte("#!/bin/sh\nprintf 'registry launcher'\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			pin := legacyInvocationDigest(t, launcher, tt.args)
			marker := fmt.Sprintf("SECRET-%s", tt.name)

			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			p := New(Config{
				ServerName:    "it-support",
				SessionID:     "sess-identity-doc-runners-" + tt.name,
				ClientID:      "agent-identity",
				AuditLogPath:  auditPath,
				Policy:        attestationPolicy(t, pin),
				ServerCommand: launcher,
				ServerArgs:    tt.args,
			})
			defer p.audit.Close()

			out := &bytes.Buffer{}
			client := mcp.NewParser(nil, out)
			_, action := p.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{"ticket_id": marker}), client)
			if action == "forward" {
				t.Fatalf("P1: %s registry-runner invocation must fail closed before relay, got forward", tt.name)
			}
			if action != "denied" {
				t.Fatalf("P1: expected denied action, got %q; response=%s", action, out.String())
			}

			ev := findAuditEvent(t, auditPath, audit.EventToolDenied, "open_ticket")
			if ev.ServerAttested == nil || *ev.ServerAttested {
				t.Fatalf("P1: expected attested=false for %s, got %+v", tt.name, ev.ServerAttested)
			}
			if ev.ServerIdentityKind != "stdio_executable_sha256" {
				t.Fatalf("expected identity kind, got %+v", ev)
			}
			if ev.ServerIdentityExpected != pin {
				t.Fatalf("expected configured digest in deny event, got %+v", ev)
			}
			if ev.ServerIdentityResolved != "" {
				t.Fatalf("unpinnable launcher must omit resolved digest, got %+v", ev)
			}
			if ev.Arguments != nil {
				t.Fatalf("identity denial event must omit arguments, got %+v", ev.Arguments)
			}
			data, err := os.ReadFile(auditPath)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), marker) || strings.Contains(string(data), tt.spec) {
				t.Fatalf("argument/package data leaked into identity denial event: %s", data)
			}
			var denies int
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				var ev audit.Event
				if err := json.Unmarshal([]byte(line), &ev); err != nil {
					t.Fatalf("unmarshal audit event: %v\n%s", err, line)
				}
				if ev.EventType == audit.EventToolDenied && ev.Tool == "open_ticket" {
					denies++
				}
			}
			if denies != 1 {
				t.Fatalf("expected one terminal deny event, got %d", denies)
			}
		})
	}
}
