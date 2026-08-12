package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
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

// declaredEntryAttestationPolicy pins a digest and declares entry_arg_positions
// [0]: the first ServerArgs entry is the local entry payload whose content is
// part of the digest.
func declaredEntryAttestationPolicy(t *testing.T, digest string) *policy.Policy {
	t.Helper()
	return mustLoadPolicy(t, fmt.Sprintf(`version: "1.0"
default_action: deny
servers:
  - name: "it-support"
    allowed: true
    attestation:
      kind: "stdio_executable_sha256"
      digest: "%s"
      entry_arg_positions: [0]
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
`, digest))
}

// writeExecutableServer writes a direct executable launcher for proxy tests.
func writeExecutableServer(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server-bin")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'server'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// lastAuditEvent returns the MOST RECENT event matching type+tool, which is
// what a multi-call reload test needs (findAuditEvent returns the first).
func lastAuditEvent(t *testing.T, path string, eventType audit.EventType, tool string) audit.Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var found *audit.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal audit event: %v\n%s", err, line)
		}
		if ev.EventType == eventType && ev.Tool == tool {
			cp := ev
			found = &cp
		}
	}
	if found == nil {
		t.Fatalf("audit event not found: type=%s tool=%s log=%s", eventType, tool, string(data))
	}
	return *found
}

// must not change the digest and must not deny a pinned server; a declared
// entry payload mutation must still change the digest and deny. The pin is
// computed before the log exists; the proxy then resolves at construction
// after the log was created/populated. The vulnerable resolver hashes every
// regular-file argument, so the log changes the digest and the pinned server
// is falsely denied.
func TestServerIdentityUndeclaredRuntimeFileDoesNotChangeDigestAtProxy(t *testing.T) {
	launcher := writeExecutableServer(t)
	entry := filepath.Join(t.TempDir(), "server.js")
	if err := os.WriteFile(entry, []byte("serve stable"), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "server.log")

	// Pin before the log exists: declared entry position [0] only.
	pinRes, err := serveridentity.ResolveStdioInvocation(launcher, []string{entry, "-observe-log", logPath}, []int{0})
	if err != nil {
		t.Fatalf("resolve pin: %v", err)
	}

	// Create and populate the undeclared runtime log AFTER the pin.
	if err := os.WriteFile(logPath, []byte("request 1"), 0o600); err != nil {
		t.Fatal(err)
	}

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:    "it-support",
		SessionID:     "sess-identity-runtime-log",
		ClientID:      "agent-identity",
		AuditLogPath:  auditPath,
		Policy:        declaredEntryAttestationPolicy(t, pinRes.Digest),
		ServerCommand: launcher,
		ServerArgs:    []string{entry, "-observe-log", logPath},
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{"ticket_id": "T-1"}), client)
	if action != "forward" {
		t.Fatalf("P1: undeclared runtime log must not deny a pinned server, got %q; response=%s", action, out.String())
	}
	ev := findAuditEvent(t, auditPath, audit.EventToolAllowed, "open_ticket")
	if ev.ServerAttested == nil || !*ev.ServerAttested {
		t.Fatalf("P1: expected attested=true when undeclared log present, got %+v", ev.ServerAttested)
	}

	// Mutate the DECLARED entry: a fresh proxy with the same pin must deny.
	if err := os.WriteFile(entry, []byte("serve mutated"), 0o755); err != nil {
		t.Fatal(err)
	}
	auditPath2 := filepath.Join(t.TempDir(), "audit2.jsonl")
	p2 := New(Config{
		ServerName:    "it-support",
		SessionID:     "sess-identity-entry-mutated",
		ClientID:      "agent-identity",
		AuditLogPath:  auditPath2,
		Policy:        declaredEntryAttestationPolicy(t, pinRes.Digest),
		ServerCommand: launcher,
		ServerArgs:    []string{entry, "-observe-log", logPath},
	})
	defer p2.audit.Close()
	out2 := &bytes.Buffer{}
	client2 := mcp.NewParser(nil, out2)
	_, action2 := p2.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{"ticket_id": "T-2"}), client2)
	if action2 != "denied" {
		t.Fatalf("P1: declared entry mutation must deny against the old pin, got %q; response=%s", action2, out2.String())
	}
}

// P2 RED (round-4): a logical server with NO attestation performs zero
// identity-resolution work in BOTH constructors, even when ServerArgs contain
// a large sparse data file that the vulnerable resolver would stream. The
// unexported resolver seam counts calls; construction must not consult it.
func TestServerIdentityNoAttestationPerformsZeroResolverWork(t *testing.T) {
	constructors := []struct {
		name string
		fn   func(Config) *Proxy
	}{
		{"New", New},
		{"NewWithTracing", NewWithTracing},
	}
	for _, c := range constructors {
		t.Run(c.name, func(t *testing.T) {
			sparseDir := t.TempDir()
			sparsePath := filepath.Join(sparseDir, "dataset.bin")
			f, err := os.Create(sparsePath)
			if err != nil {
				t.Fatal(err)
			}
			// 1 GiB sparse file: no allocation, but reading it would be
			// observable and slow. Truncate, not Write.
			if err := f.Truncate(1 << 30); err != nil {
				f.Close()
				t.Fatal(err)
			}
			f.Close()

			calls := 0
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			p := c.fn(Config{
				ServerName:    "it-support",
				SessionID:     "sess-identity-zero-work",
				ClientID:      "agent-identity",
				AuditLogPath:  auditPath,
				ServerCommand: filepath.Join(sparseDir, "server-bin"),
				ServerArgs:    []string{"--data", sparsePath},
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
				resolveIdentity: func(command string, args []string, entryArgPositions []int) (serveridentity.Resolved, error) {
					calls++
					return serveridentity.Resolved{}, errors.New("resolver must not be called without an attestation pin")
				},
			})
			defer p.audit.Close()
			if calls != 0 {
				t.Fatalf("P2: unattested construction must perform zero resolver work, got %d calls", calls)
			}

			// Legacy allow/audit behavior and omitted identity verdict.
			out := &bytes.Buffer{}
			client := mcp.NewParser(nil, out)
			_, action := p.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{"ticket_id": "T-1"}), client)
			if action != "forward" {
				t.Fatalf("P2: legacy unattested allow must be preserved, got %q; response=%s", action, out.String())
			}
			ev := findAuditEvent(t, auditPath, audit.EventToolAllowed, "open_ticket")
			if ev.ServerAttested != nil {
				t.Fatalf("P2: legacy policy must omit attestation verdict, got %+v", ev.ServerAttested)
			}
			if ev.ServerIdentityKind != "" || ev.ServerIdentityExpected != "" || ev.ServerIdentityResolved != "" {
				t.Fatalf("P2: legacy policy must omit identity fields, got %+v", ev)
			}
		})
	}
}

// Reload RED (round-4): a hot reload that introduces a pin resolves it exactly
// once and publishes policy + identity atomically; removal clears the verdict;
// reintroduction resolves again. The resolver seam records call counts.
func TestServerIdentityReloadIntroducesPinAtomically(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")

	launcher := writeExecutableServer(t)
	entry := filepath.Join(t.TempDir(), "server.js")
	if err := os.WriteFile(entry, []byte("serve stable"), 0o755); err != nil {
		t.Fatal(err)
	}

	resolved := serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: pinnedDigest("a")}
	calls := 0
	seamErr := error(nil)

	write := func(yaml string) {
		t.Helper()
		if err := os.WriteFile(policyPath, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	noPinYAML := `version: "1.0"
default_action: deny
servers:
  - name: "it-support"
    allowed: true
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
`
	pinYAML := func(digest string) string {
		return fmt.Sprintf(`version: "1.0"
default_action: deny
servers:
  - name: "it-support"
    allowed: true
    attestation:
      kind: "stdio_executable_sha256"
      digest: "%s"
      entry_arg_positions: [0]
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
`, digest)
	}

	write(noPinYAML)
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer w.Close()
	eng := policy.NewEngineWithWatcher(w)
	p := New(Config{
		ServerName:    "it-support",
		SessionID:     "sess-identity-reload-pin",
		ClientID:      "agent-identity",
		AuditLogPath:  auditPath,
		Policy:        w.Policy(),
		Engine:        eng,
		ServerCommand: launcher,
		ServerArgs:    []string{entry, "-observe-log", filepath.Join(dir, "server.log")},
		resolveIdentity: func(command string, args []string, entryArgPositions []int) (serveridentity.Resolved, error) {
			calls++
			return resolved, seamErr
		},
	})
	defer p.audit.Close()

	call := func(id int) string {
		out := &bytes.Buffer{}
		client := mcp.NewParser(nil, out)
		_, action := p.interceptAndModify(toolCallRaw(id, "open_ticket", map[string]any{"ticket_id": fmt.Sprintf("T-%d", id)}), client)
		return action
	}

	// No-pin start: no resolver work, legacy verdict omitted.
	if calls != 0 {
		t.Fatalf("reload: no-pin start must do zero resolver work, got %d calls", calls)
	}
	if action := call(1); action != "forward" {
		t.Fatalf("reload: legacy no-pin call must forward, got %q", action)
	}

	// Introduce a valid pin: exactly one resolver call, next call forwards
	// with attested=true.
	write(pinYAML(pinnedDigest("a")))
	w.Reload()
	if calls != 1 {
		t.Fatalf("reload: pin introduction must resolve exactly once, got %d calls", calls)
	}
	if action := call(2); action != "forward" {
		t.Fatalf("reload: matched introduced pin must forward, got %q", action)
	}
	ev := lastAuditEvent(t, auditPath, audit.EventToolAllowed, "open_ticket")
	if ev.ServerAttested == nil || !*ev.ServerAttested {
		t.Fatalf("reload: introduced pin must emit attested=true, got %+v", ev.ServerAttested)
	}

	// Mismatched pin: resolver called again; deny uses the coherent new
	// policy snapshot (expected digest b, resolved digest a).
	write(pinYAML(pinnedDigest("b")))
	w.Reload()
	if action := call(3); action != "denied" {
		t.Fatalf("reload: mismatched pin must deny, got %q", action)
	}

	// Remove pin: verdict cleared, no extra resolver work.
	write(noPinYAML)
	w.Reload()
	before := calls
	if action := call(4); action != "forward" {
		t.Fatalf("reload: pin removal must restore legacy forward, got %q", action)
	}
	if calls != before {
		t.Fatalf("reload: pin removal must not call the resolver, got %d calls", calls)
	}
	ev2 := lastAuditEvent(t, auditPath, audit.EventToolAllowed, "open_ticket")
	if ev2.ServerAttested != nil {
		t.Fatalf("reload: pin removal must clear the attestation verdict, got %+v", ev2.ServerAttested)
	}

	// Reintroduce the pin: fresh resolver call, forward again.
	write(pinYAML(pinnedDigest("a")))
	w.Reload()
	if calls != before+1 {
		t.Fatalf("reload: pin reintroduction must resolve again, got %d calls", calls)
	}
	if action := call(5); action != "forward" {
		t.Fatalf("reload: reintroduced matched pin must forward, got %q", action)
	}
}

// Reload RED failure subcase: a resolver error during introduction publishes
// the configured pin with unresolved identity and the next tools/call fails
// closed before argument policy or relay.
func TestServerIdentityReloadResolverErrorFailsClosed(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")

	launcher := writeExecutableServer(t)
	entry := filepath.Join(t.TempDir(), "server.js")
	if err := os.WriteFile(entry, []byte("serve stable"), 0o755); err != nil {
		t.Fatal(err)
	}

	seamErr := errors.New("deterministic resolution failure")
	calls := 0
	pinYAML := fmt.Sprintf(`version: "1.0"
default_action: deny
servers:
  - name: "it-support"
    allowed: true
    attestation:
      kind: "stdio_executable_sha256"
      digest: "%s"
      entry_arg_positions: [0]
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
`, pinnedDigest("a"))
	if err := os.WriteFile(policyPath, []byte(pinYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer w.Close()
	eng := policy.NewEngineWithWatcher(w)
	p := New(Config{
		ServerName:    "it-support",
		SessionID:     "sess-identity-reload-fail",
		ClientID:      "agent-identity",
		AuditLogPath:  auditPath,
		Policy:        w.Policy(),
		Engine:        eng,
		ServerCommand: launcher,
		ServerArgs:    []string{entry},
		resolveIdentity: func(command string, args []string, entryArgPositions []int) (serveridentity.Resolved, error) {
			calls++
			return serveridentity.Resolved{}, seamErr
		},
	})
	defer p.audit.Close()

	if calls != 1 {
		t.Fatalf("reload-fail: initial pinned policy must attempt resolution once, got %d calls", calls)
	}
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{"ticket_id": "T-1"}), client)
	if action != "denied" {
		t.Fatalf("reload-fail: resolution failure must fail closed, got %q; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "server identity attestation failed") {
		t.Fatalf("reload-fail: expected attestation failure reason, got %s", out.String())
	}
	ev := findAuditEvent(t, auditPath, audit.EventToolDenied, "open_ticket")
	if ev.ServerAttested == nil || *ev.ServerAttested {
		t.Fatalf("reload-fail: expected attested=false on unresolved identity, got %+v", ev.ServerAttested)
	}
}
