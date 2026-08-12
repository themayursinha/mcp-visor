package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// restartCall intercepts one tools/call against the proxy and returns the
// action plus the raw client response (for reason assertions).
func restartCall(t *testing.T, p *Proxy, id int) (string, string) {
	t.Helper()
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(id, "open_ticket", map[string]any{"ticket_id": fmt.Sprintf("T-%d", id)}), client)
	return action, out.String()
}

// restartBoundSeam returns resolvedA on the FIRST resolver invocation
// (proxy construction) and resolvedB on every later invocation, modelling a
// replacement launcher/payload artifact appearing on disk while the proxy
// (and its launched stdio child) keeps running. The call count and the
// current digest are mutex-protected so -race is clean when the watcher
// goroutine and the test goroutine both reach the seam.
type restartBoundSeam struct {
	mu        sync.Mutex
	calls     int
	resolvedA serveridentity.Resolved
	resolvedB serveridentity.Resolved
}

func (s *restartBoundSeam) resolve(command string, args []string, entryArgPositions []int) (serveridentity.Resolved, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls == 1 {
		return s.resolvedA, nil
	}
	return s.resolvedB, nil
}

func (s *restartBoundSeam) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func restartPinYAML(digest string, positions string) string {
	if positions == "" {
		positions = "[0]"
	}
	return fmt.Sprintf(`version: "1.0"
default_action: deny
servers:
  - name: "it-support"
    allowed: true
    attestation:
      kind: "stdio_executable_sha256"
      digest: "%s"
      entry_arg_positions: %s
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
`, digest, positions)
}

func restartNoPinYAML() string {
	return `version: "1.0"
default_action: deny
servers:
  - name: "it-support"
    allowed: true
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
`
}

// P1 RED (round-5): a running process launched as artifact A must never
// become attested after the executable/payload on disk is replaced with B and
// the policy is reloaded to B's pin. The resolver is invoked exactly once (at
// construction); the deny carries expected=B, resolved=A, attested=false,
// restart-required reason, and no arguments.
func TestServerIdentityReloadDoesNotReResolveRunningProcess(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")

	digestA := pinnedDigest("a")
	digestB := pinnedDigest("b")
	seam := &restartBoundSeam{
		resolvedA: serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestA},
		resolvedB: serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestB},
	}

	if err := os.WriteFile(policyPath, []byte(restartPinYAML(digestA, "[0]")), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer w.Close()
	eng := policy.NewEngineWithWatcher(w)
	p := New(Config{
		ServerName:      "it-support",
		SessionID:       "sess-identity-replace",
		ClientID:        "agent-identity",
		AuditLogPath:    auditPath,
		Policy:          w.Policy(),
		Engine:          eng,
		ServerCommand:   writeExecutableServer(t),
		ServerArgs:      []string{filepath.Join(dir, "server.js")},
		resolveIdentity: seam.resolve,
	})
	defer p.audit.Close()
	if calls := seam.count(); calls != 1 {
		t.Fatalf("launch must resolve identity exactly once, got %d calls", calls)
	}
	if action, _ := restartCall(t, p, 1); action != "forward" {
		t.Fatalf("launched artifact A must forward against pin A, got %q", action)
	}

	// Reload the policy to B's pin while the proxy (and its logical server
	// process) is still running. The still-running process launched as A
	// must NOT become attested: identity is not re-resolved, so B's pin
	// cannot be satisfied by the captured A identity.
	if err := os.WriteFile(policyPath, []byte(restartPinYAML(digestB, "[0]")), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	if calls := seam.count(); calls != 1 {
		t.Fatalf("reload after artifact replacement must not re-resolve identity, got %d calls", calls)
	}
	if action, resp := restartCall(t, p, 2); action != "denied" {
		t.Fatalf("replaced artifact must NOT make the running process attested, got %q; response=%s", action, resp)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "open_ticket")
	if denied.ServerIdentityExpected != digestB {
		t.Fatalf("expected=B on replacement deny, got %q", denied.ServerIdentityExpected)
	}
	if denied.ServerIdentityResolved != digestA {
		t.Fatalf("resolved must stay the captured launch digest A, got %q", denied.ServerIdentityResolved)
	}
	if denied.ServerAttested == nil || *denied.ServerAttested {
		t.Fatalf("replacement must never attest the running process, got %+v", denied.ServerAttested)
	}
	if !strings.Contains(denied.Reason, "restart") {
		t.Fatalf("replacement deny must require a restart, got reason %q", denied.Reason)
	}
	if len(denied.Arguments) != 0 {
		t.Fatalf("identity-gate deny must not leak arguments, got %+v", denied.Arguments)
	}
}

// P1 RED (round-5): introducing a pin AFTER an unattested launch fails closed
// for tools/call and reports that a server restart is required. The running
// server is never retroactively hashed and attested; the resolver is never
// invoked by the reload. Removing the pin restores the explicitly requested
// unattested legacy path; reintroducing a pin on an originally unattested
// process stays unresolved and denied.
func TestServerIdentityPinIntroAfterLaunchFailsClosedRequiresRestart(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")

	digestA := pinnedDigest("a")
	seam := &restartBoundSeam{
		resolvedA: serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestA},
		resolvedB: serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestA},
	}

	if err := os.WriteFile(policyPath, []byte(restartNoPinYAML()), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer w.Close()
	eng := policy.NewEngineWithWatcher(w)
	p := New(Config{
		ServerName:      "it-support",
		SessionID:       "sess-identity-intro-pin",
		ClientID:        "agent-identity",
		AuditLogPath:    auditPath,
		Policy:          w.Policy(),
		Engine:          eng,
		ServerCommand:   writeExecutableServer(t),
		ServerArgs:      []string{filepath.Join(dir, "server.js")},
		resolveIdentity: seam.resolve,
	})
	defer p.audit.Close()
	if calls := seam.count(); calls != 0 {
		t.Fatalf("unattested launch must perform zero resolver work, got %d calls", calls)
	}
	if action, _ := restartCall(t, p, 1); action != "forward" {
		t.Fatalf("legacy unattested call must forward, got %q", action)
	}

	// Introduce a pin for the CURRENT artifact while the unattested server
	// keeps running: no identity was captured, so the next call fails closed
	// and reports a restart requirement. The resolver is never invoked.
	if err := os.WriteFile(policyPath, []byte(restartPinYAML(digestA, "[0]")), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	if calls := seam.count(); calls != 0 {
		t.Fatalf("pin introduction must not resolve on reload, got %d calls", calls)
	}
	if action, resp := restartCall(t, p, 2); action != "denied" {
		t.Fatalf("introduced pin without captured identity must fail closed, got %q; response=%s", action, resp)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "open_ticket")
	if denied.ServerIdentityExpected != digestA {
		t.Fatalf("expected introduced pin digest on deny, got %q", denied.ServerIdentityExpected)
	}
	if denied.ServerIdentityResolved != "" {
		t.Fatalf("no captured identity must omit resolved digest, got %q", denied.ServerIdentityResolved)
	}
	if denied.ServerAttested == nil || *denied.ServerAttested {
		t.Fatalf("introduced pin must not attest the running server, got %+v", denied.ServerAttested)
	}
	if !strings.Contains(denied.Reason, "restart") {
		t.Fatalf("introduced-pin deny must require a restart, got reason %q", denied.Reason)
	}
	if len(denied.Arguments) != 0 {
		t.Fatalf("identity-gate deny must not leak arguments, got %+v", denied.Arguments)
	}

	// Ordinary policy reload without attestation still applies.
	if err := os.WriteFile(policyPath, []byte(restartNoPinYAML()), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	if calls := seam.count(); calls != 0 {
		t.Fatalf("no-pin reload must not call the resolver, got %d calls", calls)
	}
	if action, _ := restartCall(t, p, 3); action != "forward" {
		t.Fatalf("removed pin must restore explicit unattested forward, got %q", action)
	}
	allowed := lastAuditEvent(t, auditPath, audit.EventToolAllowed, "open_ticket")
	if allowed.ServerAttested != nil {
		t.Fatalf("removed pin must omit the attestation verdict, got %+v", allowed.ServerAttested)
	}

	// Reintroducing a pin after an originally unattested start remains
	// unresolved and denied: the launched process has no startup contract.
	if err := os.WriteFile(policyPath, []byte(restartPinYAML(digestA, "[0]")), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	if calls := seam.count(); calls != 0 {
		t.Fatalf("pin reintroduction must not resolve on reload, got %d calls", calls)
	}
	if action, resp := restartCall(t, p, 4); action != "denied" {
		t.Fatalf("reintroduced pin on originally unattested process must stay denied, got %q; response=%s", action, resp)
	}
}

// P1 RED (round-5): a changed resolution shape cannot reuse the cached launch
// digest even when the expected digest string is equal. The deny reports an
// incompatible startup resolution contract. Equivalent normalized position
// sets ([0,2] and [2,0]) remain the same shape and stay attested.
func TestServerIdentityChangedShapeCannotReuseOldDigest(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")

	digestA := pinnedDigest("a")
	seam := &restartBoundSeam{
		resolvedA: serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestA},
		resolvedB: serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestA},
	}

	// Construct with positions [0]: digest A is bound to shape (kind, [0]).
	if err := os.WriteFile(policyPath, []byte(restartPinYAML(digestA, "[0]")), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer w.Close()
	eng := policy.NewEngineWithWatcher(w)
	p := New(Config{
		ServerName:      "it-support",
		SessionID:       "sess-identity-shape",
		ClientID:        "agent-identity",
		AuditLogPath:    auditPath,
		Policy:          w.Policy(),
		Engine:          eng,
		ServerCommand:   writeExecutableServer(t),
		ServerArgs:      []string{filepath.Join(dir, "server.js"), filepath.Join(dir, "extra.js")},
		resolveIdentity: seam.resolve,
	})
	defer p.audit.Close()
	if calls := seam.count(); calls != 1 {
		t.Fatalf("pinned launch must resolve exactly once, got %d calls", calls)
	}
	if action, _ := restartCall(t, p, 1); action != "forward" {
		t.Fatalf("launch shape [0] with digest A must forward, got %q", action)
	}

	// Reload a VALID policy with positions [1] but the SAME expected digest
	// A. The cached digest was produced under shape [0]; shape [1] measures
	// different bytes, so it must NOT reuse digest A and must fail closed.
	if err := os.WriteFile(policyPath, []byte(restartPinYAML(digestA, "[1]")), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	if action, resp := restartCall(t, p, 2); action != "denied" {
		t.Fatalf("changed shape must not reuse the old digest, got %q; response=%s", action, resp)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "open_ticket")
	if denied.ServerAttested == nil || *denied.ServerAttested {
		t.Fatalf("changed shape must not attest, got %+v", denied.ServerAttested)
	}
	if !strings.Contains(denied.Reason, "shape") && !strings.Contains(denied.Reason, "restart") {
		t.Fatalf("changed-shape deny must report incompatible contract / restart, got reason %q", denied.Reason)
	}
	if len(denied.Arguments) != 0 {
		t.Fatalf("identity-gate deny must not leak arguments, got %+v", denied.Arguments)
	}
}

// P1 compatibility control: equivalent normalized position sets ([0,2] and
// [2,0]) are the SAME resolution shape, so a reload between them keeps the
// launch identity and stays attested.
func TestServerIdentityShapeNormalizedOrderCompatibility(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")

	digestA := pinnedDigest("a")
	seam := &restartBoundSeam{
		resolvedA: serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestA},
		resolvedB: serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestA},
	}

	if err := os.WriteFile(policyPath, []byte(restartPinYAML(digestA, "[0,2]")), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer w.Close()
	eng := policy.NewEngineWithWatcher(w)
	p := New(Config{
		ServerName:      "it-support",
		SessionID:       "sess-identity-shape-normalize",
		ClientID:        "agent-identity",
		AuditLogPath:    auditPath,
		Policy:          w.Policy(),
		Engine:          eng,
		ServerCommand:   writeExecutableServer(t),
		ServerArgs:      []string{filepath.Join(dir, "s0.js"), filepath.Join(dir, "s1.js"), filepath.Join(dir, "s2.js")},
		resolveIdentity: seam.resolve,
	})
	defer p.audit.Close()
	if calls := seam.count(); calls != 1 {
		t.Fatalf("pinned launch must resolve exactly once, got %d calls", calls)
	}
	if action, _ := restartCall(t, p, 1); action != "forward" {
		t.Fatalf("launch shape [0,2] with digest A must forward, got %q", action)
	}

	// Reload with the same positions in a different YAML order: the
	// normalized contract is identical, so identity is preserved and the
	// call stays attested.
	if err := os.WriteFile(policyPath, []byte(restartPinYAML(digestA, "[2,0]")), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	if calls := seam.count(); calls != 1 {
		t.Fatalf("same-shape reload must not re-resolve identity, got %d calls", calls)
	}
	if action, resp := restartCall(t, p, 2); action != "forward" {
		t.Fatalf("normalized-order reload must keep the launch identity, got %q; response=%s", action, resp)
	}
	allowed := lastAuditEvent(t, auditPath, audit.EventToolAllowed, "open_ticket")
	if allowed.ServerAttested == nil || !*allowed.ServerAttested || allowed.ServerIdentityExpected != digestA || allowed.ServerIdentityResolved != digestA {
		t.Fatalf("normalized-order reload must keep attested=true with digest A, got %+v", allowed)
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

// P1 RED (round-6): the launch digest and its launch shape (attestation kind
// plus normalized entry_arg_positions) must derive from ONE policy snapshot.
// A reload that publishes policy B while the resolver is hashing must not
// relabel a digest measured under A with B's shape, even when the expected
// digest string is identical. The resolver seam asserts it receives A's
// positions [0], synchronously publishes B (positions [1], same digest D),
// and returns digest D; the vulnerable double policy read then labels D with
// B's shape and forwards/attests. The fixed code keeps A's shape so the call
// under B fails closed with a restart-required reason and no arguments.
func TestServerIdentityLaunchDigestAndShapeUseSinglePolicySnapshot(t *testing.T) {
	digestD := pinnedDigest("d")

	policyA := mustLoadPolicy(t, fmt.Sprintf(`version: "1.0"
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
`, digestD))

	policyB := mustLoadPolicy(t, fmt.Sprintf(`version: "1.0"
default_action: deny
servers:
  - name: "it-support"
    allowed: true
    attestation:
      kind: "stdio_executable_sha256"
      digest: "%s"
      entry_arg_positions: [1]
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
`, digestD))

	eng := policy.NewEngine(policyA)

	resolveCalls := 0
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:    "it-support",
		SessionID:     "sess-identity-single-snapshot",
		ClientID:      "agent-identity",
		AuditLogPath:  auditPath,
		Policy:        policyA,
		Engine:        eng,
		ServerCommand: writeExecutableServer(t),
		ServerArgs:    []string{filepath.Join(t.TempDir(), "s0.js"), filepath.Join(t.TempDir(), "s1.js")},
		resolveIdentity: func(command string, args []string, entryArgPositions []int) (serveridentity.Resolved, error) {
			resolveCalls++
			if len(entryArgPositions) != 1 || entryArgPositions[0] != 0 {
				t.Fatalf("resolver must measure the digest under policy A positions [0], got %v", entryArgPositions)
			}
			// Deterministic interleaving: publish B between digest
			// measurement and launch-shape construction.
			eng.Reload(policyB)
			return serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestD}, nil
		},
	})
	defer p.audit.Close()

	if resolveCalls != 1 {
		t.Fatalf("pinned launch must resolve exactly once, got %d calls", resolveCalls)
	}
	if cur := eng.Policy(); cur != policyB {
		t.Fatalf("current engine policy after construction must be B, got %p", cur)
	}
	// The launch-time resolved identity retains the digest D measured under
	// policy A; the cached evidence stays coherent and never pairs that
	// digest with B's measurement contract.
	if p.resolvedIdentity.Digest != digestD {
		t.Fatalf("launch-time resolved digest must stay D, got %q", p.resolvedIdentity.Digest)
	}

	// Under B (same expected digest D but positions [1]), the cached launch
	// evidence must stay coherent: the digest was measured under A ([0]), so
	// B's shape cannot reuse digest D and the ordinary allowed call must
	// fail closed before relay.
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{"ticket_id": "T-1"}), client)
	if action != "denied" {
		t.Fatalf("digest measured under A must not be relabeled with B's shape, got %q; response=%s", action, out.String())
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "open_ticket")
	if denied.ServerIdentityExpected != digestD {
		t.Fatalf("expected digest D on deny, got %q", denied.ServerIdentityExpected)
	}
	// Round-5 terminal-evidence semantics: a shape-mismatch deny omits the
	// resolved digest because the cached digest was measured under a
	// different contract and is not comparable to the current pin. Recording
	// it here would itself pair the A-measured digest with B's pin, the
	// exact class of confusion this P1 prevents.
	if denied.ServerIdentityResolved != "" {
		t.Fatalf("shape-mismatch deny must omit the non-comparable resolved digest, got %q", denied.ServerIdentityResolved)
	}
	if denied.ServerAttested == nil || *denied.ServerAttested {
		t.Fatalf("B's shape must never attest the A-measured digest, got %+v", denied.ServerAttested)
	}
	if !strings.Contains(denied.Reason, "shape") || !strings.Contains(denied.Reason, "restart") {
		t.Fatalf("deny must report the changed shape / restart requirement, got reason %q", denied.Reason)
	}
	if len(denied.Arguments) != 0 {
		t.Fatalf("identity-gate deny must not leak arguments, got %+v", denied.Arguments)
	}
}
