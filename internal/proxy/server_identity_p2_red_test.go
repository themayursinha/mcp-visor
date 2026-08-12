package proxy

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/serveridentity"
	"github.com/themayursinha/mcp-visor/internal/signer"
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

// blockingFailingSigner implements signer.Signer with a deterministic
// blocking failure: Sign signals entry, blocks until released, then returns
// a fixed error. The remaining interface methods delegate to a real Ed25519
// signer so the receipt path sees a genuine public key and key ID.
type blockingFailingSigner struct {
	inner   signer.Signer
	entered chan struct{}
	release chan struct{}
}

func (s *blockingFailingSigner) Sign(data []byte) ([]byte, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.release
	return nil, errors.New("deterministic signing failure")
}

func (s *blockingFailingSigner) PublicKey() crypto.PublicKey { return s.inner.PublicKey() }
func (s *blockingFailingSigner) KeyID() string               { return s.inner.KeyID() }
func (s *blockingFailingSigner) Algorithm() string           { return s.inner.Algorithm() }

// P2 RED (round-5): a post-approval receipt signing failure happens AFTER the
// runtime barrier is released, so the terminal deny must attach identity from
// the complete policy+identity SNAPSHOT that authorized the call, not the
// live policy or live resolved identity after a reload. The resolver seam
// returns digest A at construction and digest B after the reload so the live
// identity ACTUALLY changes (a fixed Config.ResolvedIdentity would mask the
// bug because the vulnerable reload re-resolves to the same fixed value).
// Codex P2: reloading from digest A to B while the failing signer blocks must
// not make the deny report expected B / resolved B / attested=false.
func TestServerIdentityApprovalSigningFailureUsesPolicySnapshot(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	approvalDir := filepath.Join(dir, "approvals")
	auditPath := filepath.Join(dir, "audit.jsonl")

	digestA := pinnedDigest("a")
	digestB := pinnedDigest("b")

	policyYAML := func(digest string) string {
		return fmt.Sprintf(`version: "1.0"
default_action: deny
settings:
  approval_timeout_seconds: 10
servers:
  - name: "it-support"
    allowed: true
    attestation:
      kind: "stdio_executable_sha256"
      digest: "%s"
    tools:
      - name: "open_ticket"
        allowed: true
        approval_required: true
`, digest)
	}

	if err := os.WriteFile(policyPath, []byte(policyYAML(digestA)), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer w.Close()

	inner, err := signer.NewApprovalSigner()
	if err != nil {
		t.Fatalf("real signer: %v", err)
	}
	failing := &blockingFailingSigner{inner: inner, entered: make(chan struct{}, 1), release: make(chan struct{})}

	seam := &restartBoundSeam{
		resolvedA: serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestA},
		resolvedB: serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestB},
	}
	p := New(Config{
		ServerName:      "it-support",
		SessionID:       "sess-approval-snapshot",
		ClientID:        "agent-identity",
		AuditLogPath:    auditPath,
		Policy:          w.Policy(),
		Engine:          policy.NewEngineWithWatcher(w),
		ServerCommand:   writeExecutableServer(t),
		ApprovalDir:     approvalDir,
		ApprovalSigner:  failing,
		resolveIdentity: seam.resolve,
	})
	defer p.audit.Close()
	if calls := seam.count(); calls != 1 {
		t.Fatalf("pinned launch must resolve exactly once, got %d calls", calls)
	}

	// Operator goroutine: approve the request as soon as it appears.
	requestSeen := make(chan struct{})
	go func() {
		for {
			matches, _ := filepath.Glob(filepath.Join(approvalDir, "req-*.json"))
			if len(matches) > 0 {
				id := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
				_ = os.WriteFile(filepath.Join(approvalDir, id+".ok"), []byte{}, 0o600)
				close(requestSeen)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	callDone := make(chan string, 1)
	go func() {
		out := &bytes.Buffer{}
		client := mcp.NewParser(nil, out)
		_, action := p.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{"ticket_id": "T-1"}), client)
		callDone <- action
	}()

	select {
	case <-requestSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("approval request was not created")
	}

	// Wait until the failing signer reports that receipt signing has begun.
	// This guarantees approval succeeded and the call is past receipt creation.
	select {
	case <-failing.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("signer was not invoked after approval")
	}

	// Reload policy B while the signer is blocked: the live engine now
	// expects digest B, and the seam would resolve B if reloaded. The call
	// was authorized under snapshot A and its terminal deny must stay A.
	if err := os.WriteFile(policyPath, []byte(policyYAML(digestB)), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()

	// Release the signer so it returns its deterministic error and the call
	// terminates denied.
	close(failing.release)

	select {
	case action := <-callDone:
		if action != "denied" {
			t.Fatalf("expected denied after signing failure, got %q", action)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("call did not terminate after signing failure")
	}

	ev := findAuditEvent(t, auditPath, audit.EventToolDenied, "open_ticket")
	if ev.ServerIdentityKind != "stdio_executable_sha256" {
		t.Fatalf("P2: expected snapshot identity kind on signing-failure deny, got %+v", ev)
	}
	if ev.ServerIdentityExpected != digestA {
		t.Fatalf("P2: expected snapshot digest A on signing-failure deny, got %q", ev.ServerIdentityExpected)
	}
	if ev.ServerIdentityResolved != digestA {
		t.Fatalf("P2: expected resolved digest A on signing-failure deny, got %q", ev.ServerIdentityResolved)
	}
	if ev.ServerAttested == nil || !*ev.ServerAttested {
		t.Fatalf("P2: expected attested=true from snapshot A on signing-failure deny, got %+v", ev.ServerAttested)
	}
	if !strings.Contains(ev.Reason, "approval receipt signing failed") {
		t.Fatalf("P2: expected signing-failure reason on deny, got %q", ev.Reason)
	}
	if ev.ServerIdentityExpected == digestB || ev.ServerIdentityResolved == digestB {
		t.Fatalf("P2: deny must not carry reloaded digest B: %+v", ev)
	}
}

// blockingSuccessSigner implements signer.Signer with a deterministic
// blocking success: Sign signals entry, blocks until released, then delegates
// to a real Ed25519 signer so approval ultimately SUCCEEDS (the allow-path
// counterpart to blockingFailingSigner).
type blockingSuccessSigner struct {
	inner   signer.Signer
	entered chan struct{}
	release chan struct{}
}

func (s *blockingSuccessSigner) Sign(data []byte) ([]byte, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.release
	return s.inner.Sign(data)
}

func (s *blockingSuccessSigner) PublicKey() crypto.PublicKey { return s.inner.PublicKey() }
func (s *blockingSuccessSigner) KeyID() string               { return s.inner.KeyID() }
func (s *blockingSuccessSigner) Algorithm() string           { return s.inner.Algorithm() }

// P2 RED (round-5): an APPROVED allow after the runtime barrier is released
// must attach identity from the COMPLETE policy+identity snapshot captured
// before the barrier, never from live resolved identity after a reload. The
// resolver seam returns digest A at construction and digest B after the
// reload. Codex P2: reloading A→B while approval is pending must not make the
// terminal allow report resolved B or attested=false.
func TestServerIdentityApprovalAllowUsesIdentitySnapshot(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	approvalDir := filepath.Join(dir, "approvals")
	auditPath := filepath.Join(dir, "audit.jsonl")

	digestA := pinnedDigest("a")
	digestB := pinnedDigest("b")

	policyYAML := func(digest string) string {
		return fmt.Sprintf(`version: "1.0"
default_action: deny
settings:
  approval_timeout_seconds: 10
servers:
  - name: "it-support"
    allowed: true
    attestation:
      kind: "stdio_executable_sha256"
      digest: "%s"
    tools:
      - name: "open_ticket"
        allowed: true
        approval_required: true
`, digest)
	}

	if err := os.WriteFile(policyPath, []byte(policyYAML(digestA)), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer w.Close()

	inner, err := signer.NewApprovalSigner()
	if err != nil {
		t.Fatalf("real signer: %v", err)
	}
	blocking := &blockingSuccessSigner{inner: inner, entered: make(chan struct{}, 1), release: make(chan struct{})}

	seam := &restartBoundSeam{
		resolvedA: serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestA},
		resolvedB: serveridentity.Resolved{Kind: serveridentity.KindStdioExecutableSHA256, Digest: digestB},
	}
	p := New(Config{
		ServerName:      "it-support",
		SessionID:       "sess-approval-allow-snapshot",
		ClientID:        "agent-identity",
		AuditLogPath:    auditPath,
		Policy:          w.Policy(),
		Engine:          policy.NewEngineWithWatcher(w),
		ServerCommand:   writeExecutableServer(t),
		ApprovalDir:     approvalDir,
		ApprovalSigner:  blocking,
		resolveIdentity: seam.resolve,
	})
	defer p.audit.Close()
	if calls := seam.count(); calls != 1 {
		t.Fatalf("pinned launch must resolve exactly once, got %d calls", calls)
	}

	// Operator goroutine: approve the request as soon as it appears.
	requestSeen := make(chan struct{})
	go func() {
		for {
			matches, _ := filepath.Glob(filepath.Join(approvalDir, "req-*.json"))
			if len(matches) > 0 {
				id := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
				_ = os.WriteFile(filepath.Join(approvalDir, id+".ok"), []byte{}, 0o600)
				close(requestSeen)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	callDone := make(chan string, 1)
	go func() {
		out := &bytes.Buffer{}
		client := mcp.NewParser(nil, out)
		_, action := p.interceptAndModify(toolCallRaw(1, "open_ticket", map[string]any{"ticket_id": "T-1"}), client)
		callDone <- action
	}()

	select {
	case <-requestSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("approval request was not created")
	}

	// Wait until the blocking signer reports that receipt signing has begun:
	// approval has succeeded and the call is past the runtime barrier.
	select {
	case <-blocking.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("signer was not invoked after approval")
	}

	// Reload A→B while the approval is in flight. The runtime barrier was
	// released before the approval wait, so this must not stall; the
	// terminal allow event must still use snapshot A's identity evidence.
	if err := os.WriteFile(policyPath, []byte(policyYAML(digestB)), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()

	// Release the signer so approval succeeds and the terminal ALLOW event
	// is written.
	close(blocking.release)

	select {
	case action := <-callDone:
		if action != "forward" {
			t.Fatalf("expected forward after approved+reload, got %q", action)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("call did not terminate after signer release")
	}

	ev := findAuditEvent(t, auditPath, audit.EventToolAllowed, "open_ticket")
	if ev.ServerIdentityKind != "stdio_executable_sha256" {
		t.Fatalf("P2: expected snapshot identity kind on approval allow, got %+v", ev)
	}
	if ev.ServerIdentityExpected != digestA {
		t.Fatalf("P2: expected snapshot expected digest A on approval allow, got %q", ev.ServerIdentityExpected)
	}
	if ev.ServerIdentityResolved != digestA {
		t.Fatalf("P2: expected snapshot resolved digest A on approval allow, got %q", ev.ServerIdentityResolved)
	}
	if ev.ServerAttested == nil || !*ev.ServerAttested {
		t.Fatalf("P2: expected snapshot attested=true on approval allow, got %+v", ev.ServerAttested)
	}
	if ev.ServerIdentityExpected == digestB || ev.ServerIdentityResolved == digestB {
		t.Fatalf("P2: approval allow must not carry reloaded digest B: %+v", ev)
	}
}
