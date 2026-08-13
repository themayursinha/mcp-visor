package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/serveridentity"
)

// RED-to-GREEN (Codex P2): installing the reload committer before identity
// hashing does not intercept a reload that ALREADY started and snapshotted a
// nil committer. Watcher.reload copies w.committer under RLock and releases
// the lock before publish; if that snapshot is nil, it publishes policy B
// directly and leaves redactor/audit patterns/approval timeout at generation A.
//
// This test holds an in-flight reload at a stall seam after the nil committer
// snapshot, then lets construction register the committer and enter identity
// hashing, then releases the reload to publish with the stale nil snapshot.
// Without a re-check/reconcile fix the mixed-generation runtime remains.
func TestReloadStartedBeforeCommitterRegistrationReconcilesRuntime(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")

	digestA := pinnedDigest("a")
	digestB := pinnedDigest("b")

	if err := os.WriteFile(policyPath, []byte(reloadIdentityPolicy(digestA, 30, "token_a", "TOKENA[0-9]+", "[REDACTED-A]")), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer w.Close()
	eng := policy.NewEngineWithWatcher(w)

	stallEntered := make(chan struct{}, 1)
	stallRelease := make(chan struct{})
	w.SetReloadStallForTest(func() {
		select {
		case stallEntered <- struct{}{}:
		default:
		}
		<-stallRelease
	})

	if err := os.WriteFile(policyPath, []byte(reloadIdentityPolicy(digestB, 7, "token_b", "TOKENB[0-9]+", "[REDACTED-B]")), 0o600); err != nil {
		t.Fatal(err)
	}

	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		w.Reload()
	}()

	// Reload has begun and (on the vulnerable path) already snapshotted a nil
	// committer; registration has not happened yet.
	select {
	case <-stallEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("reload stall was not entered")
	}

	resolver := &blockingResolver{
		entered:  make(chan struct{}, 1),
		release:  make(chan struct{}),
		resolved: serveridentity.Resolved{Kind: serveridentity.KindStdioInvocationSHA256V1, Digest: digestA},
	}

	done := make(chan *Proxy, 1)
	go func() {
		done <- New(Config{
			ServerName:      "it-support",
			SessionID:       "sess-reload-before-registration",
			ClientID:        "agent-identity",
			AuditLogPath:    auditPath,
			ApprovalDir:     approvalDir,
			Policy:          w.Policy(),
			Engine:          eng,
			ServerCommand:   "server-bin",
			ServerArgs:      []string{"server.js"},
			resolveIdentity: resolver.resolve,
		})
	}()

	// Constructor registered the committer and is hashing identity under the
	// still-published generation A snapshot.
	select {
	case <-resolver.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("identity resolver was not entered")
	}

	// Release the in-flight reload: vulnerable code publishes B directly with
	// the stale nil committer; fixed code re-checks and uses commitPolicyRuntime
	// (and/or reconciles after registration).
	close(stallRelease)

	select {
	case <-reloadDone:
	case <-time.After(3 * time.Second):
		t.Fatal("reload did not complete")
	}

	close(resolver.release)

	var p *Proxy
	select {
	case p = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("constructor did not complete")
	}
	defer p.audit.Close()

	if got := p.engine.Policy().Settings.ApprovalTimeoutSecs; got != 7 {
		t.Fatalf("engine policy must be generation B after pre-registration reload, got timeout %d", got)
	}

	red := p.currentRedactor()
	if out, res := red.RedactArgs(map[string]any{"secret": "TOKENB42"}); !res.Redacted || out["secret"] != "[REDACTED-B]" {
		t.Fatalf("redactor must correspond to generation B, got %+v %+v", out, res)
	}
	if out, res := red.RedactArgs(map[string]any{"secret": "TOKENA42"}); res.Redacted {
		t.Fatalf("redactor must not keep generation A patterns after pre-registration reload, got %+v %+v", out, res)
	}

	if got := p.currentApproval().Timeout(); got != 7*time.Second {
		t.Fatalf("approval timeout must correspond to generation B, got %v", got)
	}

	p.logAudit(audit.Event{
		EventType: audit.EventToolAllowed,
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
		Server:    "it-support",
		Tool:      "open_ticket",
		Reason:    "token TOKENB77",
	})
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "TOKENB77") {
		t.Fatalf("audit redaction patterns must correspond to generation B, log contains TOKENB77: %s", data)
	}

	if !p.identityResolved || p.resolvedIdentity.Digest != digestA {
		t.Fatalf("launch identity must be snapshot A, got %+v resolved=%v", p.resolvedIdentity, p.identityResolved)
	}
	if p.launchShape == nil || p.launchShape.kind != serveridentity.KindStdioInvocationSHA256V1 || len(p.launchShape.entry) != 1 || p.launchShape.entry[0] != 0 {
		t.Fatalf("launch shape must be snapshot A's shape [0], got %+v", p.launchShape)
	}

	if action, resp := restartCall(t, p, 1); action != "denied" {
		t.Fatalf("call under changed attestation contract must fail closed, got %q; response=%s", action, resp)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "open_ticket")
	if denied.ServerAttested == nil || *denied.ServerAttested {
		t.Fatalf("changed attestation contract must never attest the running process, got %+v", denied.ServerAttested)
	}
	if denied.ServerIdentityExpected != digestB {
		t.Fatalf("expected digest must be generation B on deny, got %q", denied.ServerIdentityExpected)
	}
	if denied.ServerIdentityResolved != digestA {
		t.Fatalf("resolved digest must stay the captured snapshot A on deny, got %q", denied.ServerIdentityResolved)
	}
	if !strings.Contains(denied.Reason, "restart") {
		t.Fatalf("changed-attestation deny must require restart, got reason %q", denied.Reason)
	}
}
