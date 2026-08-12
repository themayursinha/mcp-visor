package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/serveridentity"
)

// blockingResolver signals that the identity resolver has been entered, then
// blocks synchronously until released, then returns the configured resolved
// identity. It models the slow identity hashing window inside
// resolveLaunchedIdentity without sleeps: the test controls exactly when the
// resolver is blocked and when it completes.
type blockingResolver struct {
	entered  chan struct{}
	release  chan struct{}
	resolved serveridentity.Resolved
}

func (s *blockingResolver) resolve(command string, args []string, entryArgPositions []int) (serveridentity.Resolved, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.release
	return s.resolved, nil
}

// reloadIdentityPolicy pins digest with entry_arg_positions [0] and a single
// tool, plus a redaction pattern that differs per generation so the test can
// observe which generation's redactor/audit patterns are live.
func reloadIdentityPolicy(digest string, timeoutSecs int, patternName, patternRegex, replacement string) string {
	return fmt.Sprintf(`version: "1.0"
default_action: deny
settings:
  approval_timeout_seconds: %d
servers:
  - name: "it-support"
    allowed: true
    attestation:
      kind: "stdio_invocation_sha256_v1"
      digest: "%s"
      entry_arg_positions: [0]
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
redaction:
  patterns:
    - name: "%s"
      regex: "%s"
      replacement: "%s"
`, timeoutSecs, digest, patternName, patternRegex, replacement)
}

// RED-to-GREEN (round 8, Codex P2): both constructors previously called
// resolveLaunchedIdentity(cfg) BEFORE wirePolicyReload(). resolveLaunchedIdentity
// can stream the executable and declared entry payloads; until
// wirePolicyReload() installs the atomic commitPolicyRuntime transaction, a
// watcher reload that lands during identity hashing publishes the new policy
// directly and leaves the redactor, approval timeout, and audit redaction
// patterns at the OLD generation. This test:
//
//  1. starts policy A current,
//  2. begins construction (wirePolicyReload must already be installed before
//     the resolver is entered on the fixed code),
//  3. blocks the identity resolver,
//  4. publishes policy B through the watcher/reload path,
//  5. unblocks the resolver, lets construction complete,
//  6. asserts engine policy, redactor, approval timeout, and audit redaction
//     patterns all correspond to generation B,
//  7. asserts the launch identity and launch shape still derive coherently
//     from the ONE policy snapshot (A) captured by the launch resolver,
//  8. asserts a tools/call under B's changed attestation contract fails
//     closed with a restart requirement (never attested).
//
// It must FAIL on 7199382 (where the reload transaction is wired after
// identity hashing) and PASS after the fix.
func TestReloadTransactionInstalledBeforeIdentityHashing(t *testing.T) {
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

	resolver := &blockingResolver{
		entered:  make(chan struct{}, 1),
		release:  make(chan struct{}),
		resolved: serveridentity.Resolved{Kind: serveridentity.KindStdioInvocationSHA256V1, Digest: digestA},
	}

	done := make(chan *Proxy, 1)
	go func() {
		done <- New(Config{
			ServerName:      "it-support",
			SessionID:       "sess-reload-before-identity",
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

	// The resolver is entered: identity hashing is in progress. On the FIXED
	// code wirePolicyReload already ran before resolveLaunchedIdentity, so the
	// reload committer is installed; on the vulnerable tip it is not.
	select {
	case <-resolver.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("identity resolver was not entered")
	}

	// Publish policy B through the watcher while the resolver is blocked.
	if err := os.WriteFile(policyPath, []byte(reloadIdentityPolicy(digestB, 7, "token_b", "TOKENB[0-9]+", "[REDACTED-B]")), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()

	// Unblock the resolver; construction completes.
	close(resolver.release)

	var p *Proxy
	select {
	case p = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("constructor did not complete")
	}
	defer p.audit.Close()

	// 6a. Engine policy must be generation B.
	if got := p.engine.Policy().Settings.ApprovalTimeoutSecs; got != 7 {
		t.Fatalf("engine policy must be generation B after reload during hashing, got timeout %d", got)
	}

	// 6b. Redactor must correspond to B (B pattern active, A pattern gone).
	red := p.currentRedactor()
	if out, res := red.RedactArgs(map[string]any{"secret": "TOKENB42"}); !res.Redacted || out["secret"] != "[REDACTED-B]" {
		t.Fatalf("redactor must correspond to generation B, got %+v %+v", out, res)
	}
	if out, res := red.RedactArgs(map[string]any{"secret": "TOKENA42"}); res.Redacted {
		t.Fatalf("redactor must not keep generation A patterns after reload during hashing, got %+v %+v", out, res)
	}

	// 6c. Approval timeout must correspond to B.
	if got := p.currentApproval().Timeout(); got != 7*time.Second {
		t.Fatalf("approval timeout must correspond to generation B, got %v", got)
	}

	// 6d. Audit redaction patterns must correspond to B.
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

	// 7. Launch identity + launch shape remain the ONE snapshot A captured by
	// the launch resolver, even though the current policy is B.
	if !p.identityResolved || p.resolvedIdentity.Digest != digestA {
		t.Fatalf("launch identity must be snapshot A, got %+v resolved=%v", p.resolvedIdentity, p.identityResolved)
	}
	if p.launchShape == nil || p.launchShape.kind != serveridentity.KindStdioInvocationSHA256V1 || len(p.launchShape.entry) != 1 || p.launchShape.entry[0] != 0 {
		t.Fatalf("launch shape must be snapshot A's shape [0], got %+v", p.launchShape)
	}

	// 8. B changed the attestation contract (digest B != A): a tools/call
	// must fail closed with a restart requirement, never attested.
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
