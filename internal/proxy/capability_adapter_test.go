package proxy

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/capability"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

// fakeCapabilityEvaluator is a deterministic test evaluator that returns the
// canned receipt/error the test needs. It models the ChainEvaluator contract
// (per-session, Eval returns a sealed receipt or an error).
type fakeCapabilityEvaluator struct {
	decision string
	reason   string
	err      error
}

func (f *fakeCapabilityEvaluator) Eval(ctx context.Context, step capability.Step, prior string) (*capability.Receipt, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &capability.Receipt{
		ReceiptVersion: capability.ReceiptVersion,
		SessionID:      step.SessionID,
		StepID:         step.StepID,
		Decision:       f.decision,
		Reason:         f.reason,
		PrevHash:       prior,
		Hash:           "sha256:test-hash",
	}, nil
}

// setCapEval swaps the proxy's evaluator under its mutex and resets the hash
// chain to genesis so a test can drive a deterministic pause/error path.
func (p *Proxy) setCapEval(e capability.Evaluator) {
	p.capEvalMu.Lock()
	defer p.capEvalMu.Unlock()
	p.capEval = e
	if e != nil {
		p.capLastHash = capability.GenesisPrevHash
	}
}

// callTool drives one tools/call through the shared enforcement gate and
// returns the action ("forward" | "denied" | ...).
func callTool(t *testing.T, p *Proxy, id int, name string, args map[string]any) string {
	t.Helper()
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(id, name, args), client)
	return action
}

// TestREDCapabilityPauseRoutesToApprovalGate is the P1-1 RED test: when an
// opted-in evaluator returns PAUSE_REQUIRE_NEW_PROOF, the call must route to
// the existing approval gate (pause-to-approval). An operator supplying fresh
// proof must cause the call to FORWARD. On the vulnerable baseline this test
// FAILS because the adapter hard-denies and never reaches requestApproval.
func TestREDCapabilityPauseRoutesToApprovalGate(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")

	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-pause-red",
		ClientID:     "agent-pause-red",
		AuditLogPath: auditPath,
		ApprovalDir:  approvalDir,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: allow
servers:
  - name: "workspace"
    allowed: true
    workspace_root: "`+dir+`"
    tools:
      - name: "file_write"
        allowed: true
        risk: low
`),
	})
	defer p.audit.Close()
	p.setCapEval(&fakeCapabilityEvaluator{
		decision: capability.DecisionPauseRequireProof,
		reason:   capability.ReasonEffectOutsideEnvelope,
	})

	// Operator goroutine: approve the request as soon as it appears.
	approved := make(chan struct{})
	go func() {
		for {
			matches, _ := filepath.Glob(filepath.Join(approvalDir, "req-*.json"))
			if len(matches) > 0 {
				id := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
				_ = os.WriteFile(filepath.Join(approvalDir, id+".ok"), []byte{}, 0o600)
				close(approved)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	action := callTool(t, p, 1, "file_write", map[string]any{"path": filepath.Join(dir, "out.txt")})
	if action != "forward" {
		t.Fatalf("P1-1 RED: capability PAUSE must route to approval gate and forward on operator approval, got action=%q (want forward; baseline hard-denies)", action)
	}
	select {
	case <-approved:
	case <-time.After(5 * time.Second):
		t.Fatal("P1-1 RED: approval request never reached the approval dir; the call hard-denied instead of pausing")
	}
}

// TestREDCapabilityEvaluatorErrorRoutesToApprovalGate is the second P1-1 RED
// case: an evaluator error (the preceding branch) must also pause-to-approval,
// never a hard deny. An operator approving must forward.
func TestREDCapabilityEvaluatorErrorRoutesToApprovalGate(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")

	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-err-red",
		ClientID:     "agent-err-red",
		AuditLogPath: auditPath,
		ApprovalDir:  approvalDir,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: allow
servers:
  - name: "workspace"
    allowed: true
    workspace_root: "`+dir+`"
    tools:
      - name: "file_write"
        allowed: true
        risk: low
`),
	})
	defer p.audit.Close()
	p.setCapEval(&fakeCapabilityEvaluator{err: capability.ErrInvalidStep})

	approved := make(chan struct{})
	go func() {
		for {
			matches, _ := filepath.Glob(filepath.Join(approvalDir, "req-*.json"))
			if len(matches) > 0 {
				id := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
				_ = os.WriteFile(filepath.Join(approvalDir, id+".ok"), []byte{}, 0o600)
				close(approved)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	action := callTool(t, p, 2, "file_write", map[string]any{"path": filepath.Join(dir, "out.txt")})
	if action != "forward" {
		t.Fatalf("P1-1 RED: evaluator error must route to approval gate and forward on operator approval, got action=%q (want forward; baseline hard-denies)", action)
	}
	select {
	case <-approved:
	case <-time.After(5 * time.Second):
		t.Fatal("P1-1 RED: approval request never reached the approval dir for evaluator error")
	}
}

// TestREDPolicyCapabilityOptInHonored is the P1-2 RED test: a policy that sets
// settings.capability_accounting: true WITHOUT the CLI flag must construct the
// evaluator. On the vulnerable baseline this FAILS because capEval is nil.
func TestREDPolicyCapabilityOptInHonored(t *testing.T) {
	dir := t.TempDir()
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-policy-red",
		ClientID:     "agent-policy-red",
		AuditLogPath: filepath.Join(dir, "audit.jsonl"),
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: allow
settings:
  capability_accounting: true
servers:
  - name: "workspace"
    allowed: true
`),
	})
	defer p.audit.Close()
	if p.capEval == nil {
		t.Fatal("P1-2 RED: policy settings.capability_accounting: true must construct the evaluator without the CLI flag; capEval is nil")
	}
}

// TestREDPolicyCapabilityOptInTogglesOnReload is the reload-semantics RED test
// (documented decision: effective enable = CLI flag OR policy setting, and the
// evaluator enable state follows reloads). A reload that turns the setting off
// must remove the evaluator; a reload that turns it on must construct it.
func TestREDPolicyCapabilityOptInTogglesOnReload(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")

	off := `
version: "1.0"
default_action: allow
servers:
  - name: "workspace"
    allowed: true
`
	on := `
version: "1.0"
default_action: allow
settings:
  capability_accounting: true
servers:
  - name: "workspace"
    allowed: true
`
	if err := os.WriteFile(policyPath, []byte(on), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer w.Close()
	eng := policy.NewEngineWithWatcher(w)
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-policy-reload-red",
		ClientID:     "agent-policy-reload-red",
		Policy:       w.Policy(),
		Engine:       eng,
		AuditLogPath: auditPath,
	})
	defer p.audit.Close()

	if p.capEval == nil {
		t.Fatal("P1-2 RED: initial policy with capability_accounting: true must construct the evaluator")
	}
	if err := os.WriteFile(policyPath, []byte(off), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	if p.capEval != nil {
		t.Fatal("P1-2 RED: reload turning capability_accounting off must remove the evaluator")
	}
	if err := os.WriteFile(policyPath, []byte(on), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	if p.capEval == nil {
		t.Fatal("P1-2 RED: reload turning capability_accounting on must reconstruct the evaluator")
	}
}

// TestREDCapabilityPauseNeverDowngradesPolicyDeny is a P1 fail-open RED test:
// the capability adapter is ACCOUNTING and must never downgrade a terminal
// policy deny into an approval request. When the policy explicitly denies a
// tool, an opted-in evaluator returning PAUSE_REQUIRE_NEW_PROOF (or an
// evaluator error) must NOT turn the call into ActionRequireApproval — the
// deny is terminal. On the vulnerable fixed-code baseline this test FAILS
// because the capability block overwrites decision with ActionRequireApproval
// and the call reaches the approval gate.
func TestREDCapabilityPauseNeverDowngradesPolicyDeny(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")

	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-deny-red",
		ClientID:     "agent-deny-red",
		AuditLogPath: auditPath,
		ApprovalDir:  approvalDir,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: allow
settings:
  approval_timeout_seconds: 1
servers:
  - name: "workspace"
    allowed: true
    workspace_root: "`+dir+`"
    tools:
      - name: "file_write"
        allowed: false
        risk: low
`),
	})
	defer p.audit.Close()
	p.setCapEval(&fakeCapabilityEvaluator{
		decision: capability.DecisionPauseRequireProof,
		reason:   capability.ReasonEffectOutsideEnvelope,
	})

	// Watch the approval dir: a downgraded deny would write a request here.
	approvalSeen := make(chan struct{}, 1)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			matches, _ := filepath.Glob(filepath.Join(approvalDir, "req-*.json"))
			if len(matches) > 0 {
				select {
				case approvalSeen <- struct{}{}:
				default:
				}
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	defer close(stop)

	action := callTool(t, p, 1, "file_write", map[string]any{"path": filepath.Join(dir, "out.txt")})
	if action != "denied" {
		t.Fatalf("P1 RED: policy deny must stay terminal; capability PAUSE must not downgrade it to approval. got action=%q (want denied; fixed code forwards on operator approval)", action)
	}
	select {
	case <-approvalSeen:
		t.Fatal("P1 RED: policy-denied call reached the approval gate; capability adapter downgraded a terminal deny to ActionRequireApproval")
	default:
		// no approval request written — correct fail-closed deny
	}
}

// TestREDCapabilityEvaluatorErrorNeverDowngradesPolicyDeny is the same P1
// invariant for the evaluator-error branch: an error must map to a pause that
// routes to approval ONLY when the policy would otherwise allow. A policy deny
// stays denied.
func TestREDCapabilityEvaluatorErrorNeverDowngradesPolicyDeny(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")

	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-deny-err-red",
		ClientID:     "agent-deny-err-red",
		AuditLogPath: auditPath,
		ApprovalDir:  approvalDir,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: allow
settings:
  approval_timeout_seconds: 1
servers:
  - name: "workspace"
    allowed: true
    workspace_root: "`+dir+`"
    tools:
      - name: "file_write"
        allowed: false
        risk: low
`),
	})
	defer p.audit.Close()
	p.setCapEval(&fakeCapabilityEvaluator{err: capability.ErrInvalidStep})

	action := callTool(t, p, 1, "file_write", map[string]any{"path": filepath.Join(dir, "out.txt")})
	if action != "denied" {
		t.Fatalf("P1 RED: evaluator error must not downgrade a policy deny to approval. got action=%q (want denied)", action)
	}
	matches, _ := filepath.Glob(filepath.Join(approvalDir, "req-*.json"))
	if len(matches) > 0 {
		t.Fatal("P1 RED: policy-denied call with evaluator error reached the approval gate")
	}
}
