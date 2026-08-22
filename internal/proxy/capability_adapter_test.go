package proxy

import (
	"bytes"
	"context"
	"encoding/json"
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

func approveFirstRequest(t *testing.T, approvalDir string) <-chan struct{} {
	t.Helper()
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
	return approved
}

func optedInWorkspaceProxy(t *testing.T, dir, sessionID string) *Proxy {
	t.Helper()
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    sessionID,
		ClientID:     "agent-" + sessionID,
		AuditLogPath: filepath.Join(dir, "audit.jsonl"),
		ApprovalDir:  filepath.Join(dir, "approvals"),
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: allow
settings:
  capability_accounting: true
servers:
  - name: "workspace"
    allowed: true
    workspace_root: "`+dir+`"
`),
	})
	t.Cleanup(func() { p.audit.Close() })
	if p.capEval == nil {
		t.Fatal("capEval must be constructed with capability_accounting: true")
	}
	return p
}

// TestREDPublishedPolicyCapabilityReconciledAtRegistration: a stale
// cfg.Policy without capability_accounting must not leave capEval nil when
// the supplied Engine already publishes a generation with the setting on.
// wirePolicyReload → reconcilePublishedRuntime is the parent path.
func TestREDPublishedPolicyCapabilityReconciledAtRegistration(t *testing.T) {
	dir := t.TempDir()
	stale := mustLoadPolicy(t, `
version: "1.0"
default_action: allow
servers:
  - name: "workspace"
    allowed: true
`)
	published := mustLoadPolicy(t, `
version: "1.0"
default_action: allow
settings:
  capability_accounting: true
servers:
  - name: "workspace"
    allowed: true
`)
	eng := policy.NewEngine(published)
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-reconcile-cap",
		ClientID:     "agent-reconcile-cap",
		AuditLogPath: filepath.Join(dir, "audit.jsonl"),
		Policy:       stale,
		Engine:       eng,
	})
	defer p.audit.Close()
	if p.capEval == nil {
		t.Fatal("published capability_accounting: true must construct capEval at registration reconcile even when cfg.Policy is stale")
	}
}

// TestP1ShellExecOptedInPauses: visor's shipped shell_exec tool with
// {"command":"id"} must pause-to-approval when opted in.
func TestP1ShellExecOptedInPauses(t *testing.T) {
	dir := t.TempDir()
	p := optedInWorkspaceProxy(t, dir, "sess-shell-exec-proxy")
	approved := approveFirstRequest(t, filepath.Join(dir, "approvals"))
	action := callTool(t, p, 1, "shell_exec", map[string]any{"command": "id"})
	if action != "forward" {
		t.Fatalf("shell_exec({command:id}) must PAUSE → approval → forward, got %q", action)
	}
	select {
	case <-approved:
	case <-time.After(5 * time.Second):
		t.Fatal("shell_exec never reached the approval dir; call ALLOWed instead of pausing")
	}
}

// TestP1NestedCommandBearingArgumentsPauses: run({"arguments":{"command":"bash -c id"}})
// must pause, not ALLOW, because the nested command surface is preserved.
func TestP1NestedCommandBearingArgumentsPauses(t *testing.T) {
	dir := t.TempDir()
	p := optedInWorkspaceProxy(t, dir, "sess-nested-args")
	approved := approveFirstRequest(t, filepath.Join(dir, "approvals"))
	action := callTool(t, p, 1, "run", map[string]any{
		"arguments": map[string]any{"command": "bash -c id"},
	})
	if action != "forward" {
		t.Fatalf("nested command-bearing arguments must PAUSE → approval → forward, got %q", action)
	}
	select {
	case <-approved:
	case <-time.After(5 * time.Second):
		t.Fatal("nested arguments call never reached approval; nested command was dropped")
	}
}

// TestREDCapabilityReceiptPersistedOnAllow: an ordinary ALLOW receipt must
// be attached to the terminal audit event, not discarded after updating
// the in-memory hash.
func TestREDCapabilityReceiptPersistedOnAllow(t *testing.T) {
	dir := t.TempDir()
	p := optedInWorkspaceProxy(t, dir, "sess-persist-allow")
	action := callTool(t, p, 1, "file_write", map[string]any{"path": filepath.Join(dir, "out.txt")})
	if action != "forward" {
		t.Fatalf("in-workspace file_write must ALLOW/forward, got %q", action)
	}
	data, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("audit jsonl: %v", err)
		}
		rec, _ := ev["approval_receipt"].(map[string]any)
		if rec == nil {
			continue
		}
		if rec["decision"] == capability.DecisionAllow && rec["hash"] != nil {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ALLOW capability receipt missing from audit jsonl:\n%s", data)
	}
}

// TestREDEvaluatorErrorAdvancesReceiptChain: after an evaluator error, the
// sealed pause receipt must become capLastHash so the next step cannot fork
// around it.
func TestREDEvaluatorErrorAdvancesReceiptChain(t *testing.T) {
	dir := t.TempDir()
	p := optedInWorkspaceProxy(t, dir, "sess-chain-adv")
	genesis := p.capLastHash
	approved := approveFirstRequest(t, filepath.Join(dir, "approvals"))
	// Missing workspace-root attribution is forced by pointing at a server
	// with an empty root: use a path outside the workspace so Eval errors
	// (untyped file-boundary / missing root). The default policy has a root,
	// so use a malformed DestHost via url to force evaluator error.
	action := callTool(t, p, 1, "web_fetch", map[string]any{"url": "https://bad host!/"})
	if action != "forward" {
		t.Fatalf("malformed dest must pause-to-approval, got %q", action)
	}
	select {
	case <-approved:
	case <-time.After(5 * time.Second):
		t.Fatal("malformed dest never reached approval")
	}
	p.capEvalMu.Lock()
	defer p.capEvalMu.Unlock()
	if p.capLastHash == "" || p.capLastHash == genesis {
		t.Fatalf("evaluator-error pause receipt must become capLastHash (got %q, genesis %q)", p.capLastHash, genesis)
	}
}

// TestP1AbsoluteExecPathOptedInPauses: Codex P1 on f30be23 — an absolute
// path to a canonical shell/net executable must pause-to-approval, same as
// the bare name. Path identity is filepath-base, not an extra name in the
// allowlist.
func TestP1AbsoluteExecPathOptedInPauses(t *testing.T) {
	for _, tc := range []struct {
		name string
		tool string
		args map[string]any
	}{
		{"usr-bin-bash", "run", map[string]any{"command": "/usr/bin/bash -c id"}},
		{"usr-bin-curl", "run", map[string]any{"command": "/usr/bin/curl example.com"}},
		{"bash-exe", "run", map[string]any{"command": "/usr/local/bin/bash.exe -c id"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := optedInWorkspaceProxy(t, dir, "sess-abs-"+tc.name)
			approved := approveFirstRequest(t, filepath.Join(dir, "approvals"))
			action := callTool(t, p, 1, tc.tool, tc.args)
			if action != "forward" {
				t.Fatalf("%v must PAUSE → approval → forward, got %q", tc.args, action)
			}
			select {
			case <-approved:
			case <-time.After(5 * time.Second):
				t.Fatalf("%v never reached approval; absolute path was treated as observation", tc.args)
			}
		})
	}
}

// TestP2GenericToolUrlArgDoesNotPause: Codex P2 — exec({"url":"https://example.com"})
// must not route to approval. url is Rev 15 payload on a non-network tool.
func TestP2GenericToolUrlArgDoesNotPause(t *testing.T) {
	dir := t.TempDir()
	p := optedInWorkspaceProxy(t, dir, "sess-exec-url")
	action := callTool(t, p, 1, "exec", map[string]any{"url": "https://example.com"})
	if action != "forward" {
		t.Fatalf("exec({url}) must ALLOW/forward, got %q", action)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "approvals", "req-*.json"))
	if len(matches) > 0 {
		t.Fatal("exec({url}) reached approval; url was treated as a structured destination")
	}
}

// TestP2GenericToolPathArgDoesNotPause: Codex P2 — a generic tool with a
// payload path must not hit Eval's empty-Effect outside-workspace probe.
func TestP2GenericToolPathArgDoesNotPause(t *testing.T) {
	dir := t.TempDir()
	p := optedInWorkspaceProxy(t, dir, "sess-meta-path")
	action := callTool(t, p, 1, "get_metadata", map[string]any{"path": "/docs"})
	if action != "forward" {
		t.Fatalf("get_metadata({path}) must ALLOW/forward, got %q", action)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "approvals", "req-*.json"))
	if len(matches) > 0 {
		t.Fatal("get_metadata({path}) reached approval; payload path was treated as a file observation")
	}
}

// TestP1CommandBearingArrayOfObjectsPauses: Codex P1 — arguments as an
// array of objects must still expose the buried command and pause.
func TestP1CommandBearingArrayOfObjectsPauses(t *testing.T) {
	dir := t.TempDir()
	p := optedInWorkspaceProxy(t, dir, "sess-args-array-obj")
	approved := approveFirstRequest(t, filepath.Join(dir, "approvals"))
	action := callTool(t, p, 1, "run", map[string]any{
		"arguments": []any{map[string]any{"command": "bash -c id"}},
	})
	if action != "forward" {
		t.Fatalf("arguments:[{command}] must PAUSE → approval → forward, got %q", action)
	}
	select {
	case <-approved:
	case <-time.After(5 * time.Second):
		t.Fatal("array-of-objects command never reached approval; maps in the array were dropped")
	}
}
