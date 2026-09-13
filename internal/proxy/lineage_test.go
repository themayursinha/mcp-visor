package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/lineage/testfixture"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/signer"
)

const lineageRawMarker = "LINRAW_t3ec7b275_SECRET"

func TestLineageApprovalAllowUsesSnapshotRedaction(t *testing.T) {
	runLineageApprovalSnapshot(t, true)
}

func TestLineageApprovalDenyUsesSnapshotRedaction(t *testing.T) {
	runLineageApprovalSnapshot(t, false)
}

func runLineageApprovalSnapshot(t *testing.T, allow bool) {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")
	siemPath := filepath.Join(dir, "siem.jsonl")
	var webhookBuf bytes.Buffer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		webhookBuf.Write(b)
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)

	if err := os.WriteFile(policyPath, []byte(testfixture.MarkerPolicyYAML(lineageRawMarker, true, true)), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	sig, err := signer.NewApprovalSigner()
	if err != nil {
		t.Fatal(err)
	}
	p := New(Config{
		ServerName:     testfixture.Server,
		SessionID:      "sess-lin-snap",
		ClientID:       testfixture.Coding,
		AuditLogPath:   auditPath,
		Policy:         w.Policy(),
		Engine:         policy.NewEngineWithWatcher(w),
		ApprovalDir:    approvalDir,
		ApprovalSigner: sig,
		WebhookURLs:    []string{srv.URL},
		SIEMTargets:    []string{siemPath},
	})
	t.Cleanup(func() { _ = p.audit.Close() })

	blocked := make(chan struct{})
	go func() {
		for {
			matches, _ := filepath.Glob(filepath.Join(approvalDir, "req-*.json"))
			if len(matches) > 0 {
				close(blocked)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	done := make(chan string, 1)
	go func() {
		out := &bytes.Buffer{}
		client := mcp.NewParser(nil, out)
		_, action := p.interceptAndModify(toolCallRaw(1, testfixture.Tool, testfixture.MarkerArgs(lineageRawMarker)), client)
		done <- action
	}()
	select {
	case <-blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("approval was not blocked")
	}
	if err := os.WriteFile(policyPath, []byte(testfixture.MarkerPolicyYAML(lineageRawMarker, false, true)), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	matches, _ := filepath.Glob(filepath.Join(approvalDir, "req-*.json"))
	if len(matches) == 0 {
		t.Fatal("missing approval request")
	}
	id := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
	ext := ".ok"
	if !allow {
		ext = ".no"
	}
	if err := os.WriteFile(filepath.Join(approvalDir, id+ext), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case action := <-done:
		if allow && action != "forward" {
			t.Fatalf("allow path want forward, got %s", action)
		}
		if !allow && action != "denied" {
			t.Fatalf("deny path want denied, got %s", action)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call did not finish")
	}
	time.Sleep(50 * time.Millisecond)
	jsonl, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(jsonl, []byte(lineageRawMarker)) {
		t.Fatal("raw marker leaked into JSONL")
	}
	siem, _ := os.ReadFile(siemPath)
	if bytes.Contains(siem, []byte(lineageRawMarker)) {
		t.Fatal("raw marker leaked into SIEM")
	}
	if bytes.Contains(webhookBuf.Bytes(), []byte(lineageRawMarker)) {
		t.Fatal("raw marker leaked into webhook")
	}
	wantType := audit.EventToolDenied
	if allow {
		wantType = audit.EventToolAllowed
	}
	ev := findAuditEvent(t, auditPath, wantType, testfixture.Tool)
	if ev.Lineage == nil {
		t.Fatal("terminal event must retain authorizing lineage")
	}
	blob, _ := json.Marshal(ev.Lineage)
	if !bytes.Contains(blob, []byte("[REDACTED]")) {
		t.Fatalf("JSONL lineage must keep [REDACTED] evidence, got %s", blob)
	}
	if ev.PolicyHash == "" {
		t.Fatal("terminal event must keep authorizing policy hash")
	}
}

func lineageProxy(t *testing.T, client string) (*Proxy, string) {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName: testfixture.Server, SessionID: "sess-lin", ClientID: client,
		AuditLogPath: auditPath, Policy: mustLoadPolicy(t, testfixture.PolicyYAML()),
	})
	t.Cleanup(func() { _ = p.audit.Close() })
	return p, auditPath
}

func TestLineageProxyDeniesUnregisteredBeforeRelay(t *testing.T) {
	p, auditPath := lineageProxy(t, "orphan-1")
	out := &bytes.Buffer{}
	_, action := p.interceptAndModify(toolCallRaw(1, testfixture.Tool, testfixture.Args()), mcp.NewParser(nil, out))
	if action != "denied" || !strings.Contains(out.String(), "lineage:unregistered-principal") {
		t.Fatalf("unregistered must deny, action=%s out=%s", action, out.String())
	}
	_ = p.audit.Close()
	ev := findAuditEvent(t, auditPath, audit.EventToolDenied, testfixture.Tool)
	if ev.Lineage == nil || ev.Lineage.ActorAgentID != "orphan-1" {
		t.Fatalf("deny evidence: %+v", ev.Lineage)
	}
}

func TestLineageProxyAllowsValidChain(t *testing.T) {
	p, auditPath := lineageProxy(t, testfixture.Coding)
	_, action := p.interceptAndModify(toolCallRaw(1, testfixture.Tool, testfixture.Args()), mcp.NewParser(nil, &bytes.Buffer{}))
	if action != "forward" {
		t.Fatalf("valid lineage must forward, got %s", action)
	}
	_ = p.audit.Close()
	ev := findAuditEvent(t, auditPath, audit.EventToolAllowed, testfixture.Tool)
	if ev.Lineage == nil || ev.Lineage.Capability != testfixture.CapWrite || strings.Join(ev.Lineage.GrantChain, ",") != testfixture.GrantPlanner+","+testfixture.GrantCoding {
		t.Fatalf("allow lineage: %+v", ev.Lineage)
	}
}

func TestLineageProxyDeniesDuplicateKeyHiddenGrant(t *testing.T) {
	p, _ := lineageProxy(t, testfixture.Coding)
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"README.md","_lineage":{"grant_id":"grant-coding-1","capability":"github.repo.write","resource":"repo:themayursinha/mcp-visor","effect":"write","prior_state_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","trajectory_id":"traj-write-1"},"_lineage":{"grant_id":"grant-forged","capability":"github.repo.write","resource":"repo:themayursinha/mcp-visor","effect":"write","prior_state_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","trajectory_id":"traj-write-1"}}}}` + "\n")
	out := &bytes.Buffer{}
	_, action := p.interceptAndModify(raw, mcp.NewParser(nil, out))
	if action != "denied" || !strings.Contains(out.String(), "lineage:delegation-ceiling-violation") {
		t.Fatalf("last-wins forged grant must deny ceiling, got %s %s", action, out.String())
	}
}

func TestLineageProxyDeniesEscapedEquivalentGrant(t *testing.T) {
	p, _ := lineageProxy(t, testfixture.Coding)
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"README.md","_lineage":{"grant_id":"grant-coding-1","capability":"github.repo.write","resource":"repo:themayursinha/mcp-visor","effect":"write","prior_state_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","trajectory_id":"traj-write-1"},"\u005flineage":{"grant_id":"grant-forged","capability":"github.repo.write","resource":"repo:themayursinha/mcp-visor","effect":"write","prior_state_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","trajectory_id":"traj-write-1"}}}}` + "\n")
	out := &bytes.Buffer{}
	_, action := p.interceptAndModify(raw, mcp.NewParser(nil, out))
	if action != "denied" || !strings.Contains(out.String(), "lineage:delegation-ceiling-violation") {
		t.Fatalf("escaped-equivalent last-wins forged grant must deny, got %s %s", action, out.String())
	}
}

func lineageH32YAML() string {
	return "version: \"1.0\"\ndefault_action: deny\nsettings:\n  instruction_authority_continuity: true\n  instruction_authority_ed25519_public_keys:\n    " + h32KeyID + ": " + h32Pub + "\n" + strings.TrimPrefix(testfixture.PolicyYAML(), "version: \"1.0\"\ndefault_action: deny\n")
}

func lineageH32Proxy(t *testing.T, yaml, client string) *Proxy {
	t.Helper()
	p := New(Config{
		ServerName: testfixture.Server, SessionID: "sess-h32-lin", ClientID: client,
		AuditLogPath: filepath.Join(t.TempDir(), "audit.jsonl"),
		ApprovalDir:  filepath.Join(t.TempDir(), "approvals"),
		Policy:       mustLoadPolicy(t, yaml),
	})
	t.Cleanup(func() { _ = p.audit.Close() })
	return p
}

func TestLineageH32AuthenticatedRequestAllows(t *testing.T) {
	p := lineageH32Proxy(t, lineageH32YAML(), testfixture.Coding)
	obj, root := h32Honest()
	raw := h32Attach(t, p, h32Call(1, testfixture.Tool, testfixture.Args(), h32Meta(obj, root)), nil)
	action, msg, _, _ := h32Intercept(t, p, raw)
	if action != "forward" {
		t.Fatalf("H32+lineage valid must allow, got %s %s", action, msg)
	}
}

func TestLineageH32FailurePrecedesPolicy(t *testing.T) {
	p := lineageH32Proxy(t, lineageH32YAML(), testfixture.Coding)
	action, msg, _, _ := h32Intercept(t, p, toolCallRaw(1, testfixture.Tool, testfixture.Args()))
	if action != "denied" || !strings.Contains(msg, "instruction authority") {
		t.Fatalf("H32 failure must precede lineage, got %s %s", action, msg)
	}
}

func TestLineageH32ValidButLineageInvalidDenies(t *testing.T) {
	p := lineageH32Proxy(t, lineageH32YAML(), "orphan-1")
	obj, root := h32Honest()
	raw := h32Attach(t, p, h32Call(1, testfixture.Tool, testfixture.Args(), h32Meta(obj, root)), nil)
	action, msg, _, _ := h32Intercept(t, p, raw)
	if action != "denied" || msg != "lineage:unregistered-principal" {
		t.Fatalf("valid H32 invalid lineage must deny lineage, got %s %s", action, msg)
	}
}

func TestLineageH32StripPreservesLineageClaims(t *testing.T) {
	p := lineageH32Proxy(t, lineageH32YAML(), testfixture.Coding)
	obj, root := h32Honest()
	raw := h32Attach(t, p, h32Call(1, testfixture.Tool, testfixture.Args(), h32Meta(obj, root)), nil)
	action, _, _, modified := h32Intercept(t, p, raw)
	if action != "forward" {
		t.Fatalf("want forward, got %s", action)
	}
	s := string(modified)
	if strings.Contains(s, h32MetaKey) {
		t.Fatal("H32 metadata must be stripped")
	}
	if !strings.Contains(s, `"_lineage"`) && !strings.Contains(s, `"grant_id"`) {
		t.Fatalf("strip must preserve _lineage, got %s", s)
	}
}

func lineageApprovalYAML() string {
	return strings.Replace(testfixture.PolicyYAML(), "risk: high\n        rules:", "risk: high\n        approval_required: true\n        rules:", 1)
}

func waitLineageApproval(t *testing.T, dir string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		matches, _ := filepath.Glob(filepath.Join(dir, "req-*.json"))
		if len(matches) > 0 {
			return strings.TrimSuffix(filepath.Base(matches[0]), ".json")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("approval was not blocked")
	return ""
}

func TestLineagePostApprovalExpiryDenies(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")
	p := New(Config{
		ServerName: testfixture.Server, SessionID: "sess-lin-exp", ClientID: testfixture.Coding,
		AuditLogPath: auditPath, ApprovalDir: approvalDir, Policy: mustLoadPolicy(t, lineageApprovalYAML()),
	})
	t.Cleanup(func() { _ = p.audit.Close() })
	done := make(chan string, 1)
	go func() {
		_, action := p.interceptAndModify(toolCallRaw(1, testfixture.Tool, testfixture.Args()), mcp.NewParser(nil, &bytes.Buffer{}))
		done <- action
	}()
	id := waitLineageApproval(t, approvalDir)
	exp, err := time.Parse(time.RFC3339, testfixture.Expiry)
	if err != nil {
		t.Fatal(err)
	}
	p.setNowFunc(func() time.Time { return exp })
	if err := os.WriteFile(filepath.Join(approvalDir, id+".ok"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case action := <-done:
		if action != "denied" {
			t.Fatalf("expired lineage after approval must deny, got %s", action)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call did not finish")
	}
	_ = p.audit.Close()
	ev := findAuditEvent(t, auditPath, audit.EventToolDenied, testfixture.Tool)
	if ev.Lineage == nil || ev.Lineage.ActorAgentID != testfixture.Coding {
		t.Fatalf("terminal deny must keep lineage evidence, got %+v", ev.Lineage)
	}
	if !strings.Contains(ev.Reason, "lineage:") {
		t.Fatalf("terminal reason must be lineage, got %q", ev.Reason)
	}
}

func TestLineagePostApprovalOwnershipDenyKeepsEvidence(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")
	yaml := lineageApprovalYAML() + `
capability_ownership:
  endpoints:
    - server: github
      owner: tenant-B
      capabilities:
        - tool: write_file
          effect_class: NETWORK
          scope_argument: path
  delegations:
    - id: b-to-coding-write
      owner: tenant-B
      delegate: coding-agent-1
      server: github
      tool: write_file
      effect_class: NETWORK
      resource_scope:
        argument: path
        exact_values: ["README.md"]
      issued_at: "2026-09-11T10:00:00Z"
      expires_at: "2026-09-11T10:15:00Z"
`
	p := New(Config{
		ServerName: testfixture.Server, SessionID: "sess-lin-own", ClientID: testfixture.Coding,
		AuditLogPath: auditPath, ApprovalDir: approvalDir, Policy: mustLoadPolicy(t, yaml),
	})
	p.setNowFunc(func() time.Time { return time.Date(2026, 9, 11, 10, 5, 0, 0, time.UTC) })
	t.Cleanup(func() { _ = p.audit.Close() })
	out := &bytes.Buffer{}
	done := make(chan string, 1)
	go func() {
		_, action := p.interceptAndModify(toolCallRaw(1, testfixture.Tool, testfixture.Args()), mcp.NewParser(nil, out))
		done <- action
	}()
	id := waitLineageApproval(t, approvalDir)
	p.setNowFunc(func() time.Time { return time.Date(2026, 9, 11, 10, 16, 0, 0, time.UTC) })
	if err := os.WriteFile(filepath.Join(approvalDir, id+".ok"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case action := <-done:
		if action != "denied" {
			t.Fatalf("lapsed ownership after approval must deny, got %s", action)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call did not finish")
	}
	_ = p.audit.Close()
	ev := findAuditEvent(t, auditPath, audit.EventToolDenied, testfixture.Tool)
	if ev.Lineage == nil || ev.Lineage.ActorAgentID != testfixture.Coding || ev.Lineage.GrantID != testfixture.GrantCoding {
		t.Fatalf("ownership deny must retain lineage snapshot, got %+v", ev.Lineage)
	}
	if !strings.Contains(out.String(), "expired") {
		t.Fatalf("denial must record ownership expiry, got %s", out.String())
	}
}
