package proxy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/receipt"
	"github.com/themayursinha/mcp-visor/internal/signer"
)

func TestApprovalRequiredFailsClosedWithoutBackend(t *testing.T) {
	p := New(Config{
		ServerName: "slack",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "slack"
    allowed: true
    tools:
      - name: "slack_send_message"
        allowed: true
        approval_required: true
`),
	})

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "slack_send_message", map[string]any{"text": "hello"}), client)

	if action != "denied" {
		t.Fatalf("expected denied, got %s", action)
	}
	if !strings.Contains(out.String(), "approval not granted") {
		t.Fatalf("expected approval denial response, got %s", out.String())
	}
}

func TestApprovalRequiredWithFileBackendAllowsAfterMarker(t *testing.T) {
	dir := t.TempDir()
	p := New(Config{
		ServerName:  "slack",
		ApprovalDir: dir,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "slack"
    allowed: true
    tools:
      - name: "slack_send_message"
        allowed: true
        approval_required: true
`),
	})

	go func() {
		for {
			matches, _ := filepath.Glob(filepath.Join(dir, "req-*.json"))
			if len(matches) > 0 {
				base := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
				_ = os.WriteFile(filepath.Join(dir, base+".ok"), []byte{}, 0o600)
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "slack_send_message", map[string]any{"text": "hello"}), client)

	if action != "forward" {
		t.Fatalf("expected forward after approval, got %s; response=%s", action, out.String())
	}
}

func TestApprovedCallWritesVerifiableReceiptEvidence(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	approvalSigner, err := signer.NewApprovalSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	p := New(Config{
		ServerName:     "slack",
		ApprovalDir:    dir,
		AuditLogPath:   auditPath,
		ApprovalSigner: approvalSigner,
		ClientID:       "agent-test",
		SessionID:      "sess-test",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "slack"
    allowed: true
    tools:
      - name: "slack_send_message"
        allowed: true
        approval_required: true
`),
	})

	go func() {
		for {
			matches, _ := filepath.Glob(filepath.Join(dir, "req-*.json"))
			if len(matches) > 0 {
				base := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
				_ = os.WriteFile(filepath.Join(dir, base+".ok"), []byte{}, 0o600)
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "slack_send_message", map[string]any{"text": "hello"}), client)
	if action != "forward" {
		t.Fatalf("expected forward after approval, got %s; response=%s", action, out.String())
	}
	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var allowed audit.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal audit event: %v\n%s", err, line)
		}
		if ev.EventType == audit.EventToolAllowed && ev.ApprovalReceiptHash != "" {
			allowed = ev
			break
		}
	}
	if allowed.ApprovalReceiptHash == "" {
		t.Fatalf("expected allowed audit event with approval receipt, log:\n%s", string(data))
	}
	if allowed.RequestHash == "" || allowed.RedactedArgumentHash == "" || allowed.PolicyHash == "" || allowed.ChainContextHash == "" {
		t.Fatalf("expected evidence hashes on allowed event: %+v", allowed)
	}

	recData, err := json.Marshal(allowed.ApprovalReceipt)
	if err != nil {
		t.Fatalf("marshal receipt map: %v", err)
	}
	rec, err := receipt.Unmarshal(recData)
	if err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	pub := approvalSigner.PublicKey().(ed25519.PublicKey)
	verifier := signer.NewVerifierFromPublicKey(pub)
	if err := rec.VerifyWith(verifier); err != nil {
		t.Fatalf("receipt should verify: %v", err)
	}
	rec.PolicyHash = "tampered"
	if err := rec.VerifyWith(verifier); err == nil {
		t.Fatal("tampered receipt should not verify")
	}
}

func TestRuntimeLimitMaxArgumentSizeDenies(t *testing.T) {
	p := New(Config{
		ServerName: "filesystem",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
settings:
  max_argument_size_bytes: 8
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
`),
	})

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{"path": "/tmp/large"}), client)

	if action != "denied" {
		t.Fatalf("expected denied, got %s", action)
	}
	if !strings.Contains(out.String(), "argument size") {
		t.Fatalf("expected argument-size denial, got %s", out.String())
	}
}

func TestRuntimeLimitSessionMaxToolsDenies(t *testing.T) {
	p := New(Config{
		ServerName: "filesystem",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
settings:
  session_max_tools: 1
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
`),
	})
	p.session.RecordToolCall("filesystem", mcp.ToolsCallRequest{Name: "file_read", Arguments: json.RawMessage(`{}`)}, "")

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(2, "file_read", map[string]any{"path": "/tmp/other"}), client)

	if action != "denied" {
		t.Fatalf("expected denied, got %s", action)
	}
	if !strings.Contains(out.String(), "session tool limit") {
		t.Fatalf("expected session-limit denial, got %s", out.String())
	}
}

func TestRuntimeLimitSessionTimeoutDenies(t *testing.T) {
	p := New(Config{
		ServerName: "filesystem",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
settings:
  session_timeout_seconds: 1
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
`),
	})
	p.session.CreatedAt = time.Now().Add(-2 * time.Second)

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{"path": "/tmp/test"}), client)

	if action != "denied" {
		t.Fatalf("expected denied, got %s", action)
	}
	if !strings.Contains(out.String(), "session timeout") {
		t.Fatalf("expected session-timeout denial, got %s", out.String())
	}
}

func TestChainRequireApprovalGatesExecution(t *testing.T) {
	p := New(Config{
		ServerName: "slack",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
settings:
  chain_window_size: 3
servers:
  - name: "slack"
    allowed: true
    tools:
      - name: "slack_send_message"
        allowed: true
tool_chains:
  - name: "read_then_slack"
    sources:
      - server: "*"
        tool_pattern: "file_read"
    sinks:
      - server: "*"
        tool_pattern: "slack_send_message"
    action: require_approval
    within_calls: 3
`),
	})
	p.session.RecordToolCall("filesystem", mcp.ToolsCallRequest{Name: "file_read", Arguments: json.RawMessage(`{}`)}, "")

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "slack_send_message", map[string]any{"text": "data"}), client)

	if action != "denied" {
		t.Fatalf("expected denied without approval backend, got %s", action)
	}
	if !strings.Contains(out.String(), "approval not granted") {
		t.Fatalf("expected approval-required denial, got %s", out.String())
	}
}

func TestApprovedCallTaintsUseSnapshotPolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	initial := `
version: "v1"
default_action: deny
settings:
  approval_timeout_seconds: 10
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        approval_required: true
taints:
  - name: "sensitive_file_accessed"
    source_servers: ["filesystem"]
    source_tools: ["file_read"]
    source_patterns: ["**/secrets/**"]
`
	updated := `
version: "v2"
default_action: deny
settings:
  approval_timeout_seconds: 10
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        approval_required: true
`
	if err := os.WriteFile(policyPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer w.Close()
	p := New(Config{
		ServerName:  "filesystem",
		Policy:      w.Policy(),
		Engine:      policy.NewEngineWithWatcher(w),
		ApprovalDir: dir,
		SessionID:   "snapshot-taint",
		ClientID:    "agent-test",
	})

	requestSeen := make(chan string, 1)
	approve := make(chan struct{})
	go func() {
		for {
			matches, _ := filepath.Glob(filepath.Join(dir, "req-*.json"))
			if len(matches) > 0 {
				requestSeen <- strings.TrimSuffix(filepath.Base(matches[0]), ".json")
				<-approve
				_ = os.WriteFile(filepath.Join(dir, strings.TrimSuffix(filepath.Base(matches[0]), ".json")+".ok"), []byte{}, 0o600)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	result := make(chan string, 1)
	go func() {
		out := &bytes.Buffer{}
		client := mcp.NewParser(nil, out)
		_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{"path": "/workspace/secrets/token.txt"}), client)
		result <- action
	}()

	select {
	case <-requestSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("approval request was not created")
	}
	if err := os.WriteFile(policyPath, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	close(approve)

	select {
	case action := <-result:
		if action != "forward" {
			t.Fatalf("approved call action = %q, want forward", action)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("approved call did not complete")
	}
	if !p.session.HasTaint("sensitive_file_accessed") {
		t.Fatal("approved call lost its source taint after policy reload")
	}
}

func TestRuntimeSnapshotPairsOutputLimitAndRedactor(t *testing.T) {
	p := New(Config{
		ServerName: "filesystem",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
settings:
  max_output_size_bytes: 5
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
redaction:
  patterns:
    - name: "secret"
      regex: "SECRET[0-9]+"
      replacement: "[REDACTED]"
`),
	})

	snapshot := p.currentRuntimeSnapshot()
	if snapshot.policy.Settings.MaxOutputSizeBytes != 5 {
		t.Fatalf("snapshot max output = %d, want 5", snapshot.policy.Settings.MaxOutputSizeBytes)
	}
	if got := snapshot.redactor.RedactOutput("SECRET42"); got != "[REDACTED]" {
		t.Fatalf("snapshot redactor = %q, want [REDACTED]", got)
	}
}

func TestRedactServerResponseTruncatesOutput(t *testing.T) {
	p := New(Config{
		ServerName: "filesystem",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
settings:
  max_output_size_bytes: 5
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
`),
	})

	raw := json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"abcdefghijklmnopqrstuvwxyz"}]}}`)
	got := string(p.redactServerResponse(raw))
	if !strings.Contains(got, "abcde") || !strings.Contains(got, "TRUNCATED") {
		t.Fatalf("expected truncated output, got %s", got)
	}
	if strings.Contains(got, "fghijklmnopqrstuvwxyz") {
		t.Fatalf("expected output beyond max to be removed, got %s", got)
	}
}

func TestLogAuditFansOutToWebhookAndSIEM(t *testing.T) {
	webhookSeen := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-MCP-Visor-Signature") == "" {
			t.Errorf("expected webhook signature header")
		}
		webhookSeen <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	siemPath := filepath.Join(t.TempDir(), "events.jsonl")
	p := New(Config{
		WebhookURLs:       []string{server.URL},
		WebhookHMACSecret: "test-secret",
		SIEMTargets:       []string{siemPath},
		SIEMFormat:        "json",
	})
	defer p.closeEventSinks()

	p.logAudit(audit.Event{
		EventType: audit.EventToolDenied,
		SessionID: "sess-test",
		AgentID:   "agent-test",
		Server:    "filesystem",
		Tool:      "file_read",
		Decision:  "deny",
		Reason:    "test denial",
		RiskLevel: "medium",
	})

	select {
	case <-webhookSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("webhook did not receive audit event")
	}

	data, err := os.ReadFile(siemPath)
	if err != nil {
		t.Fatalf("read siem export: %v", err)
	}
	if !strings.Contains(string(data), "tool_call_denied") {
		t.Fatalf("expected SIEM export to contain event type, got %s", string(data))
	}
}

func mustLoadPolicy(t *testing.T, yaml string) *policy.Policy {
	t.Helper()
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return p
}

func toolCallRaw(id int, name string, args map[string]any) json.RawMessage {
	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      name,
			"arguments": args,
		},
	}
	data, _ := json.Marshal(msg)
	return append(data, '\n')
}

func TestApprovalRequiredReleasesRuntimeBarrierBeforeWait(t *testing.T) {
	// Verify that a hot reload can proceed while a tools/call is
	// waiting for operator approval — i.e., the runtimeMu read lock
	// is released before the blocking approval wait, not after SIEM
	// forwarding.  This test does not mock SIEM; it exercises the
	// lock discipline directly by issuing a reload from inside the
	// approval context.
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")

	initial := `
version: "1.0"
default_action: deny
servers:
  - name: "slack"
    allowed: true
    tools:
      - name: "slack_send_message"
        allowed: true
        approval_required: true
redaction:
  patterns:
    - name: "v1"
      regex: "v1secret"
      replacement: "[R1]"
`
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
		ServerName:   "slack",
		Policy:       w.Policy(),
		Engine:       eng,
		AuditLogPath: auditPath,
		ApprovalDir:  approvalDir,
	})

	// Issue a tools/call that requires approval.  It will block on
	// the channel in requestApproval because there is no operator to
	// place an .ok marker.
	req := toolCallRaw(1, "slack_send_message", map[string]any{"text": "hello"})
	out := &bytes.Buffer{}
	parser := mcp.NewParser(nil, out)

	callDone := make(chan struct{})
	go func() {
		p.interceptAndModify(req, parser)
		close(callDone)
	}()

	// Give the approval goroutine time to release the runtime
	// barrier and enter the blocking wait.
	time.Sleep(100 * time.Millisecond)

	// While the call is waiting for approval, perform a hot reload.
	// This must not deadlock and must complete before the approval
	// wait finishes.
	updated := `
version: "1.0"
default_action: deny
servers:
  - name: "slack"
    allowed: true
    tools:
      - name: "slack_send_message"
        allowed: true
        approval_required: true
redaction:
  patterns:
    - name: "v2"
      regex: "v2secret"
      replacement: "[R2]"
`
	if err := os.WriteFile(policyPath, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}

	reloadDone := make(chan struct{})
	go func() {
		w.Reload()
		close(reloadDone)
	}()

	select {
	case <-reloadDone:
		// Hot reload completed while approval is still pending — success.
	case <-callDone:
		t.Fatal("approval returned before hot reload completed — runtimeMu was held too long")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: hot reload likely deadlocked holding runtimeMu")
	}

	// Clean up: approve the pending call so the goroutine exits.
	matches, _ := filepath.Glob(filepath.Join(approvalDir, "req-*.json"))
	if len(matches) > 0 {
		base := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
		_ = os.WriteFile(filepath.Join(approvalDir, base+".ok"), []byte{}, 0o600)
	}

	select {
	case <-callDone:
	case <-time.After(3 * time.Second):
		t.Fatal("approval goroutine did not exit after marker placed")
	}
}
