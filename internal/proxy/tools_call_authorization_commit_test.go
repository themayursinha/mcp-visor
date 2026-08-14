package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/transport"
)

// observingWriter counts every byte the downstream transport actually
// receives. It is the causal-order oracle: relay must never attempt a
// downstream write before the durable authorization commit has completed.
type observingWriter struct {
	mu    sync.Mutex
	count int
	bytes []byte
}

func (w *observingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.count++
	w.bytes = append(w.bytes, p...)
	return len(p), nil
}

func (w *observingWriter) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

func (w *observingWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]byte, len(w.bytes))
	copy(out, w.bytes)
	return out
}

// TestAuditCommitFailureFailClosedNoRelay is the RED test for H19.
// On the vulnerable baseline, Logger.Log swallows the write error from a
// closed audit file, processToolsCall returns "forward", and
// relayClientToServer writes the call downstream despite the failed audit
// append. After the fix, a failed durable authorization commit must deny
// the call with zero downstream writes, no allow/approved metrics, and no
// session taint mutation.
func TestAuditCommitFailureFailClosedNoRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-commit-red",
		ClientID:     "agent-commit-red",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
taints:
  - name: "sensitive_file_accessed"
    description: "Session has read sensitive workspace data"
    source_tools: ["file_read"]
    source_patterns: ["**/secrets/**", "**/*.env"]
`),
	})
	defer p.audit.Close()

	// Deterministic live write failure using existing APIs: closing the
	// logger closes the underlying O_SYNC file, so the next append fails.
	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}

	clientOut := &bytes.Buffer{}
	downstream := &observingWriter{}
	raw := toolCallRaw(1, "file_read", map[string]any{"path": "/workspace/secrets/customer-tokens.txt"})
	client := mcp.NewParser(bytes.NewReader(append(raw, '\n')), clientOut)
	server := mcp.NewParser(nil, downstream)

	err := p.relayClientToServer(context.Background(), client, server)
	if err == nil {
		t.Fatalf("expected relay to return when the client stream ends")
	}
	if !strings.Contains(clientOut.String(), "durable authorization audit commit failed") {
		t.Fatalf("expected generic audit-commit denial to the client, got %q", clientOut.String())
	}
	if got := downstream.Count(); got != 0 {
		t.Fatalf("downstream write count=%d, want 0 (relay must be denied after audit commit failure); bytes=%q", got, downstream.Bytes())
	}
	if got := downstream.Bytes(); len(got) != 0 {
		t.Fatalf("downstream bytes=%q, want empty", got)
	}
	if p.metrics.MessagesAllowed != 0 {
		t.Fatalf("allowed metric=%d, want 0 on commit failure", p.metrics.MessagesAllowed)
	}
	if p.metrics.MessagesApproved != 0 {
		t.Fatalf("approved metric=%d, want 0 on commit failure", p.metrics.MessagesApproved)
	}
	if p.metrics.MessagesDenied != 1 {
		t.Fatalf("denied metric=%d, want 1 on commit failure", p.metrics.MessagesDenied)
	}
	if p.session.HasTaint("sensitive_file_accessed") {
		t.Fatalf("session taint must not mutate on commit failure, taints=%+v", p.session.TaintsSnapshot())
	}
}

// causalAuditWriter is the causal-order oracle for healthy allow commits:
// at the first downstream Write it snapshots the JSONL ledger so the test
// can prove the hash-linked allow record existed before relay began.
type causalAuditWriter struct {
	mu            sync.Mutex
	count         int
	bytes         []byte
	auditPath     string
	ledgerAtWrite []byte
	readErr       error
}

func (w *causalAuditWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.count == 0 {
		w.ledgerAtWrite, w.readErr = os.ReadFile(w.auditPath)
	}
	w.count++
	w.bytes = append(w.bytes, p...)
	return len(p), nil
}

func (w *causalAuditWriter) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

func (w *causalAuditWriter) LedgerAtFirstWrite() ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]byte, len(w.ledgerAtWrite))
	copy(out, w.ledgerAtWrite)
	return out, w.readErr
}

func TestAllowRequiresDurableAuditBeforeDownstream(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-commit-allow",
		ClientID:     "agent-commit-allow",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
`),
	})
	defer p.audit.Close()

	clientOut := &bytes.Buffer{}
	downstream := &causalAuditWriter{auditPath: auditPath}
	raw := toolCallRaw(1, "file_read", map[string]any{"path": "/workspace/public/readme.md"})
	framed := append(append([]byte(nil), raw...), '\n')
	client := mcp.NewParser(bytes.NewReader(framed), clientOut)
	server := mcp.NewParser(nil, downstream)

	err := p.relayClientToServer(context.Background(), client, server)
	if err == nil {
		t.Fatalf("expected relay to return when the client stream ends")
	}
	if got := downstream.Count(); got != 1 {
		t.Fatalf("downstream write count=%d, want 1", got)
	}
	ledger, readErr := downstream.LedgerAtFirstWrite()
	if readErr != nil {
		t.Fatalf("read audit ledger at first downstream write: %v", readErr)
	}
	allowed := mustFindAllowInLedger(t, ledger, "file_read")
	if allowed.Hash == "" {
		t.Fatalf("allow record missing hash at downstream-write time: %+v", allowed)
	}
	if allowed.RequestHash == "" {
		t.Fatalf("allow record missing request_hash at downstream-write time: %+v", allowed)
	}
	if allowed.Decision != "allow" {
		t.Fatalf("allow record decision=%q, want allow", allowed.Decision)
	}
	if want := sha256Hex(framed); allowed.RequestHash != want {
		t.Fatalf("request_hash=%q, want %q", allowed.RequestHash, want)
	}
}

func TestApprovedAllowRequiresDurableAuditBeforeDownstream(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		dir := t.TempDir()
		auditPath := filepath.Join(dir, "audit.jsonl")
		approvalDir := filepath.Join(dir, "approvals")
		p := New(Config{
			ServerName:   "slack",
			SessionID:    "sess-commit-approved",
			ClientID:     "agent-commit-approved",
			AuditLogPath: auditPath,
			ApprovalDir:  approvalDir,
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
        risk: high
`),
		})
		defer p.audit.Close()

		go writeApprovalMarkerWhenRequested(approvalDir)

		clientOut := &bytes.Buffer{}
		downstream := &causalAuditWriter{auditPath: auditPath}
		raw := toolCallRaw(1, "slack_send_message", map[string]any{"text": "hello"})
		client := mcp.NewParser(bytes.NewReader(append(append([]byte(nil), raw...), '\n')), clientOut)
		server := mcp.NewParser(nil, downstream)

		err := p.relayClientToServer(context.Background(), client, server)
		if err == nil {
			t.Fatalf("expected relay to return when the client stream ends")
		}
		if strings.Contains(clientOut.String(), "durable authorization audit commit failed") {
			t.Fatalf("healthy approved allow was denied: %s", clientOut.String())
		}
		if got := downstream.Count(); got != 1 {
			t.Fatalf("downstream write count=%d, want 1; client=%q", got, clientOut.String())
		}
		ledger, readErr := downstream.LedgerAtFirstWrite()
		if readErr != nil {
			t.Fatalf("read audit ledger at first downstream write: %v", readErr)
		}
		allowed := mustFindAllowInLedger(t, ledger, "slack_send_message")
		if allowed.Hash == "" {
			t.Fatalf("approved allow record missing hash at downstream-write time: %+v", allowed)
		}
		if allowed.RequestHash == "" {
			t.Fatalf("approved allow record missing request_hash at downstream-write time: %+v", allowed)
		}
		if allowed.ApprovalReceiptHash == "" {
			t.Fatalf("approved allow record missing receipt hash at downstream-write time: %+v", allowed)
		}
	})

	t.Run("failed_ledger", func(t *testing.T) {
		dir := t.TempDir()
		auditPath := filepath.Join(dir, "audit.jsonl")
		approvalDir := filepath.Join(dir, "approvals")
		p := New(Config{
			ServerName:   "slack",
			SessionID:    "sess-commit-approved-fail",
			ClientID:     "agent-commit-approved-fail",
			AuditLogPath: auditPath,
			ApprovalDir:  approvalDir,
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
        risk: high
`),
		})

		go func() {
			for {
				matches, _ := filepath.Glob(filepath.Join(approvalDir, "req-*.json"))
				if len(matches) > 0 {
					_ = p.audit.Close()
					base := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
					_ = os.WriteFile(filepath.Join(approvalDir, base+".ok"), []byte{}, 0o600)
					return
				}
				time.Sleep(25 * time.Millisecond)
			}
		}()

		clientOut := &bytes.Buffer{}
		downstream := &observingWriter{}
		raw := toolCallRaw(1, "slack_send_message", map[string]any{"text": "hello"})
		client := mcp.NewParser(bytes.NewReader(append(append([]byte(nil), raw...), '\n')), clientOut)
		server := mcp.NewParser(nil, downstream)

		err := p.relayClientToServer(context.Background(), client, server)
		if err == nil {
			t.Fatalf("expected relay to return when the client stream ends")
		}
		if !strings.Contains(clientOut.String(), "durable authorization audit commit failed") {
			t.Fatalf("expected generic audit-commit denial after approved commit failure, got %q", clientOut.String())
		}
		if got := downstream.Count(); got != 0 {
			t.Fatalf("downstream write count=%d, want 0 after approved commit failure; bytes=%q", got, downstream.Bytes())
		}
		if p.metrics.MessagesAllowed != 0 {
			t.Fatalf("allowed metric=%d, want 0 on approved commit failure", p.metrics.MessagesAllowed)
		}
		if p.metrics.MessagesApproved != 0 {
			t.Fatalf("approved metric=%d, want 0 on approved commit failure", p.metrics.MessagesApproved)
		}
		if p.metrics.MessagesDenied != 1 {
			t.Fatalf("denied metric=%d, want 1 on approved commit failure", p.metrics.MessagesDenied)
		}
	})
}

func TestNonDurableAuditSinkFailClosedNoRelay(t *testing.T) {
	p := New(Config{
		ServerName: "workspace",
		SessionID:  "sess-commit-stderr",
		ClientID:   "agent-commit-stderr",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
`),
	})

	clientOut := &bytes.Buffer{}
	downstream := &observingWriter{}
	raw := toolCallRaw(1, "file_read", map[string]any{"path": "/workspace/public/readme.md"})
	client := mcp.NewParser(bytes.NewReader(append(append([]byte(nil), raw...), '\n')), clientOut)
	server := mcp.NewParser(nil, downstream)

	err := p.relayClientToServer(context.Background(), client, server)
	if err == nil {
		t.Fatalf("expected relay to return when the client stream ends")
	}
	if !strings.Contains(clientOut.String(), "durable authorization audit commit failed") {
		t.Fatalf("expected generic audit-commit denial for stderr sink, got %q", clientOut.String())
	}
	if got := downstream.Count(); got != 0 {
		t.Fatalf("downstream write count=%d, want 0 for non-durable sink; bytes=%q", got, downstream.Bytes())
	}
	if p.metrics.MessagesAllowed != 0 {
		t.Fatalf("allowed metric=%d, want 0 for non-durable sink", p.metrics.MessagesAllowed)
	}
	if p.metrics.MessagesDenied != 1 {
		t.Fatalf("denied metric=%d, want 1 for non-durable sink", p.metrics.MessagesDenied)
	}
}

func TestAuditCommitFailureFailClosedRemoteNoRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-commit-remote",
		ClientID:     "agent-commit-remote",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
`),
	})
	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}

	clientOut := &bytes.Buffer{}
	remote := &observingTransport{}
	raw := toolCallRaw(1, "file_read", map[string]any{"path": "/workspace/public/readme.md"})
	client := mcp.NewParser(bytes.NewReader(append(append([]byte(nil), raw...), '\n')), clientOut)

	err := p.relayClientToRemoteServer(context.Background(), client, remote)
	if err == nil {
		t.Fatalf("expected remote relay to return when the client stream ends")
	}
	if !strings.Contains(clientOut.String(), "durable authorization audit commit failed") {
		t.Fatalf("expected generic audit-commit denial to the client, got %q", clientOut.String())
	}
	if got := remote.Count(); got != 0 {
		t.Fatalf("remote EncodeRaw count=%d, want 0", got)
	}
	if p.metrics.MessagesAllowed != 0 {
		t.Fatalf("allowed metric=%d, want 0 on remote commit failure", p.metrics.MessagesAllowed)
	}
	if p.metrics.MessagesDenied != 1 {
		t.Fatalf("denied metric=%d, want 1 on remote commit failure", p.metrics.MessagesDenied)
	}
}

// TestAuditLedgerRotationFailClosedNoRelay is the H19 round-4 RED test for
// the stdio transport: if the configured audit ledger path is rotated or
// rebound while the proxy is running, the next allowed tools/call must be
// denied with zero downstream relay, no allow/approved metrics, no session
// taint, and no tool_call_allowed record in the replacement ledger. On the
// vulnerable baseline, CommitAuthorization writes through the stale fd and
// the call is relayed.
func TestAuditLedgerRotationFailClosedNoRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-rotation-stdio",
		ClientID:     "agent-rotation-stdio",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
taints:
  - name: "sensitive_file_accessed"
    description: "Session has read sensitive workspace data"
    source_tools: ["file_read"]
    source_patterns: ["**/secrets/**", "**/*.env"]
`),
	})
	defer p.audit.Close()

	// Rotate the configured audit ledger: rename the opened sink away and
	// install a fresh regular replacement at the same path.
	if err := os.Rename(auditPath, auditPath+".rotated"); err != nil {
		t.Fatalf("rotate audit away: %v", err)
	}
	if err := os.WriteFile(auditPath, nil, 0o600); err != nil {
		t.Fatalf("fresh replacement ledger: %v", err)
	}

	clientOut := &bytes.Buffer{}
	downstream := &observingWriter{}
	raw := toolCallRaw(1, "file_read", map[string]any{"path": "/workspace/secrets/customer-tokens.txt"})
	client := mcp.NewParser(bytes.NewReader(append(raw, '\n')), clientOut)
	server := mcp.NewParser(nil, downstream)

	err := p.relayClientToServer(context.Background(), client, server)
	if err == nil {
		t.Fatalf("expected relay to return when the client stream ends")
	}
	if !strings.Contains(clientOut.String(), "durable authorization audit commit failed") {
		t.Fatalf("expected generic audit-commit denial to the client, got %q", clientOut.String())
	}
	if got := downstream.Count(); got != 0 {
		t.Fatalf("downstream write count=%d, want 0 (relay must be denied after audit rotation); bytes=%q", got, downstream.Bytes())
	}
	if got := downstream.Bytes(); len(got) != 0 {
		t.Fatalf("downstream bytes=%q, want empty", got)
	}
	if p.metrics.MessagesAllowed != 0 {
		t.Fatalf("allowed metric=%d, want 0 on audit rotation", p.metrics.MessagesAllowed)
	}
	if p.metrics.MessagesApproved != 0 {
		t.Fatalf("approved metric=%d, want 0 on audit rotation", p.metrics.MessagesApproved)
	}
	if p.metrics.MessagesDenied != 1 {
		t.Fatalf("denied metric=%d, want 1 on audit rotation", p.metrics.MessagesDenied)
	}
	if p.session.HasTaint("sensitive_file_accessed") {
		t.Fatalf("session taint must not mutate on audit rotation, taints=%+v", p.session.TaintsSnapshot())
	}
	replacement, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read replacement ledger: %v", err)
	}
	if strings.Contains(string(replacement), "tool_call_allowed") {
		t.Fatalf("replacement ledger must not contain a tool_call_allowed record, got %q", replacement)
	}
}

// TestAuditLedgerRotationFailClosedRemoteNoRelay is the H19 round-4 RED test
// for the remote transport: rotation of the configured audit path must deny
// with zero EncodeRaw writes and no allowed-state mutation. On the vulnerable
// baseline the call is relayed.
func TestAuditLedgerRotationFailClosedRemoteNoRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-rotation-remote",
		ClientID:     "agent-rotation-remote",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
`),
	})
	defer p.audit.Close()

	if err := os.Rename(auditPath, auditPath+".rotated"); err != nil {
		t.Fatalf("rotate audit away: %v", err)
	}
	if err := os.WriteFile(auditPath, nil, 0o600); err != nil {
		t.Fatalf("fresh replacement ledger: %v", err)
	}

	clientOut := &bytes.Buffer{}
	remote := &observingTransport{}
	raw := toolCallRaw(1, "file_read", map[string]any{"path": "/workspace/public/readme.md"})
	client := mcp.NewParser(bytes.NewReader(append(raw, '\n')), clientOut)

	err := p.relayClientToRemoteServer(context.Background(), client, remote)
	if err == nil {
		t.Fatalf("expected remote relay to return when the client stream ends")
	}
	if !strings.Contains(clientOut.String(), "durable authorization audit commit failed") {
		t.Fatalf("expected generic audit-commit denial to the client, got %q", clientOut.String())
	}
	if got := remote.Count(); got != 0 {
		t.Fatalf("remote EncodeRaw count=%d, want 0 on audit rotation", got)
	}
	if p.metrics.MessagesAllowed != 0 {
		t.Fatalf("allowed metric=%d, want 0 on audit rotation", p.metrics.MessagesAllowed)
	}
	if p.metrics.MessagesApproved != 0 {
		t.Fatalf("approved metric=%d, want 0 on audit rotation", p.metrics.MessagesApproved)
	}
	if p.metrics.MessagesDenied != 1 {
		t.Fatalf("denied metric=%d, want 1 on audit rotation", p.metrics.MessagesDenied)
	}
}

type observingTransport struct {
	mu    sync.Mutex
	count int
}

func (t *observingTransport) ReadRaw() (json.RawMessage, error) {
	return nil, io.EOF
}

func (t *observingTransport) EncodeRaw(raw json.RawMessage) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.count++
	return nil
}

func (t *observingTransport) Close() error { return nil }

func (t *observingTransport) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count
}

var _ transport.Transport = (*observingTransport)(nil)

func writeApprovalMarkerWhenRequested(dir string) {
	for {
		matches, _ := filepath.Glob(filepath.Join(dir, "req-*.json"))
		if len(matches) > 0 {
			base := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
			_ = os.WriteFile(filepath.Join(dir, base+".ok"), []byte{}, 0o600)
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func mustFindAllowInLedger(t *testing.T, data []byte, tool string) audit.Event {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal audit event: %v\n%s", err, line)
		}
		if ev.EventType == audit.EventToolAllowed && ev.Tool == tool {
			return ev
		}
	}
	t.Fatalf("tool_call_allowed record for %s not present at downstream-write time; ledger=%s", tool, string(data))
	return audit.Event{}
}
