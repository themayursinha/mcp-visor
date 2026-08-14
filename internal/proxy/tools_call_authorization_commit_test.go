package proxy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

func allowCommitPolicy(t *testing.T, server, tool string) *policy.Policy {
	t.Helper()
	return mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "`+server+`"
    allowed: true
    tools:
      - name: "`+tool+`"
        allowed: true
`)
}

// assertCommitDenied verifies the durable-commit deny contract: zero relay,
// generic client denial, denied metric +1, allowed/approved unchanged.
func assertCommitDenied(t *testing.T, p *Proxy, out *bytes.Buffer, action string) {
	t.Helper()
	if action != "denied" {
		t.Fatalf("expected denied on failed durable commit, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "execution denied: durable authorization audit commit failed") {
		t.Fatalf("expected generic client denial, got %s", out.String())
	}
	if p.metrics.MessagesDenied != 1 {
		t.Fatalf("denied metric = %d, want 1", p.metrics.MessagesDenied)
	}
	if p.metrics.MessagesAllowed != 0 || p.metrics.MessagesApproved != 0 {
		t.Fatalf("allowed/approved metrics must not change: allowed=%d approved=%d", p.metrics.MessagesAllowed, p.metrics.MessagesApproved)
	}
	if strings.Contains(out.String(), `"result"`) {
		t.Fatalf("unexpected relayed result, got %s", out.String())
	}
}

func TestAuthorizationCommitFailureDeniesWithoutRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-commit-fail",
		ClientID:     "agent-commit-fail",
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
taints:
  - name: "sensitive_file_accessed"
    source_tools: ["file_read"]
    source_patterns: ["**/secrets/**"]
`),
	})
	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{"path": "/workspace/public/readme.md"}), client)

	assertCommitDenied(t, p, out, action)
	if p.session.HasTaint("sensitive_file_accessed") {
		t.Fatal("session must not be tainted when durable commit fails")
	}
}

func TestAuthorizationCommitPrecedesRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-commit-first",
		ClientID:     "agent-commit-first",
		AuditLogPath: auditPath,
		Policy:       allowCommitPolicy(t, "workspace", "file_read"),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{"path": "/workspace/public/readme.md"}), client)
	if action != "forward" {
		t.Fatalf("expected forward, got %s; response=%s", action, out.String())
	}

	// The relay loop writes the first downstream message only after
	// processToolsCall returns forward. At that point the ledger must already
	// contain a complete, hash-linked allow record for this tool.
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Fatal("committed record must be newline-terminated")
	}
	ev := findAuditEvent(t, auditPath, audit.EventToolAllowed, "file_read")
	if ev.Decision != "allow" || ev.Hash == "" {
		t.Fatalf("expected complete hash-linked allow record, got %+v", ev)
	}
}

func TestAuthorizationCommitFailureDeniesRemoteWithoutRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "remote-demo",
		ServerURL:    "http://127.0.0.1:19999/mcp",
		SessionID:    "sess-remote-commit-fail",
		ClientID:     "agent-remote-commit-fail",
		AuditLogPath: auditPath,
		Policy:       allowCommitPolicy(t, "remote-demo", "file_read"),
	})
	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModifyRemote(toolCallRaw(1, "file_read", map[string]any{"path": "/tmp/x"}), client)

	assertCommitDenied(t, p, out, action)
}

func TestAuthorizationCommitFailureAfterApprovalDeniesWithoutRelay(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "slack",
		ApprovalDir:  dir,
		SessionID:    "sess-approval-commit-fail",
		ClientID:     "agent-approval-commit-fail",
		AuditLogPath: auditPath,
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
				// Close the ledger immediately before granting approval so
				// the terminal allow commit fails closed.
				_ = p.audit.Close()
				_ = os.WriteFile(filepath.Join(dir, base+".ok"), []byte{}, 0o600)
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "slack_send_message", map[string]any{"text": "hello"}), client)

	assertCommitDenied(t, p, out, action)
}

func TestAuthorizationCommitRequiresConfiguredDurableSink(t *testing.T) {
	// No AuditLogPath: MustLogger falls back to stderr, which is not a durable
	// authorization sink. Allow must fail closed with zero relay.
	p := New(Config{
		ServerName: "workspace",
		SessionID:  "sess-no-durable-sink",
		ClientID:   "agent-no-durable-sink",
		Policy:     allowCommitPolicy(t, "workspace", "file_read"),
	})

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{"path": "/workspace/public/readme.md"}), client)

	assertCommitDenied(t, p, out, action)
}
