package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

func TestHotReloadAtomicallyRefreshesRedactorAuditAndApproval(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")

	initial := `
version: "1.0"
default_action: deny
settings:
  approval_timeout_seconds: 30
servers:
  - name: "fs"
    allowed: true
    tools:
      - name: "read_file"
        allowed: true
redaction:
  patterns:
    - name: "token_a"
      regex: "TOKENA[0-9]+"
      replacement: "[REDACTED-A]"
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
		ServerName:   "fs",
		Policy:       w.Policy(),
		Engine:       eng,
		AuditLogPath: auditPath,
		ApprovalDir:  approvalDir,
	})

	before := p.currentRedactor()
	redacted, result := before.RedactArgs(map[string]any{"secret": "TOKENA123"})
	if !result.Redacted || redacted["secret"] != "[REDACTED-A]" {
		t.Fatalf("pre-reload redaction failed: %+v %+v", redacted, result)
	}
	if p.currentApproval().Timeout() != 30*time.Second {
		t.Fatalf("pre-reload approval timeout = %v", p.currentApproval().Timeout())
	}

	p.logAudit(audit.Event{
		EventType: audit.EventToolAllowed,
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
		Server:    "fs",
		Tool:      "read_file",
		Reason:    "pre TOKENA999",
	})

	updated := `
version: "1.0"
default_action: deny
settings:
  approval_timeout_seconds: 7
servers:
  - name: "fs"
    allowed: true
    tools:
      - name: "read_file"
        allowed: true
redaction:
  patterns:
    - name: "token_b"
      regex: "TOKENB[0-9]+"
      replacement: "[REDACTED-B]"
`
	if err := os.WriteFile(policyPath, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()

	after := p.currentRedactor()
	if after == before {
		t.Fatal("expected redactor pointer to be replaced after reload")
	}

	oldOut, oldRes := after.RedactArgs(map[string]any{"secret": "TOKENA123"})
	if oldRes.Redacted {
		t.Fatalf("old pattern should not apply after reload, got %+v", oldOut)
	}
	newOut, newRes := after.RedactArgs(map[string]any{"secret": "TOKENB42"})
	if !newRes.Redacted || newOut["secret"] != "[REDACTED-B]" {
		t.Fatalf("new pattern not applied: %+v %+v", newOut, newRes)
	}

	if got := p.currentApproval().Timeout(); got != 7*time.Second {
		t.Fatalf("approval timeout after reload = %v, want 7s", got)
	}

	p.logAudit(audit.Event{
		EventType: audit.EventToolAllowed,
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
		Server:    "fs",
		Tool:      "read_file",
		Reason:    "post TOKENB77 leftover",
	})

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "policy_reloaded") {
		t.Fatalf("expected policy_reloaded audit event, got %s", content)
	}
	if strings.Contains(content, "TOKENB77") {
		t.Fatalf("expected post-reload audit pattern to redact TOKENB, got %s", content)
	}
	// Pre-reload reason should have been redacted by TOKENA pattern.
	if strings.Contains(content, "TOKENA999") {
		t.Fatalf("expected pre-reload audit pattern to redact TOKENA, got %s", content)
	}
}

func TestHotReloadInvalidPolicyKeepsRuntimeSurfaces(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	initial := `
version: "1.0"
default_action: deny
settings:
  approval_timeout_seconds: 11
servers:
  - name: "fs"
    allowed: true
    tools:
      - name: "read_file"
        allowed: true
redaction:
  patterns:
    - name: "keep_me"
      regex: "KEEPME[0-9]+"
      replacement: "[KEEP]"
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
		ServerName: "fs",
		Policy:     w.Policy(),
		Engine:     eng,
	})
	beforeTimeout := p.currentApproval().Timeout()
	beforeRed := p.currentRedactor()

	if err := os.WriteFile(policyPath, []byte("not: valid: yaml: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()

	if p.currentRedactor() != beforeRed {
		t.Fatal("invalid reload must keep previous redactor")
	}
	if p.currentApproval().Timeout() != beforeTimeout {
		t.Fatalf("invalid reload changed approval timeout: %v", p.currentApproval().Timeout())
	}
	out, res := p.currentRedactor().RedactArgs(map[string]any{"v": "KEEPME9"})
	if !res.Redacted || out["v"] != "[KEEP]" {
		t.Fatalf("expected previous redaction pattern retained: %+v %+v", out, res)
	}
}
