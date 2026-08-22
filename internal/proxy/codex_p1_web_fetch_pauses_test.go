package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/capability"
)

// Codex P1 regression (PR #76): a web_fetch({"url":"https://example.com"})
// with opted-in eval must PAUSE (route to approval), not ALLOW. Uses the
// REAL ChainEvaluator via policy settings.capability_accounting: true —
// url arg must PAUSE (route to approval), not ALLOW.
func TestP1WebFetchOptedInPausesNotAllow(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")

	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-p1-proxy",
		ClientID:     "agent-proxy-p1",
		AuditLogPath: auditPath,
		ApprovalDir:  approvalDir,
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
	defer p.audit.Close()
	if p.capEval == nil {
		t.Fatal("capEval must be constructed with capability_accounting: true")
	}

	// Operator approves as soon as the request appears.
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

	action := callTool(t, p, 1, "web_fetch", map[string]any{"url": "https://example.com"})
	if action != "forward" {
		t.Fatalf("web_fetch with opted-in eval must PAUSE → route to approval → forward on operator approval, got action=%q", action)
	}
	select {
	case <-approved:
	case <-time.After(5 * time.Second):
		t.Fatal("web_fetch approval request never reached the approval dir; the call must PAUSE (route to approval), not ALLOW")
	}
}

var _ = capability.DecisionPauseRequireProof
