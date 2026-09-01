package proxy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func TestProxyDeniesEmptyTimeOutsideActionBeforeRelay(t *testing.T) {
	day := strings.ToLower(time.Now().Weekday().String())
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "neo"
    allowed: true
    tools:
      - name: "check_syntax"
        allowed: true
        rules:
          - type: require_approval_always
          - type: require_path_literal
time_restrictions:
  - name: "weekends"
    servers: ["neo"]
    tools: ["check_syntax"]
    denied_days: ["` + day + `"]
`
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "neo",
		SessionID:    "sess-eval-fold-time",
		ClientID:     "agent-path-shell",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, yaml),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "check_syntax", map[string]any{
		"path": "/workspace/src/app.mjs",
	}), client)
	if action != "denied" {
		t.Fatalf("empty outside_action must deny before approval wait/relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "unsupported policy action") {
		t.Fatalf("denial must name the unsupported action, got %s", out.String())
	}
}
