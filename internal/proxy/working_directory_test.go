package proxy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func environmentLaunderingYAML() string {
	return `
version: "1.0"
description: "Run decoder only under /workspace/safe"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: low
      - name: "run_python"
        allowed: true
        risk: high
        rules:
          - type: allow_working_directory
            patterns:
              - "/workspace/safe"
              - "/workspace/safe/**"
`
}

func TestWorkingDirectoryProxyDeniesUntrustedCwdBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-env-launder",
		ClientID:     "agent-rehberger",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, environmentLaunderingYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{
		"path": "/workspace/tickets.md",
	}), client)
	if action != "forward" {
		t.Fatalf("legitimate local read must forward, got %s; response=%s", action, out.String())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(2, "run_python", map[string]any{
		"script": "/workspace/decoder.py",
		"cwd":    "/workspace/safe",
	}), client)
	if action != "forward" {
		t.Fatalf("mandated cwd must forward, got %s; response=%s", action, out.String())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(3, "run_python", map[string]any{
		"script": "/workspace/decoder.py",
		"cwd":    "/tmp/attacker-extract",
	}), client)
	if action != "denied" {
		t.Fatalf("untrusted extract cwd must deny before relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "untrusted execution environment") {
		t.Fatalf("denial must name untrusted execution environment, got %s", out.String())
	}

	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "run_python")
	if denied.Decision != "deny" {
		t.Fatalf("expected deny decision in audit, got %+v", denied)
	}
	for _, token := range []string{
		"argument class PATH",
		"effect class EXECUTION",
		"authority transition MANDATE->ENVIRONMENT",
	} {
		if !strings.Contains(denied.Reason, token) {
			t.Fatalf("audit reason missing evidence %q: %+v", token, denied)
		}
	}
}

func TestWorkingDirectoryProxyDeniesShadowAliasBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-env-alias",
		ClientID:     "agent-rehberger",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, environmentLaunderingYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "run_python", map[string]any{
		"cwd":               "/workspace/safe",
		"working_directory": "/tmp/attacker-extract",
	}), client)
	if action != "denied" {
		t.Fatalf("shadow working_directory alias must deny before relay, got %s; response=%s", action, out.String())
	}
}

func TestWorkingDirectoryProxyHistoryDoesNotAuthorizeCwd(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-env-history",
		ClientID:     "agent-rehberger",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, environmentLaunderingYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	for id := 1; id <= 2; id++ {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(id, "run_python", map[string]any{
			"cwd": "/tmp/attacker-extract",
		}), client)
		if action != "denied" {
			t.Fatalf("call %d: repeated untrusted cwd must stay denied, got %s", id, action)
		}
	}
	out.Reset()
	_, action := p.interceptAndModify(toolCallRaw(3, "run_python", map[string]any{
		"cwd": "/workspace/safe",
	}), client)
	if action != "forward" {
		t.Fatalf("mandated cwd must still forward after denials, got %s; response=%s", action, out.String())
	}
}
