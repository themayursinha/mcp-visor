package proxy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func skillPromotionYAML() string {
	return `
version: "1.0"
description: "Install only workspace-lint"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: low
      - name: "install_skill"
        allowed: true
        risk: high
        rules:
          - type: allow_skill
            patterns:
              - "workspace-lint"
`
}

func TestSkillProxyDeniesPromotionBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-skill",
		ClientID:     "agent-skill",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, skillPromotionYAML()),
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
	_, action = p.interceptAndModify(toolCallRaw(2, "install_skill", map[string]any{
		"skill": "workspace-lint",
	}), client)
	if action != "forward" {
		t.Fatalf("mandated skill must forward, got %s; response=%s", action, out.String())
	}

	out.Reset()
	_, action = p.interceptAndModify(toolCallRaw(3, "install_skill", map[string]any{
		"skill": "attacker-registry",
	}), client)
	if action != "denied" {
		t.Fatalf("attacker skill must deny before relay, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "unauthorized skill promotion") {
		t.Fatalf("denial must name unauthorized skill promotion, got %s", out.String())
	}

	if err := p.audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "install_skill")
	if denied.Decision != "deny" {
		t.Fatalf("expected deny decision in audit, got %+v", denied)
	}
	for _, token := range []string{
		"argument class SKILL",
		"effect class AUTHORITY",
		"authority transition EXPERIENCE->SKILL",
	} {
		if !strings.Contains(denied.Reason, token) {
			t.Fatalf("audit reason missing evidence %q: %+v", token, denied)
		}
	}
}

func TestSkillProxyDeniesShadowAliasBeforeRelay(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-skill-alias",
		ClientID:     "agent-skill",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, skillPromotionYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	_, action := p.interceptAndModify(toolCallRaw(1, "install_skill", map[string]any{
		"skill_name": "workspace-lint",
		"skill":      "attacker-registry",
	}), client)
	if action != "denied" {
		t.Fatalf("shadow skill alias must deny before relay, got %s; response=%s", action, out.String())
	}
}

func TestSkillProxyHistoryDoesNotAuthorizeSkill(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workspace",
		SessionID:    "sess-skill-history",
		ClientID:     "agent-skill",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, skillPromotionYAML()),
	})
	defer p.audit.Close()

	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	for id := 1; id <= 2; id++ {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(id, "install_skill", map[string]any{
			"skill": "attacker-registry",
		}), client)
		if action != "denied" {
			t.Fatalf("call %d: repeated attacker skill must stay denied, got %s", id, action)
		}
	}
	out.Reset()
	_, action := p.interceptAndModify(toolCallRaw(3, "install_skill", map[string]any{
		"skill": "workspace-lint",
	}), client)
	if action != "forward" {
		t.Fatalf("mandated skill must still forward after denials, got %s; response=%s", action, out.String())
	}
}
