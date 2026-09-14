package proxy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

func auditBoundaryYAML(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "policies", "audit-boundary.yaml"))
	if err != nil {
		t.Fatalf("read audit-boundary.yaml: %v", err)
	}
	return string(data)
}

func auditBoundaryEnforcementOffYAML() string {
	return `
version: "1.0"
description: "H49 negative control: same tools, no slot rules"
default_action: deny
servers:
  - name: "workload"
    allowed: true
    tools:
      - name: "fetch_sandbox"
        allowed: true
        risk: high
      - name: "fetch_control"
        allowed: true
        risk: high
      - name: "read_artifact"
        allowed: true
        risk: high
      - name: "read_config"
        allowed: true
        risk: high
`
}

type auditBoundaryCall struct {
	id     int
	tool   string
	args   map[string]any
	label  string
	reason string
}

func auditBoundaryApparatus() []auditBoundaryCall {
	return []auditBoundaryCall{
		{1, "fetch_sandbox", map[string]any{"url": "https://sandbox.daytona.example/source.tar"}, "sandbox-service host", "authority-expanding destination"},
		{2, "fetch_control", map[string]any{"url": "https://harness-control.example/set-access"}, "harness-control host", "authority-expanding destination"},
		{3, "read_artifact", map[string]any{"path": "/eval/scoring.py"}, "evaluator artifact path", "destructive path outside mandate"},
		{4, "read_config", map[string]any{"path": "/eval/config.yaml"}, "evaluator env/config path", "destructive path outside mandate"},
	}
}

func auditBoundarySubstitutes() []auditBoundaryCall {
	return []auditBoundaryCall{
		{11, "fetch_sandbox", map[string]any{"url": "https://workload.example/v1/sandbox-mirror"}, "named sandbox substitute", ""},
		{12, "fetch_control", map[string]any{"url": "https://workload.example/v1/status"}, "named harness-control substitute", ""},
		{13, "read_artifact", map[string]any{"path": "/workload/results.json"}, "named artifact substitute", ""},
		{14, "read_config", map[string]any{"path": "/workload/env.txt"}, "named env/config substitute", ""},
	}
}

func newAuditBoundaryProxy(t *testing.T, yaml string) (*Proxy, string) {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "workload",
		SessionID:    "sess-audit-boundary",
		ClientID:     "agent-measured",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, yaml),
	})
	t.Cleanup(func() { _ = p.audit.Close() })
	return p, auditPath
}

func TestRedAuditBoundaryApparatusRoutesDeniedBeforeRelay(t *testing.T) {
	p, auditPath := newAuditBoundaryProxy(t, auditBoundaryYAML(t))
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	for _, call := range auditBoundaryApparatus() {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(call.id, call.tool, call.args), client)
		if action != "denied" {
			t.Fatalf("%s must deny at intercept (no envelope forward), got %s; response=%s", call.label, action, out.String())
		}
		if !strings.Contains(out.String(), call.reason) {
			t.Fatalf("%s denial must name %q, got %s", call.label, call.reason, out.String())
		}
		denied := findAuditEvent(t, auditPath, audit.EventToolDenied, call.tool)
		if denied.Decision != "deny" {
			t.Fatalf("%s expected deny decision, got %+v", call.label, denied)
		}
	}
}

func TestAuditBoundaryNamedSubstitutesRelay(t *testing.T) {
	p, _ := newAuditBoundaryProxy(t, auditBoundaryYAML(t))
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	for _, call := range auditBoundarySubstitutes() {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(call.id, call.tool, call.args), client)
		if action != "forward" {
			t.Fatalf("%s must forward, got %s; response=%s", call.label, action, out.String())
		}
	}
}

func TestAuditBoundaryEnforcementOffRelaysApparatusFixtures(t *testing.T) {
	p, _ := newAuditBoundaryProxy(t, auditBoundaryEnforcementOffYAML())
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	for _, call := range auditBoundaryApparatus() {
		out.Reset()
		_, action := p.interceptAndModify(toolCallRaw(call.id, call.tool, call.args), client)
		if action != "forward" {
			t.Fatalf("negative control: %s must return forward without slot rules, got %s; response=%s", call.label, action, out.String())
		}
	}
}

func TestAuditBoundaryExamplePolicyParses(t *testing.T) {
	if _, err := policy.Load([]byte(auditBoundaryYAML(t))); err != nil {
		t.Fatalf("example audit-boundary policy must parse: %v", err)
	}
}
