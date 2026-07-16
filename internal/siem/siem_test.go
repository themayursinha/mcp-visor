package siem

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
)

func TestSyslog5424Format(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Format = FormatSyslog5424
	cfg.Hostname = "test-host"

	exp := &Exporter{
		format:   cfg.Format,
		hostname: cfg.Hostname,
		appName:  cfg.AppName,
	}

	event := audit.Event{
		Timestamp: "2026-05-26T10:00:00Z",
		EventType: audit.EventToolDenied,
		SessionID: "sess-001",
		AgentID:   "agent-001",
		Server:    "shell",
		Tool:      "shell_exec",
		Decision:  "deny",
		Reason:    "dangerous command pattern detected",
		RiskLevel: "critical",
	}

	output := string(exp.formatSyslog5424(event))
	if !strings.HasPrefix(output, "<") {
		t.Errorf("syslog output should start with PRI: %s", output)
	}
	if !strings.Contains(output, "mcp_visor") {
		t.Errorf("syslog output should contain app name: %s", output)
	}
	if !strings.Contains(output, event.SessionID) {
		t.Errorf("syslog output should contain session ID: %s", output)
	}
	if !strings.Contains(output, "tool=shell_exec") {
		t.Errorf("syslog output should contain tool name: %s", output)
	}
}

func TestJSONFormat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Format = FormatJSON
	cfg.Hostname = "test-host"

	exp := &Exporter{
		format:   cfg.Format,
		hostname: cfg.Hostname,
		appName:  cfg.AppName,
	}

	event := audit.Event{
		Timestamp:  "2026-05-26T10:00:00Z",
		EventType:  audit.EventToolAllowed,
		SessionID:  "sess-002",
		AgentID:    "agent-002",
		Server:     "filesystem",
		Tool:       "file_read",
		Decision:   "allow",
		Reason:     "within allowed paths",
		RiskLevel:  "medium",
		Hash:       "abc",
		PrevHash:   "def",
		ChainIndex: 9,
		Arguments:  map[string]any{"token": "sk-secret"},
	}

	output := exp.formatJSON(event)
	var envelope map[string]any
	if err := json.Unmarshal(output, &envelope); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}
	if envelope["session_id"] != "sess-002" {
		t.Errorf("session_id: got %v", envelope["session_id"])
	}
	if envelope["decision"] != "allow" {
		t.Errorf("decision: got %v", envelope["decision"])
	}
	if envelope["hostname"] != "test-host" {
		t.Errorf("hostname: got %v", envelope["hostname"])
	}
	// Reduced export contract: no hash-chain fields and no arguments payload.
	for _, key := range []string{"hash", "prev_hash", "chain_index", "arguments"} {
		if _, ok := envelope[key]; ok {
			t.Errorf("SIEM JSON export must omit %s (reduced/pre-logger contract)", key)
		}
	}
	// Reason is copied as-is; built-in SIEM does not re-redact.
	if envelope["reason"] != "within allowed paths" {
		t.Errorf("reason: got %v", envelope["reason"])
	}
}

func TestCEFFormat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Format = FormatCEF

	exp := &Exporter{
		format:   cfg.Format,
		hostname: cfg.Hostname,
		appName:  cfg.AppName,
	}

	event := audit.Event{
		Timestamp: "2026-05-26T10:00:00Z",
		EventType: audit.EventToolChainDetected,
		SessionID: "sess-003",
		AgentID:   "agent-003",
		Server:    "filesystem",
		Tool:      "http_post",
		Decision:  "deny",
		Reason:    "data exfiltration chain detected",
		RiskLevel: "high",
	}

	output := string(exp.formatCEF(event))
	if !strings.HasPrefix(output, "CEF:0|") {
		t.Errorf("CEF output should start with CEF prefix: %s", output)
	}
	if !strings.Contains(output, "MCP|mcp-visor") {
		t.Errorf("CEF output should contain product info: %s", output)
	}
	if !strings.Contains(output, "RiskLevel") {
		t.Errorf("CEF output should contain risk level extension: %s", output)
	}
}

func TestFileExport(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "siem-export.jsonl")

	exp, err := NewExporter(Config{
		Format:  FormatJSON,
		Targets: []string{logPath},
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	defer exp.Close()

	event := audit.Event{
		Timestamp: "2026-05-26T10:00:00Z",
		EventType: audit.EventToolAllowed,
		SessionID: "sess-file-test",
		AgentID:   "agent-file",
		Server:    "filesystem",
		Tool:      "file_read",
		Decision:  "allow",
		Reason:    "test export",
		RiskLevel: "low",
	}

	if err := exp.Export(event); err != nil {
		t.Fatalf("Export: %v", err)
	}

	exp.mu.Lock()
	defer exp.mu.Unlock()
	for _, w := range exp.writers {
		w.Close()
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read export file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var envelope map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &envelope); err != nil {
		t.Fatalf("unmarshal exported line: %v", err)
	}
	if envelope["session_id"] != "sess-file-test" {
		t.Errorf("session_id mismatch: %v", envelope["session_id"])
	}
}

func TestEmptyTargets(t *testing.T) {
	exp, err := NewExporter(Config{
		Format: FormatJSON,
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}

	event := audit.Event{EventType: audit.EventSessionStarted}
	if err := exp.Export(event); err != nil {
		t.Fatalf("Export with no writers should succeed: %v", err)
	}
}

func TestApprovalRequiredSyslog(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Format = FormatSyslog5424
	cfg.Hostname = "prod-visor"

	exp := &Exporter{
		format:   cfg.Format,
		hostname: cfg.Hostname,
		appName:  cfg.AppName,
	}

	event := audit.Event{
		Timestamp: "2026-05-26T10:00:00Z",
		EventType: audit.EventToolApprovalRequired,
		SessionID: "sess-approval",
		AgentID:   "copilot",
		Server:    "cloud",
		Tool:      "aws_iam_create_user",
		Decision:  "require_approval",
		Reason:    "critical cloud operation",
		RiskLevel: "critical",
	}

	output := string(exp.formatSyslog5424(event))
	if !strings.Contains(output, "prod-visor") {
		t.Errorf("syslog should contain hostname: %s", output)
	}
	if !strings.Contains(output, "aws_iam_create_user") {
		t.Errorf("syslog should contain tool: %s", output)
	}
}
