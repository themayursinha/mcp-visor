package main_test

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeRestrictivePolicy(t *testing.T, serverPath string) string {
	t.Helper()
	tmp, err := os.CreateTemp("", "mcp-visor-restrict-policy-*.yaml")
	if err != nil {
		t.Fatalf("create temp policy: %v", err)
	}

	policy := fmt.Sprintf(`version: "1.0"
description: "Restrictive test policy"
default_action: deny
servers:
  - name: "%s"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        rules:
          - type: deny_path
            patterns:
              - "/etc/passwd"
              - "/etc/shadow"
              - "**/.env"
              - "/app/secrets/**"
      - name: "shell_exec"
        allowed: true
        rules:
          - type: deny_command_pattern
            patterns:
              - "curl.*\\|.*bash"
              - "wget.*\\|.*bash"
      - name: "http_post"
        allowed: true
      - name: "slack_send_message"
        allowed: true
`, serverPath)

	if _, err := tmp.WriteString(policy); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	tmp.Close()
	t.Cleanup(func() { os.Remove(tmp.Name()) })
	return tmp.Name()
}

func sendInitMessages(w *bufio.Writer, r *bufio.Reader) {
	initMsg := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "test-client",
				"version": "1.0.0",
			},
		},
	}
	_ = sendMessage(w, initMsg)
	_, _ = readMessage(r)

	initializedMsg := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	_ = sendMessage(w, initializedMsg)
}

var idCounter = 100

func nextID() int {
	idCounter++
	return idCounter
}

func TestSensitiveFileAccessDenied(t *testing.T) {
	mockServer := buildMockServer(t)
	visor := buildVisor(t)
	policyFile := writeRestrictivePolicy(t, mockServer)

	cmd := exec.Command(visor, "serve", "-server", mockServer, "-policy", policyFile)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	sendInitMessages(w, r)

	sensitiveFiles := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/home/user/.env",
	}

	for _, path := range sensitiveFiles {
		t.Run("deny_"+path, func(t *testing.T) {
			call := map[string]any{
				"jsonrpc": "2.0",
				"id":      nextID(),
				"method":  "tools/call",
				"params": map[string]any{
					"name":      "file_read",
					"arguments": map[string]any{"path": path},
				},
			}
			_ = sendMessage(w, call)
			resp, err := readMessage(r)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if resp["error"] == nil {
				t.Errorf("file_read '%s' should be denied by path rule", path)
			} else {
				t.Logf("correctly denied: %v", resp["error"])
			}
		})
	}
}

func TestAllowedFileAccess(t *testing.T) {
	mockServer := buildMockServer(t)
	visor := buildVisor(t)
	policyFile := writeRestrictivePolicy(t, mockServer)

	cmd := exec.Command(visor, "serve", "-server", mockServer, "-policy", policyFile)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	sendInitMessages(w, r)

	call := map[string]any{
		"jsonrpc": "2.0",
		"id":      nextID(),
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "file_read",
			"arguments": map[string]any{"path": "/tmp/test"},
		},
	}
	_ = sendMessage(w, call)
	resp, err := readMessage(r)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp["error"] != nil {
		t.Errorf("file_read should be allowed, got error: %v", resp["error"])
	} else {
		t.Log("file_read correctly allowed")
	}
}

func TestUnknownToolDenied(t *testing.T) {
	mockServer := buildMockServer(t)
	visor := buildVisor(t)
	policyFile := writeRestrictivePolicy(t, mockServer)

	cmd := exec.Command(visor, "serve", "-server", mockServer, "-policy", policyFile)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	sendInitMessages(w, r)

	call := map[string]any{
		"jsonrpc": "2.0",
		"id":      nextID(),
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "unknown_tool_xyz",
			"arguments": map[string]any{},
		},
	}
	_ = sendMessage(w, call)
	resp, err := readMessage(r)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp["error"] == nil {
		t.Fatal("unknown tool should be denied under default_deny")
	}
	t.Logf("unknown tool correctly denied: %v", resp["error"])
}

func TestToolsList(t *testing.T) {
	mockServer := buildMockServer(t)
	visor := buildVisor(t)
	policyFile := writeRestrictivePolicy(t, mockServer)

	cmd := exec.Command(visor, "serve", "-server", mockServer, "-policy", policyFile)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	sendInitMessages(w, r)

	listMsg := map[string]any{
		"jsonrpc": "2.0",
		"id":      nextID(),
		"method":  "tools/list",
		"params":  map[string]any{},
	}
	_ = sendMessage(w, listMsg)
	resp, err := readMessage(r)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp["error"] != nil {
		t.Fatalf("tools/list should succeed: %v", resp["error"])
	}
	result := resp["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) == 0 {
		t.Error("expected at least one tool from tools/list")
	}
	t.Logf("tools/list returned %d tools", len(tools))
}

func TestAuditLogRedaction(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	mockServer := buildMockServer(t)
	visor := buildVisor(t)
	policyFile := writeRestrictivePolicy(t, mockServer)

	cmd := exec.Command(visor, "serve", "-server", mockServer, "-policy", policyFile, "-audit-log", auditPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	sendInitMessages(w, r)

	secrets := []string{
		"sk-abc123def456ghi789jkl012mno345",
		"ghp_abcdefghijklmnopqrstuvwxyz1234567",
	}

	for _, secret := range secrets {
		msg := map[string]any{
			"jsonrpc": "2.0",
			"id":      nextID(),
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "file_read",
				"arguments": map[string]any{"path": "/tmp/test", "api_key": secret},
			},
		}
		_ = sendMessage(w, msg)
		_, _ = readMessage(r)
	}

	_ = w.Flush()
	_ = stdin.Close()
	time.Sleep(200 * time.Millisecond)

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	for _, secret := range []string{"sk-", "ghp_"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("audit log contains unredacted secret pattern '%s'", secret)
		}
	}
	t.Log("audit log correctly redacted sensitive patterns")
}

func TestMultipleToolCalls(t *testing.T) {
	mockServer := buildMockServer(t)
	visor := buildVisor(t)
	policyFile := writeRestrictivePolicy(t, mockServer)

	cmd := exec.Command(visor, "serve", "-server", mockServer, "-policy", policyFile)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	sendInitMessages(w, r)

	for i := 0; i < 10; i++ {
		call := map[string]any{
			"jsonrpc": "2.0",
			"id":      nextID(),
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "file_read",
				"arguments": map[string]any{"path": fmt.Sprintf("/tmp/file%d.txt", i)},
			},
		}
		_ = sendMessage(w, call)
		resp, err := readMessage(r)
		if err != nil {
			t.Fatalf("read response %d: %v", i, err)
		}
		if resp["error"] != nil {
			t.Errorf("call %d should be allowed, got error: %v", i, resp["error"])
		}
	}
	t.Log("multiple tool calls handled correctly")
}
