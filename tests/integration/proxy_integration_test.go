package main_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func buildMockServer(t *testing.T) string {
	t.Helper()
	tmp, err := os.CreateTemp("", "mock-mcp-server-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	tmp.Close()

	cmd := exec.Command("go", "build", "-o", tmp.Name(),
		"github.com/themayursinha/mcp-visor/examples/demo-mcp-server")
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build mock server: %v\n%s", err, out)
	}
	t.Cleanup(func() { os.Remove(tmp.Name()) })
	return tmp.Name()
}

func buildVisor(t *testing.T) string {
	t.Helper()
	tmp, err := os.CreateTemp("", "mcp-visor-test-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	tmp.Close()

	cmd := exec.Command("go", "build", "-o", tmp.Name(),
		"github.com/themayursinha/mcp-visor/cmd/mcp-visor")
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build visor: %v\n%s", err, out)
	}
	t.Cleanup(func() { os.Remove(tmp.Name()) })
	return tmp.Name()
}

func writePermissivePolicy(t *testing.T, serverPath string) string {
	t.Helper()
	tmp, err := os.CreateTemp("", "mcp-visor-policy-*.yaml")
	if err != nil {
		t.Fatalf("create temp policy: %v", err)
	}
	policy := fmt.Sprintf(`version: "1.0"
description: "Permissive test policy"
default_action: deny
servers:
  - name: "%s"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
      - name: "http_post"
        allowed: true
      - name: "shell_exec"
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

func sendMessage(w *bufio.Writer, msg map[string]any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	if err != nil {
		return err
	}
	return w.Flush()
}

func readMessage(r *bufio.Reader) (map[string]any, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var msg map[string]any
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, fmt.Errorf("decode: %w (raw: %s)", err, string(line))
	}
	return msg, nil
}

func TestProxyIntegrationHandshake(t *testing.T) {
	mockServer := buildMockServer(t)
	visor := buildVisor(t)
	policyFile := writePermissivePolicy(t, mockServer)

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
	defer cmd.Process.Kill()

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
			"clientInfo": map[string]any{
				"name":    "test-client",
				"version": "1.0.0",
			},
		},
	}

	if err := sendMessage(w, initMsg); err != nil {
		t.Fatalf("send initialize: %v", err)
	}

	resp, err := readMessage(r)
	if err != nil {
		t.Fatalf("read initialize response: %v", err)
	}

	if resp["id"] != float64(1) {
		t.Errorf("expected id 1, got %v", resp["id"])
	}
	if resp["result"] == nil {
		t.Fatal("expected result in initialize response")
	}
	result := resp["result"].(map[string]any)
	serverInfo := result["serverInfo"].(map[string]any)
	if serverInfo["name"] != "mock-mcp-server" {
		t.Errorf("expected mock-mcp-server, got %v", serverInfo["name"])
	}

	initializedMsg := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	if err := sendMessage(w, initializedMsg); err != nil {
		t.Fatalf("send initialized: %v", err)
	}

	t.Log("handshake completed successfully")
}

func TestProxyIntegrationToolsCall(t *testing.T) {
	mockServer := buildMockServer(t)
	visor := buildVisor(t)
	policyFile := writePermissivePolicy(t, mockServer)

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
	defer cmd.Process.Kill()

	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	_ = cmd.Stderr

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

	toolCall := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "file_read",
			"arguments": map[string]any{"path": "/tmp/test"},
		},
	}

	if err := sendMessage(w, toolCall); err != nil {
		t.Fatalf("send tools/call: %v", err)
	}

	resp, err := readMessage(r)
	if err != nil {
		t.Fatalf("read tools/call response: %v", err)
	}

	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}

	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	first := content[0].(map[string]any)
	t.Logf("tool result: %s", first["text"])
}

func TestProxyIntegrationPing(t *testing.T) {
	mockServer := buildMockServer(t)
	visor := buildVisor(t)
	policyFile := writePermissivePolicy(t, mockServer)

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
	defer cmd.Process.Kill()

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

	initDone := map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}
	sendMessage(w, initDone)

	pingMsg := map[string]any{"jsonrpc": "2.0", "id": 2, "method": "ping"}
	if err := sendMessage(w, pingMsg); err != nil {
		t.Fatalf("send ping: %v", err)
	}

	resp, err := readMessage(r)
	if err != nil {
		t.Fatalf("read ping response: %v", err)
	}

	if resp["id"] != float64(2) {
		t.Errorf("expected id 2, got %v", resp["id"])
	}
	if resp["error"] != nil {
		t.Errorf("unexpected error: %v", resp["error"])
	}
	t.Log("ping successful")
}

func TestProxyIntegrationToolsList(t *testing.T) {
	mockServer := buildMockServer(t)
	visor := buildVisor(t)
	policyFile := writePermissivePolicy(t, mockServer)

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
	defer cmd.Process.Kill()

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

	initDone := map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}
	sendMessage(w, initDone)

	toolsList := map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
	sendMessage(w, toolsList)

	resp, err := readMessage(r)
	if err != nil {
		t.Fatalf("read tools/list response: %v", err)
	}

	result := resp["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 4 {
		t.Errorf("expected 4 tools, got %d", len(tools))
	}

	names := make(map[string]bool)
	for _, t := range tools {
		tool := t.(map[string]any)
		names[tool["name"].(string)] = true
	}
	expected := []string{"file_read", "http_post", "shell_exec", "slack_send_message"}
	for _, n := range expected {
		if !names[n] {
			t.Errorf("missing tool: %s", n)
		}
	}
	t.Logf("tools/list returned %d tools", len(tools))
}
