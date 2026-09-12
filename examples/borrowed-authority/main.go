// Command borrowed-authority proves Capability Ownership at the MCP
// boundary: tenant-A cannot borrow tenant-B's tools through a permissive
// routing layer, while a narrow B→A delegation for one scoped effect is
// honored. Unmediated, the cross-tenant read_secret reaches tenant-B.
// Through Visor as tenant-A it is denied before relay and absent from B's
// observe-log; only internal_fetch(resource="X") forwards.
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
	tenantA = "tenant-A"
	serverB = "mcp-server-B"

	unmediatedSteal = 10
	mediatedSteal   = 20
	mediatedFetchX  = 30
	mediatedFetchY  = 40
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
	mockBin := filepath.Join(dir, fmt.Sprintf("ba-mock-%d", pid))
	visorBin := filepath.Join(dir, fmt.Sprintf("ba-visor-%d", pid))
	policyPath := filepath.Join(dir, fmt.Sprintf("ba-policy-%d.yaml", pid))
	auditPath := filepath.Join(dir, fmt.Sprintf("ba-audit-%d.jsonl", pid))
	unmedObs := filepath.Join(dir, fmt.Sprintf("ba-unmed-obs-%d.jsonl", pid))
	medObs := filepath.Join(dir, fmt.Sprintf("ba-med-obs-%d.jsonl", pid))
	defer os.Remove(mockBin)
	defer os.Remove(visorBin)
	defer os.Remove(policyPath)
	defer os.Remove(auditPath)
	defer os.Remove(unmedObs)
	defer os.Remove(medObs)

	if out, e := exec.Command("go", "build", "-o", mockBin, filepath.Join(repoRoot, "examples", "borrowed-authority", "mock-server")).CombinedOutput(); e != nil {
		return fmt.Errorf("build mock server: %w\n%s", e, out)
	}
	if out, e := exec.Command("go", "build", "-o", visorBin, filepath.Join(repoRoot, "cmd", "mcp-visor")).CombinedOutput(); e != nil {
		return fmt.Errorf("build visor: %w\n%s", e, out)
	}
	now := time.Now().UTC()
	if err := os.WriteFile(policyPath, []byte(borrowedAuthorityPolicy(now.Add(-time.Minute), now.Add(15*time.Minute))), 0o600); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}

	fmt.Println("MCP Visor")
	fmt.Println("Borrowed authority is not authority.")
	fmt.Println()
	fmt.Println("SCENARIO")
	fmt.Println("tenant-A invokes tenant-B read_secret through a permissive router.")
	fmt.Println()

	if err := runUnmediated(mockBin, unmedObs); err != nil {
		return err
	}
	if err := runMediated(visorBin, mockBin, policyPath, auditPath, medObs); err != nil {
		return err
	}

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
	resp, err := client.callTool(unmediatedSteal, "read_secret", map[string]any{})
	if err != nil {
		return fmt.Errorf("unmediated read_secret: %w", err)
	}
	if _, isErr := responseError(resp); isErr {
		return fmt.Errorf("unmediated read_secret must reach the server, got %v", resp)
	}
	ids, err := observedRequests(observePath)
	if err != nil {
		return fmt.Errorf("unmediated observations: %w", err)
	}
	if !containsRequest(ids, unmediatedSteal) {
		return errors.New("unmediated server must observe read_secret")
	}

	fmt.Println("A  UNMEDIATED (permissive router)")
	fmt.Println("   input  tenant-A -> server-B read_secret")
	fmt.Println("   authenticated YES  server exists YES  tool exists YES")
	fmt.Println("   t+0    SERVER OBSERVED  yes  (EXECUTED)")
	fmt.Println()
	return nil
}

func runMediated(visorBin, mockBin, policyPath, auditPath, observePath string) error {
	cmd := exec.Command(visorBin, "serve",
		"-server", mockBin,
		"-server-name", serverB,
		"-server-arg", "-observe-log",
		"-server-arg", observePath,
		"-policy", policyPath,
		"-audit-log", auditPath,
		"-client-id", tenantA,
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

	// 1. Cross-tenant steal: deny before relay.
	resp, err := client.callTool(mediatedSteal, "read_secret", map[string]any{})
	if err != nil {
		return fmt.Errorf("mediated steal: %w", err)
	}
	msg, isErr := responseError(resp)
	if !isErr {
		return errors.New("cross-tenant read_secret must deny")
	}
	for _, token := range []string{
		"capability ownership proof invalid",
		"argument class PRINCIPAL",
		"effect class THIRD_PARTY",
	} {
		if !strings.Contains(msg, token) {
			return fmt.Errorf("deny missing evidence %q: %s", token, msg)
		}
	}

	// 2. Narrow delegation: only internal_fetch(resource=X) forwards.
	resp, err = client.callTool(mediatedFetchX, "internal_fetch", map[string]any{"resource": "X"})
	if err != nil {
		return fmt.Errorf("mediated delegated fetch: %w", err)
	}
	if _, isErr := responseError(resp); isErr {
		return fmt.Errorf("delegated internal_fetch(X) must allow, got %v", resp)
	}

	// 3. Out-of-scope delegation use stays denied.
	resp, err = client.callTool(mediatedFetchY, "internal_fetch", map[string]any{"resource": "Y"})
	if err != nil {
		return fmt.Errorf("mediated fetch Y: %w", err)
	}
	if _, isErr := responseError(resp); !isErr {
		return errors.New("internal_fetch(Y) must deny")
	}

	ids, err := observedRequests(observePath)
	if err != nil {
		return fmt.Errorf("mediated observations: %w", err)
	}
	if containsRequest(ids, mediatedSteal) {
		return errors.New("mediated server must not observe denied read_secret")
	}
	if !containsRequest(ids, mediatedFetchX) {
		return errors.New("mediated server must observe delegated internal_fetch")
	}
	if containsRequest(ids, mediatedFetchY) {
		return errors.New("mediated server must not observe denied internal_fetch(Y)")
	}

	denied, err := findDecisionEvent(auditPath, "tool_call_denied")
	if err != nil {
		return err
	}
	reason, _ := denied["reason"].(string)
	if !strings.Contains(reason, "capability ownership proof invalid") {
		return fmt.Errorf("audit missing ownership evidence: %s", reason)
	}
	if _, ok := denied["ownership_receipt_hash"]; !ok {
		return errors.New("audit deny must carry the ownership receipt hash")
	}

	fmt.Println("B  VISOR as tenant-A (ownership proofs)")
	fmt.Println("   input  tenant-A -> server-B read_secret")
	fmt.Println("   t+0    DENY  cross-principal authority acquisition")
	fmt.Println("          argument class PRINCIPAL  effect class THIRD_PARTY")
	fmt.Println("   t+0    SERVER OBSERVED  no")
	fmt.Println("   input  tenant-A -> server-B internal_fetch(resource=X)")
	fmt.Println("   t+0    ALLOW  narrow B-to-A delegation")
	fmt.Println()
	return nil
}

func borrowedAuthorityPolicy(issued, expires time.Time) string {
	return `version: "1.0"
description: "Borrowed-authority demo: tenant-B tools behind ownership proofs, tenant-A holds one narrow delegation."
default_action: deny
servers:
  - name: "mcp-server-B"
    allowed: true
    tools:
      - name: "read_secret"
        allowed: true
        risk: high
      - name: "internal_fetch"
        allowed: true
        risk: high
capability_ownership:
  endpoints:
    - server: mcp-server-B
      owner: tenant-B
      capabilities:
        - tool: read_secret
          effect_class: CREDENTIAL
        - tool: internal_fetch
          effect_class: NETWORK
          scope_argument: resource
  delegations:
    - id: b-to-a-fetch-x
      owner: tenant-B
      delegate: tenant-A
      server: mcp-server-B
      tool: internal_fetch
      effect_class: NETWORK
      resource_scope:
        argument: resource
        exact_values: ["X"]
      issued_at: "` + issued.UTC().Format(time.RFC3339) + `"
      expires_at: "` + expires.UTC().Format(time.RFC3339) + `"
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
			"clientInfo":      map[string]any{"name": "borrowed-authority-agent", "version": "1.0"},
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
