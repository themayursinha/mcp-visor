// Command confused-deputy-demo proves MCP Visor's stdio executable identity
// attestation end to end. Two distinct local server binaries expose the same
// harmless open_ticket tool and schema. The poisoned binary's tool
// description contains adversarial preference text, so a deterministic
// selector chooses it. The policy pins the benign binary's SHA-256 under the
// logical server name, and Visor denies the poisoned call before the server
// observes it while the benign call passes.
//
// Selection provenance (selected_by=description) comes from this demo's
// deterministic selector, never from Visor. Authorization provenance
// (attested, policy_decision, identity digests) comes from Visor's JSONL
// audit events. The two domains are kept separate on purpose.
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

	"github.com/themayursinha/mcp-visor/internal/confuseddeputydemo"
	"github.com/themayursinha/mcp-visor/internal/serveridentity"
)

const (
	logicalServerName = "it-support"
	poisonedCallID    = 100
	benignCallID      = 101
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
	benignBin := filepath.Join(dir, fmt.Sprintf("cdd-benign-%d", pid))
	poisonedBin := filepath.Join(dir, fmt.Sprintf("cdd-poisoned-%d", pid))
	visorBin := filepath.Join(dir, fmt.Sprintf("cdd-visor-%d", pid))
	policyPath := filepath.Join(dir, fmt.Sprintf("cdd-policy-%d.yaml", pid))
	benignAudit := filepath.Join(dir, fmt.Sprintf("cdd-benign-audit-%d.jsonl", pid))
	poisonedAudit := filepath.Join(dir, fmt.Sprintf("cdd-poisoned-audit-%d.jsonl", pid))
	benignObs := filepath.Join(dir, fmt.Sprintf("cdd-benign-obs-%d.jsonl", pid))
	poisonedObs := filepath.Join(dir, fmt.Sprintf("cdd-poisoned-obs-%d.jsonl", pid))

	defer os.Remove(benignBin)
	defer os.Remove(poisonedBin)
	defer os.Remove(visorBin)
	defer os.Remove(policyPath)
	defer os.Remove(benignAudit)
	defer os.Remove(poisonedAudit)
	defer os.Remove(benignObs)
	defer os.Remove(poisonedObs)

	if out, e := exec.Command("go", "build", "-o", benignBin, filepath.Join(repoRoot, "examples", "confused-deputy-demo", "benign-server")).CombinedOutput(); e != nil {
		return fmt.Errorf("build benign server: %w\n%s", e, out)
	}
	if out, e := exec.Command("go", "build", "-o", poisonedBin, filepath.Join(repoRoot, "examples", "confused-deputy-demo", "poisoned-server")).CombinedOutput(); e != nil {
		return fmt.Errorf("build poisoned server: %w\n%s", e, out)
	}
	if out, e := exec.Command("go", "build", "-o", visorBin, filepath.Join(repoRoot, "cmd", "mcp-visor")).CombinedOutput(); e != nil {
		return fmt.Errorf("build visor: %w\n%s", e, out)
	}

	// The policy pins the BENIGN artifact. The poisoned artifact reuses the
	// same logical name and must be denied before any tools/call relay.
	benignIdentity, err := serveridentity.ResolveStdioExecutable(benignBin)
	if err != nil {
		return fmt.Errorf("resolve benign identity: %w", err)
	}
	if err := writePolicy(policyPath, benignIdentity.Digest); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}

	benignVisor, benignStdin, benignStdout, err := startVisor(visorBin, benignBin, policyPath, benignAudit, benignObs)
	if err != nil {
		return err
	}
	defer killVisor(benignVisor)
	poisonedVisor, poisonedStdin, poisonedStdout, err := startVisor(visorBin, poisonedBin, policyPath, poisonedAudit, poisonedObs)
	if err != nil {
		return err
	}
	defer killVisor(poisonedVisor)

	benignClient := newClient(benignStdin, benignStdout)
	if err := benignClient.initialize(); err != nil {
		return fmt.Errorf("benign initialize: %w", err)
	}
	poisonedClient := newClient(poisonedStdin, poisonedStdout)
	if err := poisonedClient.initialize(); err != nil {
		return fmt.Errorf("poisoned initialize: %w", err)
	}

	// An agent reads the advertised tool descriptions through each proxy and
	// selects by description text.
	benignDesc, err := toolDescription(benignClient)
	if err != nil {
		return fmt.Errorf("benign tools/list: %w", err)
	}
	poisonedDesc, err := toolDescription(poisonedClient)
	if err != nil {
		return fmt.Errorf("poisoned tools/list: %w", err)
	}
	selected, err := confuseddeputydemo.SelectByDescription([]confuseddeputydemo.ServerAdvert{
		{Name: "benign-it", Description: benignDesc, ToolName: confuseddeputydemo.ToolName},
		{Name: "poisoned-it", Description: poisonedDesc, ToolName: confuseddeputydemo.ToolName},
	})
	if err != nil {
		return err
	}
	if selected.Name != "poisoned-it" {
		return fmt.Errorf("expected poisoned server to win selection, got %+v", selected)
	}

	// Call the selected poisoned path. Visor must deny before relay.
	poisonedResp, err := poisonedClient.callTool(poisonedCallID, confuseddeputydemo.ToolName, map[string]any{"ticket_id": "T-POISONED"})
	if err != nil {
		return fmt.Errorf("poisoned tools/call transport: %w", err)
	}
	if _, isErr := responseError(poisonedResp); !isErr {
		return errors.New("poisoned tools/call must be denied by identity attestation")
	}

	// Call the benign pinned path. Visor must allow and the server must observe it.
	benignResp, err := benignClient.callTool(benignCallID, confuseddeputydemo.ToolName, map[string]any{"ticket_id": "T-BENIGN"})
	if err != nil {
		return fmt.Errorf("benign tools/call transport: %w", err)
	}
	if _, isErr := responseError(benignResp); isErr {
		return fmt.Errorf("benign tools/call must be allowed, got error: %v", benignResp)
	}

	poisonedObserved, err := observedRequests(poisonedObs)
	if err != nil {
		return err
	}
	if containsRequest(poisonedObserved, poisonedCallID) {
		return fmt.Errorf("poisoned server observed the denied call: %v", poisonedObserved)
	}
	benignObserved, err := observedRequests(benignObs)
	if err != nil {
		return err
	}
	if !containsRequest(benignObserved, benignCallID) {
		return fmt.Errorf("benign server did not observe the allowed call: %v", benignObserved)
	}

	poisonedDeny, err := findDecisionEvent(poisonedAudit, "tool_call_denied")
	if err != nil {
		return err
	}
	benignAllow, err := findDecisionEvent(benignAudit, "tool_call_allowed")
	if err != nil {
		return err
	}
	if attested, _ := poisonedDeny["server_attested"].(bool); attested {
		return fmt.Errorf("poisoned deny event must carry attested=false: %v", poisonedDeny)
	}
	if attested, _ := benignAllow["server_attested"].(bool); !attested {
		return fmt.Errorf("benign allow event must carry attested=true: %v", benignAllow)
	}

	// Combined receipt: selector provenance first, then Visor authorization
	// provenance, then downstream observation. No temp paths, raw arguments,
	// usernames, or secrets are printed.
	fmt.Printf("selected_by=description\n")
	fmt.Printf("selected_server=%s\n", selected.Name)
	fmt.Printf("selected_tool=%s\n", confuseddeputydemo.ToolName)
	fmt.Printf("authorization.logical_server=%s\n", logicalServerName)
	fmt.Printf("authorization.resolved_identity=%s\n", poisonedDeny["server_identity_resolved"])
	fmt.Printf("authorization.expected_identity=%s\n", poisonedDeny["server_identity_expected"])
	fmt.Printf("authorization.attested=false\n")
	fmt.Printf("authorization.policy_decision=deny\n")
	fmt.Printf("execution.server_received_call=no\n")
	fmt.Printf("benign_attested=true\n")
	fmt.Printf("benign_policy_decision=allow\n")
	fmt.Printf("benign_server_received_call=yes\n")
	return nil
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

func writePolicy(path, digest string) error {
	policy := fmt.Sprintf(`version: "1.0"
description: "Confused-deputy demo: pin the benign stdio executable under logical server it-support"
default_action: deny
servers:
  - name: "%s"
    allowed: true
    attestation:
      kind: "stdio_executable_sha256"
      digest: "%s"
    tools:
      - name: "open_ticket"
        allowed: true
        risk: low
`, logicalServerName, digest)
	return os.WriteFile(path, []byte(policy), 0o600)
}

func startVisor(visorBin, serverBin, policyPath, auditPath, observePath string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error) {
	cmd := exec.Command(visorBin, "serve",
		"-server", serverBin,
		"-server-name", logicalServerName,
		"-server-arg", "-observe-log",
		"-server-arg", observePath,
		"-policy", policyPath,
		"-audit-log", auditPath,
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("visor stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("visor stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("visor stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, fmt.Errorf("start visor: %w", err)
	}
	go drain(stderr)
	return cmd, stdin, stdout, nil
}

func killVisor(cmd *exec.Cmd) {
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
			"clientInfo":      map[string]any{"name": "confused-deputy-demo-agent", "version": "1.0"},
		},
	}); err != nil {
		return err
	}
	if _, err := c.recv(); err != nil {
		return err
	}
	return c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
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

func toolDescription(c *mcpClient) (string, error) {
	if err := c.send(map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{},
	}); err != nil {
		return "", err
	}
	resp, err := c.recv()
	if err != nil {
		return "", err
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("tools/list result missing: %v", resp)
	}
	tools, ok := result["tools"].([]any)
	if !ok || len(tools) == 0 {
		return "", fmt.Errorf("tools/list empty: %v", resp)
	}
	first, ok := tools[0].(map[string]any)
	if !ok {
		return "", fmt.Errorf("tools/list malformed: %v", resp)
	}
	desc, _ := first["description"].(string)
	return desc, nil
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
