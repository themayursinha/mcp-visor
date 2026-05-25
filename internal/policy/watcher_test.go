package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

func TestWatcherCreation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	initialYAML := `
version: "1.0"
default_action: deny
servers:
  - name: "test-server"
    allowed: true
    tools:
      - name: "my_tool"
        allowed: false
`
	if err := os.WriteFile(path, []byte(initialYAML), 0644); err != nil {
		t.Fatal(err)
	}

	w, err := policy.NewWatcher(path)
	if err != nil {
		t.Fatalf("create watcher: %v", err)
	}
	defer w.Close()

	pol := w.Policy()
	if pol.DefaultAction != policy.ActionDeny {
		t.Errorf("expected default-deny, got %s", pol.DefaultAction)
	}
}

func TestWatcherReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	initialYAML := `
version: "1.0"
default_action: deny
servers:
  - name: "test-server"
    allowed: true
    tools:
      - name: "my_tool"
        allowed: false
`
	if err := os.WriteFile(path, []byte(initialYAML), 0644); err != nil {
		t.Fatal(err)
	}

	w, err := policy.NewWatcher(path)
	if err != nil {
		t.Fatalf("create watcher: %v", err)
	}
	defer w.Close()

	eng := policy.NewEngineWithWatcher(w)

	req := mcp.ToolsCallRequest{
		Name:      "my_tool",
		Arguments: json.RawMessage(`{}`),
	}
	decision := eng.Evaluate("test-server", req)
	if decision.Action != policy.ActionDeny {
		t.Errorf("expected deny before reload, got %s", decision.Action)
	}

	updatedYAML := `
version: "1.0"
default_action: deny
servers:
  - name: "test-server"
    allowed: true
    tools:
      - name: "my_tool"
        allowed: true
`
	if err := os.WriteFile(path, []byte(updatedYAML), 0644); err != nil {
		t.Fatal(err)
	}

	w.Reload()

	decision = eng.Evaluate("test-server", req)
	if decision.Action != policy.ActionAllow {
		t.Errorf("expected allow after reload, got %s (%s)", decision.Action, decision.Reason)
	}
}

func TestWatcherReloadInvalidPolicyKeepsCurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	initialYAML := `
version: "1.0"
default_action: deny
servers:
  - name: "test-server"
    allowed: true
    tools:
      - name: "my_tool"
        allowed: true
`
	if err := os.WriteFile(path, []byte(initialYAML), 0644); err != nil {
		t.Fatal(err)
	}

	w, err := policy.NewWatcher(path)
	if err != nil {
		t.Fatalf("create watcher: %v", err)
	}
	defer w.Close()

	eng := policy.NewEngineWithWatcher(w)

	req := mcp.ToolsCallRequest{
		Name:      "my_tool",
		Arguments: json.RawMessage(`{}`),
	}
	decision := eng.Evaluate("test-server", req)
	if decision.Action != policy.ActionAllow {
		t.Fatalf("expected allow initially, got %s", decision.Action)
	}

	if err := os.WriteFile(path, []byte("this is not valid yaml: [[["), 0644); err != nil {
		t.Fatal(err)
	}

	w.Reload()

	decision = eng.Evaluate("test-server", req)
	if decision.Action != policy.ActionAllow {
		t.Errorf("expected allow after failed reload (policy unchanged), got %s", decision.Action)
	}
}

func TestWatcherReloadChains(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	initialYAML := `
version: "1.0"
default_action: deny
tool_chains:
  - name: "test_chain"
    sources:
      - server: "*"
        tool_pattern: "read"
    sinks:
      - server: "*"
        tool_pattern: "send"
    action: deny
    within_calls: 3
`
	if err := os.WriteFile(path, []byte(initialYAML), 0644); err != nil {
		t.Fatal(err)
	}

	w, err := policy.NewWatcher(path)
	if err != nil {
		t.Fatalf("create watcher: %v", err)
	}
	defer w.Close()

	eng := policy.NewEngineWithWatcher(w)

	req := mcp.ToolsCallRequest{Name: "send"}
	previousCalls := []string{"srv:read"}

	decision := eng.EvaluateChain("srv", req, previousCalls)
	if decision.Action != policy.ActionDeny {
		t.Fatalf("expected chain deny initially, got %s", decision.Action)
	}

	updatedYAML := `
version: "1.0"
default_action: deny
tool_chains:
  - name: "test_chain"
    sources:
      - server: "*"
        tool_pattern: "read"
    sinks:
      - server: "*"
        tool_pattern: "send"
    action: require_approval
    within_calls: 3
`
	if err := os.WriteFile(path, []byte(updatedYAML), 0644); err != nil {
		t.Fatal(err)
	}

	w.Reload()

	decision = eng.EvaluateChain("srv", req, previousCalls)
	if decision.Action != policy.ActionRequireApproval {
		t.Errorf("expected require_approval after reload, got %s", decision.Action)
	}
}

func TestWatcherReloadRegistry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	initialYAML := `
version: "1.0"
default_action: deny
servers:
  - name: "srv1"
    allowed: true
    tools:
      - name: "tool_a"
        allowed: true
`
	if err := os.WriteFile(path, []byte(initialYAML), 0644); err != nil {
		t.Fatal(err)
	}

	w, err := policy.NewWatcher(path)
	if err != nil {
		t.Fatalf("create watcher: %v", err)
	}
	defer w.Close()

	eng := policy.NewEngineWithWatcher(w)
	reg := eng.Registry()

	_, ok := reg.Tool("srv1", "tool_a")
	if !ok {
		t.Fatal("tool_a should be known")
	}

	_, ok = reg.Tool("srv2", "tool_b")
	if ok {
		t.Fatal("tool_b should not be known yet")
	}

	updatedYAML := `
version: "1.0"
default_action: deny
servers:
  - name: "srv1"
    allowed: true
    tools:
      - name: "tool_a"
        allowed: true
  - name: "srv2"
    allowed: true
    tools:
      - name: "tool_b"
        allowed: true
`
	if err := os.WriteFile(path, []byte(updatedYAML), 0644); err != nil {
		t.Fatal(err)
	}

	w.Reload()

	reg = eng.Registry()
	_, ok = reg.Tool("srv2", "tool_b")
	if !ok {
		t.Fatal("tool_b should be known after reload")
	}
}

func TestEngineWithoutWatcher(t *testing.T) {
	p := policy.DefaultPolicy()
	eng := policy.NewEngine(p)

	req := mcp.ToolsCallRequest{
		Name:      "some_tool",
		Arguments: json.RawMessage(`{}`),
	}
	decision := eng.Evaluate("unknown-server", req)
	if decision.Action != policy.ActionDeny {
		t.Errorf("expected deny for unknown tool, got %s", decision.Action)
	}

	eng.Close()
}
