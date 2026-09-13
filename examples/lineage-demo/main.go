// Command lineage-demo shows pre-execution authorization of a consequential
// github.write_file call. A registered Human→Planner→Coding grant chain is
// allowed and the mock server observes it. The same write from unregistered
// agent orphan-1 is denied as lineage:unregistered-principal and the server
// never sees the call.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/themayursinha/mcp-visor/examples/internal/demokit"
	"github.com/themayursinha/mcp-visor/internal/lineage/testfixture"
)

const (
	allowCallID = 200
	denyCallID  = 300
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := demokit.RepoRoot()
	if err != nil {
		return err
	}
	dir := os.TempDir()
	uniq := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	mockBin := filepath.Join(dir, "lin-mock-"+uniq)
	visorBin := filepath.Join(dir, "lin-visor-"+uniq)
	policyPath := filepath.Join(dir, "lin-policy-"+uniq+".yaml")
	defer os.Remove(mockBin)
	defer os.Remove(visorBin)
	defer os.Remove(policyPath)
	if err := demokit.Build(root, mockBin, filepath.Join(root, "examples", "demo-mcp-server")); err != nil {
		return err
	}
	if err := demokit.Build(root, visorBin, filepath.Join(root, "cmd", "mcp-visor")); err != nil {
		return err
	}
	if err := os.WriteFile(policyPath, []byte(testfixture.PolicyYAML()), 0o600); err != nil {
		return err
	}
	allowHash, err := runCall(visorBin, mockBin, policyPath, testfixture.Coding, allowCallID, testfixture.Args(), true)
	if err != nil {
		return err
	}
	if _, err := runCall(visorBin, mockBin, policyPath, "orphan-1", denyCallID, testfixture.Args(), false); err != nil {
		return err
	}
	fmt.Println("== Who did this? ==")
	fmt.Println("lineage: human_principal=mayur")
	fmt.Println("lineage: planner_agent=planner-agent-1")
	fmt.Println("lineage: coding_agent=coding-agent-1")
	fmt.Println("lineage: grant_chain=grant-planner-1 -> grant-coding-1")
	fmt.Println("lineage: capability=github.repo.write")
	fmt.Println("lineage: resource=repo:themayursinha/mcp-visor")
	fmt.Println("lineage: decision=allow")
	fmt.Printf("lineage: audit=sha256:%s\n", allowHash)
	fmt.Println("lineage: server_received_call=yes")
	fmt.Println()
	fmt.Println("== Same write from an unregistered agent ==")
	fmt.Println("lineage: agent=orphan-1")
	fmt.Println("lineage: registered_principal=no")
	fmt.Println("lineage: delegation_lineage=none")
	fmt.Println("lineage: decision=deny")
	fmt.Println("lineage: reason=lineage:unregistered-principal")
	fmt.Println("lineage: server_received_call=no")
	return nil
}

func runCall(visorBin, mockBin, policyPath, clientID string, callID int, args map[string]any, wantRelay bool) (string, error) {
	dir := os.TempDir()
	uniq := fmt.Sprintf("%d-%d-%s", os.Getpid(), time.Now().UnixNano(), clientID)
	auditPath := filepath.Join(dir, "lin-audit-"+uniq+".jsonl")
	observePath := filepath.Join(dir, "lin-obs-"+uniq+".jsonl")
	defer os.Remove(auditPath)
	defer os.Remove(observePath)
	cmd := exec.Command(visorBin, "serve",
		"-server", mockBin, "-server-name", testfixture.Server,
		"-server-arg", "-observe-log", "-server-arg", observePath,
		"-policy", policyPath, "-audit-log", auditPath, "-client-id", clientID,
	)
	stdin, stdout, err := demokit.Start(cmd)
	if err != nil {
		return "", err
	}
	defer demokit.Kill(cmd)
	client := demokit.NewClient(stdin, stdout)
	if err := client.Initialize("lineage-demo"); err != nil {
		return "", err
	}
	resp, err := client.CallTool(callID, testfixture.Tool, args)
	if err != nil {
		return "", err
	}
	msg, isErr := demokit.ResponseError(resp)
	if wantRelay && isErr {
		return "", fmt.Errorf("valid call must allow, got %s", msg)
	}
	if !wantRelay && (!isErr || msg != "lineage:unregistered-principal") {
		return "", fmt.Errorf("unregistered call must deny unregistered-principal, got %v", resp)
	}
	ids, err := demokit.ObservedIDs(observePath)
	if err != nil {
		return "", err
	}
	if wantRelay != demokit.ContainsID(ids, callID) {
		return "", fmt.Errorf("observation want relay=%v call=%d ids=%v", wantRelay, callID, ids)
	}
	wantType := "tool_call_allowed"
	if !wantRelay {
		wantType = "tool_call_denied"
	}
	ev, err := demokit.WaitEvent(auditPath, wantType, 2*time.Second)
	if err != nil {
		return "", err
	}
	hash, _ := ev["hash"].(string)
	return hash, nil
}
