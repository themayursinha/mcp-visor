package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/proxy"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		fmt.Printf("mcp-visor %s\n  commit: %s\n  date:   %s\n", version, commit, date)
		os.Exit(0)
	}

	serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
	serverCmd := serveCmd.String("server", "", "MCP server command to proxy")
	serverArgs := &stringSlice{}
	serveCmd.Var(serverArgs, "server-arg", "Argument for the MCP server command (repeatable)")
	sessionID := serveCmd.String("session-id", "", "Session identifier")
	clientID := serveCmd.String("client-id", "", "Client identifier")
	policyPath := serveCmd.String("policy", "", "Path to policy YAML file")
	auditPath := serveCmd.String("audit-log", "", "Path to JSONL audit log file (default: stderr)")
	approvalDir := serveCmd.String("approval-dir", "", "Directory for file-based approval workflow")
	demoMode := serveCmd.Bool("demo", false, "Start in demo mode with built-in mock server and permissive policy")

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: mcp-visor <command> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  serve    Start the MCP proxy\n")
		fmt.Fprintf(os.Stderr, "  version  Print version\n")
		fmt.Fprintf(os.Stderr, "\nRun 'mcp-visor serve -h' for serve options.\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		serveCmd.Parse(os.Args[2:])

		if *demoMode {
			*serverCmd, *policyPath = setupDemo()
			defer os.Remove(*serverCmd)
			defer os.Remove(*policyPath)
		}

		if *serverCmd == "" {
			fmt.Fprintf(os.Stderr, "mcp-visor serve: -server is required (or use --demo)\n")
			os.Exit(1)
		}

		var pol *policy.Policy
		if *policyPath != "" {
			var err error
			pol, err = policy.LoadFile(*policyPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "mcp-visor: failed to load policy: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Loaded policy: %s (default: %s)\n", *policyPath, pol.DefaultAction)
		} else {
			pol = policy.DefaultPolicy()
			fmt.Fprintf(os.Stderr, "Using default-deny policy\n")
		}

		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		p := proxy.New(proxy.Config{
			ServerCommand: *serverCmd,
			ServerArgs:    *serverArgs,
			ClientID:      *clientID,
			SessionID:     *sessionID,
			Policy:        pol,
			AuditLogPath:  *auditPath,
			ApprovalDir:   *approvalDir,
		})

		if err := p.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "mcp-visor: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func setupDemo() (serverPath, policyPath string) {
	mockBin, err := os.CreateTemp("", "mcp-visor-demo-server-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-visor: failed to create temp file: %v\n", err)
		os.Exit(1)
	}
	serverPath = mockBin.Name()
	mockBin.Close()

	buildCmd := exec.Command("go", "build", "-o", serverPath,
		"github.com/themayursinha/mcp-visor/examples/demo-mcp-server")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-visor: failed to build demo server: %v\n%s\n", err, out)
		os.Exit(1)
	}

	policyFile, err := os.CreateTemp("", "mcp-visor-demo-policy-*.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-visor: failed to create temp file: %v\n", err)
		os.Exit(1)
	}
	policyPath = policyFile.Name()

	demoPolicy := fmt.Sprintf(`version: "1.0"
description: "Demo mode - auto-generated permissive policy"
default_action: deny
settings:
  chain_window_size: 3
  approval_timeout_seconds: 10
servers:
  - name: "%s"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
      - name: "http_post"
        allowed: true
        risk: high
        approval_required: true
      - name: "shell_exec"
        allowed: true
        risk: critical
        approval_required: true
      - name: "slack_send_message"
        allowed: true
        risk: high
        approval_required: true
tool_chains:
  - name: "prevent_exfiltration"
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
    - "**/*.pem"
    - "**/*.key"
    - "**/.ssh/**"
`, filepath.ToSlash(serverPath))

	if _, err := policyFile.WriteString(demoPolicy); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-visor: failed to write demo policy: %v\n", err)
		os.Exit(1)
	}
	policyFile.Close()

	fmt.Fprintf(os.Stderr, "Demo mode: built mock server and policy\n")
	return serverPath, policyPath
}

type stringSlice []string

func (s *stringSlice) String() string { return fmt.Sprintf("%v", *s) }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}
