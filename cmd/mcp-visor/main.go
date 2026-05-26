package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
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
	serverName := serveCmd.String("server-name", "", "Logical server name used for policy matching (defaults to command path)")
	serverArgs := &stringSlice{}
	serveCmd.Var(serverArgs, "server-arg", "Argument for the MCP server command (repeatable)")
	sessionID := serveCmd.String("session-id", "", "Session identifier")
	clientID := serveCmd.String("client-id", "", "Client identifier")
	policyPath := serveCmd.String("policy", "", "Path to policy YAML file")
	auditPath := serveCmd.String("audit-log", "", "Path to JSONL audit log file (default: stderr)")
	approvalDir := serveCmd.String("approval-dir", "", "Directory for file-based approval workflow")
	approvalCLI := serveCmd.Bool("approval-cli", false, "Use interactive CLI prompt for approval (stdin/stderr)")
	demoMode := serveCmd.Bool("demo", false, "Start in demo mode with built-in mock server and permissive policy")
	traceEnable := serveCmd.Bool("trace", false, "Enable MCP message tracing")
	traceFormat := serveCmd.String("trace-format", "text", "Trace output format: text, jsonl, summary")
	logLevel := serveCmd.String("log-level", "info", "Log level: debug, info, warn, error")
	serverURL := serveCmd.String("server-url", "", "Remote MCP server URL (enables HTTP+SSE transport, e.g. https://remote:8080)")
	ssePath := serveCmd.String("sse-path", "", "SSE endpoint path (default /sse)")
	insecureTLS := serveCmd.Bool("insecure-tls", false, "Skip TLS certificate verification for remote servers")
	vaultAddr := serveCmd.String("vault-addr", "", "Vault server address (enables Vault Transit signing)")
	vaultToken := serveCmd.String("vault-token", "", "Vault authentication token")
	vaultKeyName := serveCmd.String("vault-key-name", "", "Vault Transit key name for approval signing")
	vaultNamespace := serveCmd.String("vault-namespace", "", "Vault namespace (Enterprise)")
	vaultCACert := serveCmd.String("vault-ca-cert", "", "Vault CA certificate file")
	vaultSkipVerify := serveCmd.Bool("vault-skip-verify", false, "Skip Vault TLS verification")

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: mcp-visor <command> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  serve    Start the MCP proxy\n")
		fmt.Fprintf(os.Stderr, "  lint     Validate a policy file\n")
		fmt.Fprintf(os.Stderr, "  version  Print version\n")
		fmt.Fprintf(os.Stderr, "\nRun 'mcp-visor serve -h' for serve options.\n")
		fmt.Fprintf(os.Stderr, "Run 'mcp-visor lint -h' for lint options.\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "lint":
		runLint()
	case "serve":
		_ = serveCmd.Parse(os.Args[2:])

		if *demoMode {
			*serverCmd, *policyPath = setupDemo()
			defer os.Remove(*serverCmd)
			defer os.Remove(*policyPath)
		}

		if *serverCmd == "" && *serverURL == "" {
			fmt.Fprintf(os.Stderr, "mcp-visor serve: -server or -server-url is required (or use --demo)\n")
			os.Exit(1)
		}

		if *serverURL != "" && *serverName == "" {
			*serverName = *serverURL
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

		var eng *policy.Engine
		if *policyPath != "" {
			watcher, err := policy.NewWatcher(*policyPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "mcp-visor: policy hot-reload unavailable: %v (using static policy)\n", err)
				eng = policy.NewEngine(pol)
			} else {
				eng = policy.NewEngineWithWatcher(watcher)
				fmt.Fprintf(os.Stderr, "Policy hot-reload enabled: %s\n", *policyPath)
			}
		}

		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		var tracingFormat proxy.TraceFormat
		switch *traceFormat {
		case "jsonl":
			tracingFormat = proxy.TraceFormatJSONL
		case "summary":
			tracingFormat = proxy.TraceFormatSummary
		case "text":
			tracingFormat = proxy.TraceFormatText
		default:
			tracingFormat = proxy.TraceFormatText
		}

		var logLevelOpt slog.Level
		switch *logLevel {
		case "debug":
			logLevelOpt = slog.LevelDebug
		case "warn":
			logLevelOpt = slog.LevelWarn
		case "error":
			logLevelOpt = slog.LevelError
		default:
			logLevelOpt = slog.LevelInfo
		}

		_ = logLevelOpt // TODO: apply to proxy

		var enabledTracing proxy.TracingConfig
		if *traceEnable {
			enabledTracing = proxy.TracingConfig{
				Enabled: true,
				Format:  tracingFormat,
			}
		}

		p := proxy.NewWithTracing(proxy.Config{
			ServerCommand: *serverCmd,
			ServerName:    *serverName,
			ServerArgs:    *serverArgs,
			ClientID:      *clientID,
			SessionID:     *sessionID,
			Policy:        pol,
			Engine:        eng,
			AuditLogPath:  *auditPath,
			ApprovalDir:   *approvalDir,
			ApprovalCLI:   *approvalCLI,
			Tracing:       enabledTracing,
			ServerURL:     *serverURL,
			SSEPath:       *ssePath,
			InsecureTLS:   *insecureTLS,
			Vault: proxy.VaultConfig{
				Addr:       *vaultAddr,
				Token:      *vaultToken,
				KeyName:    *vaultKeyName,
				Namespace:  *vaultNamespace,
				CACert:     *vaultCACert,
				SkipVerify: *vaultSkipVerify,
			},
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
	_ = mockBin.Close()

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
	_ = policyFile.Close()

	fmt.Fprintf(os.Stderr, "Demo mode: built mock server and policy\n")
	return serverPath, policyPath
}

func runLint() {
	lintCmd := flag.NewFlagSet("lint", flag.ContinueOnError)
	jsonFlag := lintCmd.Bool("json", false, "Output in JSON format")
	strictFlag := lintCmd.Bool("strict", false, "Treat warnings as errors")
	noInfoFlag := lintCmd.Bool("no-info", false, "Hide info-level findings")
	noWarnFlag := lintCmd.Bool("no-warnings", false, "Hide warning-level findings")
	lintCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: mcp-visor lint [flags] <policy-file>\n\nFlags:\n")
		lintCmd.PrintDefaults()
	}

	if err := lintCmd.Parse(os.Args[2:]); err != nil {
		lintCmd.Usage()
		os.Exit(1)
	}
	args := lintCmd.Args()
	if len(args) < 1 {
		lintCmd.Usage()
		os.Exit(1)
	}

	policyPath := args[0]
	pol, err := policy.LoadFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-visor lint: failed to load policy: %v\n", err)
		os.Exit(1)
	}

	result := policy.Lint(pol)
	result.FilePath = policyPath

	if *noInfoFlag {
		filtered := make([]policy.LintViolation, 0, len(result.Violations))
		for _, v := range result.Violations {
			if v.Severity != policy.SeverityInfo {
				filtered = append(filtered, v)
			}
		}
		result.Violations = filtered
		result.Summary.Info = 0
		result.Summary.Total = len(filtered)
	}

	if *noWarnFlag {
		filtered := make([]policy.LintViolation, 0, len(result.Violations))
		for _, v := range result.Violations {
			if v.Severity != policy.SeverityWarning && v.Severity != policy.SeverityInfo {
				filtered = append(filtered, v)
			}
		}
		result.Violations = filtered
		result.Summary.Warnings = 0
		result.Summary.Info = 0
		result.Summary.Total = len(filtered)
	}

	if *jsonFlag {
		data, err := result.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp-visor lint: JSON output error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else {
		printLintText(&result)
	}

	if result.Summary.Errors > 0 {
		os.Exit(1)
	}

	if *strictFlag && (result.Summary.Warnings > 0 || result.Summary.Errors > 0) {
		os.Exit(1)
	}
}

func printLintText(result *policy.LintResult) {
	if result.Policy != "" {
		fmt.Printf("Policy: %s\n", result.Policy)
	}
	fmt.Printf("File: %s\n", result.FilePath)

	if result.Summary.Total == 0 {
		fmt.Println("No issues found.")
		return
	}

	sort.Slice(result.Violations, func(i, j int) bool {
		order := map[policy.Severity]int{
			policy.SeverityError:   0,
			policy.SeverityWarning: 1,
			policy.SeverityInfo:    2,
		}
		if order[result.Violations[i].Severity] != order[result.Violations[j].Severity] {
			return order[result.Violations[i].Severity] < order[result.Violations[j].Severity]
		}
		return result.Violations[i].Path < result.Violations[j].Path
	})

	fmt.Printf("Errors: %d  Warnings: %d  Info: %d\n\n", result.Summary.Errors, result.Summary.Warnings, result.Summary.Info)

	for _, v := range result.Violations {
		prefix := "[INFO]  "
		switch v.Severity {
		case policy.SeverityError:
			prefix = "[ERROR] "
		case policy.SeverityWarning:
			prefix = "[WARN]  "
		}
		fmt.Printf("%s%s\n", prefix, v.Message)
		fmt.Printf("        path=%s  field=%s\n", v.Path, v.Field)
	}
}

type stringSlice []string

func (s *stringSlice) String() string { return fmt.Sprintf("%v", *s) }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}
