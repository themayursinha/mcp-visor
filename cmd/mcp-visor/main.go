package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/themayursinha/mcp-visor/internal/dashboard"
	"github.com/themayursinha/mcp-visor/internal/killswitch"
	"github.com/themayursinha/mcp-visor/internal/observability"
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
	webhookURLs := &stringSlice{}
	serveCmd.Var(webhookURLs, "webhook-url", "Webhook endpoint for audit/approval events (repeatable)")
	siemTargets := &stringSlice{}
	serveCmd.Var(siemTargets, "siem-target", "SIEM export target: file path, tcp:host:port, or udp:host:port (repeatable)")
	sessionID := serveCmd.String("session-id", "", "Session identifier")
	clientID := serveCmd.String("client-id", "", "Client identifier")
	policyPath := serveCmd.String("policy", "", "Path to policy YAML file")
	auditPath := serveCmd.String("audit-log", "", "Path to JSONL audit log file (default: stderr)")
	approvalDir := serveCmd.String("approval-dir", "", "Directory for file-based approval workflow")
	approvalCLI := serveCmd.Bool("approval-cli", false, "Use interactive CLI prompt for approval (stdin/stderr)")
	approvalSigningKey := serveCmd.String("approval-signing-key", "", "Ed25519 private key PEM file for signing approval receipts (default: ephemeral key)")
	demoMode := serveCmd.Bool("demo", false, "Start in demo mode with built-in mock server and permissive policy")
	traceEnable := serveCmd.Bool("trace", false, "Enable MCP message tracing")
	traceFormat := serveCmd.String("trace-format", "text", "Trace output format: text, jsonl, summary")
	logLevel := serveCmd.String("log-level", "info", "Log level: debug, info, warn, error")
	serverURL := serveCmd.String("server-url", "", "Remote MCP server URL (enables HTTP+SSE transport, e.g. https://remote:8080)")
	ssePath := serveCmd.String("sse-path", "", "SSE endpoint path (default /sse)")
	insecureTLS := serveCmd.Bool("insecure-tls", false, "Skip TLS certificate verification for remote servers")
	remoteCert := serveCmd.String("remote-cert", "", "Client certificate file for remote MCP mTLS")
	remoteKey := serveCmd.String("remote-key", "", "Client private key file for remote MCP mTLS")
	remoteCA := serveCmd.String("remote-ca", "", "CA certificate file for remote MCP TLS verification")
	remoteServerName := serveCmd.String("remote-server-name", "", "Expected TLS server name for remote MCP server")
	webhookHMACSecret := serveCmd.String("webhook-hmac-secret", "", "HMAC secret used to sign webhook payloads")
	siemFormat := serveCmd.String("siem-format", "json", "SIEM export format: json, syslog-rfc5424, cef")
	vaultAddr := serveCmd.String("vault-addr", "", "Vault server address (enables Vault Transit signing)")
	vaultToken := serveCmd.String("vault-token", "", "Vault authentication token")
	vaultKeyName := serveCmd.String("vault-key-name", "", "Vault Transit key name for approval signing")
	vaultNamespace := serveCmd.String("vault-namespace", "", "Vault namespace (Enterprise)")
	vaultCACert := serveCmd.String("vault-ca-cert", "", "Vault CA certificate file")
	vaultSkipVerify := serveCmd.Bool("vault-skip-verify", false, "Skip Vault TLS verification")
	dashEnabled := serveCmd.Bool("dashboard", false, "Enable web dashboard")
	dashboardAddr := serveCmd.String("dashboard-addr", "127.0.0.1:9090", "Dashboard listen address")
	metricsAddr := serveCmd.String("metrics-addr", "", "Prometheus /metrics listen address (e.g. 127.0.0.1:9091); empty disables")
	otelEndpoint := serveCmd.String("otel-endpoint", "", "OTLP gRPC endpoint for traces/metrics (e.g. localhost:4317); empty disables")
	otelInsecure := serveCmd.Bool("otel-insecure", true, "Use insecure gRPC for OTLP (typical for local LGTM)")
	otelService := serveCmd.String("otel-service-name", "mcp-visor", "OpenTelemetry service.name")
	otelTraceSample := serveCmd.Float64("otel-trace-sample", 1.0, "Trace sampling ratio 0..1 when OTLP is enabled")
	capabilityEval := serveCmd.Bool("capability-eval", false, "Enable capability accounting evaluator (default: no-op)")
	trajectoryAdvisor := serveCmd.Bool("trajectory-advisor", false, "Enable advisory session trajectory anomaly telemetry (default: off; never authorizes)")
	killSwitchDir := serveCmd.String("kill-switch-dir", "", "Opt-in local kinetic stop control directory (default: disabled)")
	killSwitchControllers := &stringSlice{}
	serveCmd.Var(killSwitchControllers, "kill-switch-controller", "CONTROLLER_ID=KEY_FILE (repeatable)")
	sessionEpoch := serveCmd.Uint64("session-epoch", 0, "Session epoch for kinetic stop (>=1 when enabled)")

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: mcp-visor <command> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  serve    Start the MCP proxy\n")
		fmt.Fprintf(os.Stderr, "  stop     Publish a kinetic stop command\n")
		fmt.Fprintf(os.Stderr, "  lint     Validate a policy file\n")
		fmt.Fprintf(os.Stderr, "  version  Print version\n")
		fmt.Fprintf(os.Stderr, "\nRun 'mcp-visor serve -h' for serve options.\n")
		fmt.Fprintf(os.Stderr, "Run 'mcp-visor stop -h' for stop options.\n")
		fmt.Fprintf(os.Stderr, "Run 'mcp-visor lint -h' for lint options.\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "lint":
		runLint()
	case "stop":
		os.Exit(runStop(os.Args[2:], os.Stdout, os.Stderr))
	case "serve":
		_ = serveCmd.Parse(os.Args[2:])

		if *demoMode && *killSwitchDir != "" {
			fmt.Fprintf(os.Stderr, "mcp-visor serve: --demo cannot be combined with --kill-switch-dir\n")
			os.Exit(1)
		}

		if *demoMode {
			*serverCmd, *policyPath = setupDemo()
			defer os.Remove(*serverCmd)
			defer os.Remove(*policyPath)
			// Demo mode must have a durable audit sink for the H19
			// authorization-commit gate: without an explicit --audit-log,
			// provision a temporary regular file so the demo actually relays
			// allowed calls instead of denying everything as non-durable.
			if *auditPath == "" {
				auditFile, err := os.CreateTemp("", "mcp-visor-demo-audit-*.jsonl")
				if err != nil {
					fmt.Fprintf(os.Stderr, "mcp-visor: failed to create demo audit file: %v\n", err)
					os.Exit(1)
				}
				*auditPath = auditFile.Name()
				_ = auditFile.Close()
				defer os.Remove(*auditPath)
			}
		}

		if *serverCmd == "" && *serverURL == "" {
			fmt.Fprintf(os.Stderr, "mcp-visor serve: -server or -server-url is required (or use --demo)\n")
			os.Exit(1)
		}

		ksControllers, err := validateServeKillSwitch(*killSwitchDir, *sessionID, *sessionEpoch, *killSwitchControllers, *auditPath, *serverCmd, *serverURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp-visor serve: %v\n", err)
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

		var enabledTracing proxy.TracingConfig
		if *traceEnable {
			enabledTracing = proxy.TracingConfig{
				Enabled: true,
				Format:  tracingFormat,
			}
		}

		p := proxy.NewWithTracing(proxy.Config{
			ServerCommand:      *serverCmd,
			ServerName:         *serverName,
			ServerArgs:         *serverArgs,
			ClientID:           *clientID,
			SessionID:          *sessionID,
			Policy:             pol,
			Engine:             eng,
			AuditLogPath:       *auditPath,
			ApprovalDir:        *approvalDir,
			ApprovalCLI:        *approvalCLI,
			ApprovalSigningKey: *approvalSigningKey,
			Tracing:            enabledTracing,
			ServerURL:          *serverURL,
			SSEPath:            *ssePath,
			InsecureTLS:        *insecureTLS,
			RemoteCert:         *remoteCert,
			RemoteKey:          *remoteKey,
			RemoteCA:           *remoteCA,
			RemoteServerName:   *remoteServerName,
			WebhookURLs:        *webhookURLs,
			WebhookHMACSecret:  *webhookHMACSecret,
			SIEMTargets:        *siemTargets,
			SIEMFormat:         *siemFormat,
			Vault: proxy.VaultConfig{
				Addr:       *vaultAddr,
				Token:      *vaultToken,
				KeyName:    *vaultKeyName,
				Namespace:  *vaultNamespace,
				CACert:     *vaultCACert,
				SkipVerify: *vaultSkipVerify,
			},
			Observability: observability.Config{
				MetricsListenAddr: *metricsAddr,
				OTLPEndpoint:      *otelEndpoint,
				OTLPInsecure:      *otelInsecure,
				ServiceName:       *otelService,
				TraceSampleRatio:  *otelTraceSample,
			},
			CapabilityEval:        *capabilityEval,
			TrajectoryAdvisor:     *trajectoryAdvisor,
			KillSwitchDir:         *killSwitchDir,
			KillSwitchControllers: ksControllers,
			SessionEpoch:          *sessionEpoch,
		})

		p.SetLogLevel(logLevelOpt)
		if *dashEnabled {
			ds := dashboard.NewServer(*dashboardAddr, p.DashboardProvider())
			go func() {
				fmt.Fprintf(os.Stderr, "Dashboard: http://%s\n", *dashboardAddr)
				if err := ds.Start(); err != nil {
					fmt.Fprintf(os.Stderr, "Dashboard error: %v\n", err)
				}
			}()
		}

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

func validateServeKillSwitch(dir, sessionID string, epoch uint64, specs []string, auditPath, server, serverURL string) ([]killswitch.ControllerKey, error) {
	if dir == "" {
		if len(specs) > 0 || epoch != 0 {
			return nil, fmt.Errorf("kill-switch-controller and session-epoch require --kill-switch-dir")
		}
		return nil, nil
	}
	if serverURL != "" {
		return nil, fmt.Errorf("kinetic stop is not supported with --server-url")
	}
	if server == "" || sessionID == "" || epoch < 1 || auditPath == "" || len(specs) == 0 {
		return nil, fmt.Errorf("kinetic stop requires --session-id, --session-epoch >= 1, --kill-switch-controller, --audit-log, and local --server")
	}
	if err := killswitch.ValidateControlDir(dir); err != nil {
		return nil, err
	}
	return loadKillSwitchControllers(specs)
}

func loadKillSwitchControllers(specs []string) ([]killswitch.ControllerKey, error) {
	out := make([]killswitch.ControllerKey, 0, len(specs))
	ids, paths := map[string]struct{}{}, map[string]struct{}{}
	for _, spec := range specs {
		ck, err := killswitch.LoadControllerSpec(spec)
		if err != nil {
			return nil, err
		}
		_, path, _ := strings.Cut(spec, "=")
		if _, ok := ids[ck.ID]; ok {
			return nil, fmt.Errorf("duplicate controller id")
		}
		if _, ok := paths[path]; ok {
			return nil, fmt.Errorf("duplicate controller key path")
		}
		ids[ck.ID] = struct{}{}
		paths[path] = struct{}{}
		out = append(out, ck)
	}
	return out, nil
}

func runStop(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("control-dir", "", "Control directory")
	sessionID := fs.String("session-id", "", "Target session id")
	epoch := fs.Uint64("revoke-through-epoch", 0, "Revoke through epoch (>=1)")
	controllerID := fs.String("controller-id", "", "Controller id")
	keyFile := fs.String("controller-key", "", "Controller HMAC key file")
	reason := fs.String("reason", "", "Stop reason")
	wait := fs.Duration("wait", 3*time.Second, "How long to wait for revoked_contained (0=publish only)")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	reasonText := strings.TrimSpace(*reason)
	if *dir == "" || *sessionID == "" || *epoch < 1 || *controllerID == "" || *keyFile == "" || reasonText == "" || *wait < 0 || *wait > 30*time.Second {
		fmt.Fprintf(stderr, "mcp-visor stop: --control-dir, --session-id, --revoke-through-epoch >= 1, --controller-id, --controller-key, and --reason are required; --wait must be 0..30s\n")
		return 1
	}
	if err := killswitch.ValidateControlDir(*dir); err != nil {
		fmt.Fprintf(stderr, "mcp-visor stop: %v\n", err)
		return 1
	}
	key, err := killswitch.LoadKeyFile(*keyFile)
	if err != nil {
		fmt.Fprintf(stderr, "mcp-visor stop: %v\n", err)
		return 1
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		fmt.Fprintf(stderr, "mcp-visor stop: %v\n", err)
		return 1
	}
	cmd := killswitch.Command{
		SchemaVersion:      killswitch.SchemaVersion,
		CommandID:          hex.EncodeToString(id[:]),
		SessionID:          *sessionID,
		RevokeThroughEpoch: *epoch,
		ControllerID:       *controllerID,
		Reason:             reasonText,
	}
	if err := killswitch.SignCommand(&cmd, key); err != nil {
		fmt.Fprintf(stderr, "mcp-visor stop: %v\n", err)
		return 1
	}
	if _, err := killswitch.WriteCommand(*dir, cmd); err != nil {
		fmt.Fprintf(stderr, "mcp-visor stop: %v\n", err)
		return 1
	}
	if *wait == 0 {
		fmt.Fprintf(stdout, "command_id=%s session_id=%s revoked_through_epoch=%d resulting_state=published\n", cmd.CommandID, cmd.SessionID, cmd.RevokeThroughEpoch)
		return 0
	}
	deadline := time.Now().Add(*wait)
	ctrls := map[string][]byte{*controllerID: key}
	for {
		st, err := killswitch.ReadState(*dir, *sessionID, ctrls)
		if err == nil && st.CommandID == cmd.CommandID && st.SessionID == *sessionID && st.RevokedThroughEpoch >= *epoch {
			if st.ResultingState == "revoked_contained" {
				fmt.Fprintf(stdout, "command_id=%s session_id=%s revoked_through_epoch=%d resulting_state=%s\n", cmd.CommandID, cmd.SessionID, st.RevokedThroughEpoch, st.ResultingState)
				return 0
			}
			fmt.Fprintf(stderr, "mcp-visor stop: resulting_state=%s\n", st.ResultingState)
			return 1
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(stderr, "kinetic stop command published but enforcement was not observed before timeout\n")
			return 2
		}
		time.Sleep(killswitch.PollInterval)
	}
}
