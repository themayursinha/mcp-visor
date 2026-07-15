package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/themayursinha/mcp-visor/internal/approval"
	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/observability"
	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/receipt"
	"github.com/themayursinha/mcp-visor/internal/redaction"
	"github.com/themayursinha/mcp-visor/internal/siem"
	"github.com/themayursinha/mcp-visor/internal/signer"
	"github.com/themayursinha/mcp-visor/internal/trace"
	"github.com/themayursinha/mcp-visor/internal/webhook"
)

type Proxy struct {
	cfg            Config
	session        *Session
	logger         *slog.Logger
	engine         *policy.Engine
	audit          *audit.Logger
	redactor       *redaction.Engine
	approval       *approval.Engine
	tracer         trace.TraceLogger
	tracing        TracingConfig
	metrics        ProxyMetrics
	webhook        *webhook.Emitter
	siem           *siem.Exporter
	approvalSigner signer.Signer
	obs            *observability.Runtime
}

type Config struct {
	ServerCommand      string
	ServerName         string
	ServerArgs         []string
	ClientID           string
	SessionID          string
	Policy             *policy.Policy
	Engine             *policy.Engine
	AuditLogPath       string
	ApprovalDir        string
	ApprovalCLI        bool
	ApprovalSigningKey string
	ApprovalSigner     signer.Signer
	Tracing            TracingConfig
	ServerURL          string
	SSEPath            string
	InsecureTLS        bool
	RemoteCert         string
	RemoteKey          string
	RemoteCA           string
	RemoteServerName   string
	WebhookURLs        []string
	WebhookHMACSecret  string
	SIEMTargets        []string
	SIEMFormat         string
	Vault              VaultConfig
	Observability      observability.Config
}

type VaultConfig struct {
	Addr       string
	Token      string
	KeyName    string
	Namespace  string
	CACert     string
	SkipVerify bool
}

type approvalOutcome struct {
	Approved bool
	Reason   string
	Receipt  *receipt.DecisionReceipt
}

type approvalEvidence struct {
	RequestHash          string
	RedactedArgumentHash string
	PolicyHash           string
	ChainContextHash     string
	RedactedArgsJSON     string
	PolicyJSON           string
	ChainContextJSON     string
}

func New(cfg Config) *Proxy {
	if cfg.SessionID == "" {
		cfg.SessionID = fmt.Sprintf("sess-%d", os.Getpid())
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "mcp-client"
	}
	if cfg.ServerName == "" {
		cfg.ServerName = cfg.ServerCommand
	}
	p := cfg.Policy
	if p == nil {
		p = policy.DefaultPolicy()
	}

	al := audit.MustLogger(cfg.AuditLogPath)
	al.SetRedactionPatterns(p.Redaction.Patterns)

	eng := cfg.Engine
	if eng == nil {
		eng = policy.NewEngine(p)
	}
	eng.SetClientID(cfg.ClientID)
	red := redaction.NewEngine(p.Redaction)
	var appr *approval.Engine
	if cfg.ApprovalCLI {
		appr = approval.NewCLIEngine(time.Duration(p.Settings.ApprovalTimeoutSecs) * time.Second)
	} else {
		appr = approval.MustEngine(cfg.ApprovalDir, time.Duration(p.Settings.ApprovalTimeoutSecs)*time.Second)
	}
	wh := cfg.buildWebhookEmitter()
	siemExp := cfg.buildSIEMExporter()
	approvalSigner := cfg.buildApprovalSigner()

	return &Proxy{
		cfg:     cfg,
		session: NewSession(cfg.SessionID, cfg.ClientID),
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
		engine:         eng,
		audit:          al,
		redactor:       red,
		approval:       appr,
		tracing:        cfg.Tracing,
		webhook:        wh,
		siem:           siemExp,
		approvalSigner: approvalSigner,
	}
}

func NewWithTracing(cfg Config) *Proxy {
	if cfg.SessionID == "" {
		cfg.SessionID = fmt.Sprintf("sess-%d", os.Getpid())
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "mcp-client"
	}
	if cfg.ServerName == "" {
		cfg.ServerName = cfg.ServerCommand
	}
	p := cfg.Policy
	if p == nil {
		p = policy.DefaultPolicy()
	}

	al := audit.MustLogger(cfg.AuditLogPath)
	al.SetRedactionPatterns(p.Redaction.Patterns)

	eng := cfg.Engine
	if eng == nil {
		eng = policy.NewEngine(p)
	}
	eng.SetClientID(cfg.ClientID)
	red := redaction.NewEngine(p.Redaction)
	var appr *approval.Engine
	if cfg.ApprovalCLI {
		appr = approval.NewCLIEngine(time.Duration(p.Settings.ApprovalTimeoutSecs) * time.Second)
	} else {
		appr = approval.MustEngine(cfg.ApprovalDir, time.Duration(p.Settings.ApprovalTimeoutSecs)*time.Second)
	}
	wh := cfg.buildWebhookEmitter()
	siemExp := cfg.buildSIEMExporter()
	approvalSigner := cfg.buildApprovalSigner()

	proxy := &Proxy{
		cfg:     cfg,
		session: NewSession(cfg.SessionID, cfg.ClientID),
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
		engine:         eng,
		audit:          al,
		redactor:       red,
		approval:       appr,
		tracing:        cfg.Tracing,
		webhook:        wh,
		siem:           siemExp,
		approvalSigner: approvalSigner,
	}
	proxy.tracer = proxy.initTracer(cfg.Tracing)
	return proxy
}

func (p *Proxy) Run(ctx context.Context) error {
	if err := p.initObservability(); err != nil {
		return fmt.Errorf("observability: %w", err)
	}
	if p.cfg.ServerURL != "" {
		return p.RunRemote(ctx)
	}

	serverCmd := exec.CommandContext(ctx, p.cfg.ServerCommand, p.cfg.ServerArgs...)

	serverStdin, err := serverCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("server stdin pipe: %w", err)
	}
	serverStdout, err := serverCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("server stdout pipe: %w", err)
	}
	serverStderr, err := serverCmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("server stderr pipe: %w", err)
	}

	if err := serverCmd.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer func() {
		_ = serverCmd.Wait()
		p.logAudit(audit.Event{
			EventType: audit.EventSessionEnded,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    p.cfg.ServerName,
			Message:   "session ended",
		})
		_ = p.audit.Close()
		p.closeEventSinks()
		p.engine.Close()
	}()
	p.logger.Info("mcp server started", "command", p.cfg.ServerCommand)

	p.logAudit(audit.Event{
		EventType: audit.EventSessionStarted,
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
		Server:    p.cfg.ServerName,
		Message:   "session started",
	})

	go p.streamStderr(serverStderr)

	clientParser := mcp.NewParser(os.Stdin, os.Stdout)
	serverParser := mcp.NewParser(serverStdout, serverStdin)

	if err := p.runHandshake(clientParser, serverParser); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	p.logger.Info("proxy ready",
		"session", p.session.ID,
		"server", p.cfg.ServerName,
		"default_action", p.engine.Policy().DefaultAction,
	)

	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- p.relayClientToServer(ctx, clientParser, serverParser)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- p.relayServerToClient(ctx, serverParser, clientParser)
	}()

	go func() {
		wg.Wait()
		close(errCh)
	}()

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Proxy) streamStderr(stderr io.Reader) {
	data, _ := io.ReadAll(stderr)
	if len(data) > 0 {
		p.logger.Info("server stderr", "text", string(data))
	}
}

func (p *Proxy) runHandshake(client, server *mcp.Parser) error {
	raw, err := client.ReadRaw()
	if err != nil {
		return fmt.Errorf("read initialize: %w", err)
	}
	req, err := client.DecodeRequest(raw)
	if err != nil {
		return fmt.Errorf("decode initialize: %w", err)
	}
	if req.Method != mcp.MethodInitialize {
		return fmt.Errorf("expected initialize, got %s", req.Method)
	}

	var initReq mcp.InitializeRequest
	if err := json.Unmarshal(req.Params, &initReq); err != nil {
		return fmt.Errorf("decode initialize params: %w", err)
	}
	p.logger.Info("client init", "client", initReq.ClientInfo.Name, "version", initReq.ClientInfo.Version)

	if err := server.EncodeRaw(raw); err != nil {
		return fmt.Errorf("forward initialize to server: %w", err)
	}

	raw, err = server.ReadRaw()
	if err != nil {
		return fmt.Errorf("read initialize response: %w", err)
	}
	resp, err := server.DecodeResponse(raw)
	if err != nil {
		return fmt.Errorf("decode initialize response: %w", err)
	}

	var initResp mcp.InitializeResult
	if err := json.Unmarshal(resp.Result, &initResp); err == nil {
		p.logger.Info("server init", "server", initResp.ServerInfo.Name, "version", initResp.ServerInfo.Version)
	}

	if err := client.EncodeRaw(raw); err != nil {
		return fmt.Errorf("return initialize response: %w", err)
	}

	raw, err = client.ReadRaw()
	if err != nil {
		return fmt.Errorf("read initialized notification: %w", err)
	}
	if err := p.enforceHandshakeEnvelope(raw, client); err != nil {
		return err
	}
	notif, err := client.DecodeNotification(raw)
	if err != nil {
		p.logger.Warn("decode initialized notification failed, forwarding raw", "error", err)
		return server.EncodeRaw(raw)
	}
	if notif.Method != mcp.MethodInitialized {
		p.logger.Warn("expected initialized, got", "method", notif.Method)
	}
	return server.EncodeRaw(raw)
}

func (p *Proxy) relayClientToServer(ctx context.Context, client, server *mcp.Parser) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		raw, err := client.ReadRaw()
		if err != nil {
			return fmt.Errorf("read from client: %w", err)
		}

		modified, action := p.interceptAndModify(raw, client)
		if action == "denied" {
			continue
		}

		p.logClientMessage(modified)

		if err := server.EncodeRaw(modified); err != nil {
			return fmt.Errorf("forward to server: %w", err)
		}
	}
}

func (p *Proxy) interceptAndModify(raw json.RawMessage, client *mcp.Parser) (json.RawMessage, string) {
	serverName := serverNameOrDefault(p.cfg.ServerName, p.cfg.ServerCommand)
	respond := func(id any, message string) {
		_ = client.EncodeResponse(mcp.NewErrorResponse(id, -32000, message))
	}
	return p.interceptClientToServerEnvelope(raw, serverName, respond)
}

func (p *Proxy) checkChain(serverName string, callReq mcp.ToolsCallRequest, redactedArgs map[string]any, risk policy.RiskLevel) (policy.Decision, []string) {
	windowSize := p.engine.Policy().Settings.ChainWindowSize
	if windowSize == 0 {
		windowSize = 10
	}
	previousCalls := p.session.RecentCallChain(windowSize)
	chainDecision := p.engine.EvaluateChain(serverName, callReq, previousCalls)

	if chainDecision.Action == policy.ActionDeny {
		p.logAudit(audit.Event{
			EventType:    audit.EventToolChainDetected,
			SessionID:    p.session.ID,
			AgentID:      p.cfg.ClientID,
			Server:       serverName,
			Tool:         callReq.Name,
			Arguments:    redactedArgs,
			Decision:     string(chainDecision.Action),
			Reason:       chainDecision.Reason,
			RiskLevel:    string(risk),
			ChainContext: previousCalls,
		})

		p.logger.Warn("chain denied",
			"tool", callReq.Name,
			"reason", chainDecision.Reason,
			"previous_calls", previousCalls,
			"session", p.session.ID,
		)
		return chainDecision, previousCalls
	}

	if chainDecision.Action == policy.ActionRequireApproval {
		p.logAudit(audit.Event{
			EventType:    audit.EventToolChainDetected,
			SessionID:    p.session.ID,
			AgentID:      p.cfg.ClientID,
			Server:       serverName,
			Tool:         callReq.Name,
			Arguments:    redactedArgs,
			Decision:     string(chainDecision.Action),
			Reason:       chainDecision.Reason,
			RiskLevel:    string(risk),
			ChainContext: previousCalls,
		})

		p.logger.Warn("chain requires approval",
			"tool", callReq.Name,
			"reason", chainDecision.Reason,
			"previous_calls", previousCalls,
			"session", p.session.ID,
		)
		return chainDecision, previousCalls
	}

	return policy.Decision{Action: policy.ActionAllow, Reason: "no chain rule matched"}, nil
}

func (p *Proxy) relayServerToClient(ctx context.Context, server, client *mcp.Parser) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		raw, err := server.ReadRaw()
		if err != nil {
			return fmt.Errorf("read from server: %w", err)
		}

		raw = p.redactServerResponse(raw)

		p.logServerMessage(raw)

		if err := client.EncodeRaw(raw); err != nil {
			return fmt.Errorf("forward to client: %w", err)
		}
	}
}

func (p *Proxy) redactServerResponse(raw json.RawMessage) json.RawMessage {
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      any             `json:"id"`
		Result  json.RawMessage `json:"result,omitempty"`
		Error   json.RawMessage `json:"error,omitempty"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return raw
	}
	if resp.Result == nil {
		return raw
	}

	var result mcp.ToolsCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return raw
	}

	modified := false
	maxOutput := p.engine.Policy().Settings.MaxOutputSizeBytes
	for i, content := range result.Content {
		if content.Text != "" {
			redacted := p.redactor.RedactOutput(content.Text)
			if maxOutput > 0 && len(redacted) > maxOutput {
				redacted = redacted[:maxOutput] + fmt.Sprintf("\n[TRUNCATED: output exceeded %d bytes]", maxOutput)
			}
			if redacted != content.Text {
				result.Content[i].Text = redacted
				modified = true
			}
		}
	}

	if !modified {
		return raw
	}

	p.logger.Info("output redacted", "session", p.session.ID)

	newResult, err := json.Marshal(result)
	if err != nil {
		return raw
	}
	resp.Result = newResult

	newRaw, err := json.Marshal(resp)
	if err != nil {
		return raw
	}
	return append(newRaw, '\n')
}

func (p *Proxy) logClientMessage(raw json.RawMessage) {
	req, err := mcp.NewParser(nil, nil).DecodeRequest(raw)
	if err != nil || req.IsNotification() {
		return
	}

	switch req.Method {
	case mcp.MethodToolsCall:
		var call mcp.ToolsCallRequest
		if err := json.Unmarshal(req.Params, &call); err != nil {
			return
		}
		p.session.RecordToolCall(p.cfg.ServerName, call, "")
		risk := p.engine.GetRiskLevel(p.cfg.ServerName, call.Name)
		p.logger.Info("tool call",
			"session", p.session.ID,
			"tool", call.Name,
			"risk", risk,
			"call_number", p.session.ToolCallCount(),
		)
	case mcp.MethodToolsList:
		p.logger.Debug("tools/list", "session", p.session.ID)
	}
}

func (p *Proxy) logServerMessage(raw json.RawMessage) {
	resp, err := mcp.NewParser(nil, nil).DecodeResponse(raw)
	if err != nil {
		return
	}

	if resp.Error != nil {
		p.logger.Warn("server error",
			"code", resp.Error.Code,
			"message", resp.Error.Message,
		)
		return
	}

	var result mcp.ToolsCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return
	}

	preview := ""
	isError := result.IsError
	for _, content := range result.Content {
		if content.Text != "" {
			preview = content.Text
			break
		}
	}
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}

	p.session.mu.Lock()
	if len(p.session.ToolCalls) > 0 {
		p.session.ToolCalls[len(p.session.ToolCalls)-1].Result = preview
	}
	p.session.mu.Unlock()

	p.logger.Info("tool result",
		"session", p.session.ID,
		"is_error", isError,
		"preview", preview,
	)
}

func (p *Proxy) rewriteArgs(raw json.RawMessage, redactedArgs map[string]any) (json.RawMessage, error) {
	var req mcp.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	var callReq struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments,omitempty"`
	}
	if err := json.Unmarshal(req.Params, &callReq); err != nil {
		return nil, err
	}

	newArgs, err := json.Marshal(redactedArgs)
	if err != nil {
		return nil, err
	}
	callReq.Arguments = newArgs

	newParams, err := json.Marshal(callReq)
	if err != nil {
		return nil, err
	}
	req.Params = newParams

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (p *Proxy) extractPath(callReq mcp.ToolsCallRequest) string {
	if callReq.Arguments == nil {
		return ""
	}
	var args map[string]any
	if err := json.Unmarshal(callReq.Arguments, &args); err != nil {
		return ""
	}
	for _, key := range []string{"path", "file", "file_path", "uri"} {
		if v, ok := args[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func (p *Proxy) Session() *Session {
	return p.session
}

func (p *Proxy) Engine() *policy.Engine {
	return p.engine
}

func extractArgs(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil
	}
	return args
}

var sessionCounter int

func GenerateSessionID() string {
	sessionCounter++
	return fmt.Sprintf("sess-%d-%d", os.Getpid(), sessionCounter)
}

func (p *Proxy) initTracer(cfg TracingConfig) trace.TraceLogger {
	if !cfg.Enabled {
		return nil
	}
	switch cfg.Format {
	case TraceFormatJSONL:
		return &trace.JSONLLogger{}
	case TraceFormatSummary:
		return trace.NewSummaryLogger()
	default:
		return &trace.TextLogger{}
	}
}

func (p *Proxy) Metrics() *ProxyMetrics {
	return &p.metrics
}

func (p *Proxy) evaluateRuntimeLimits(callReq mcp.ToolsCallRequest) policy.Decision {
	settings := p.engine.Policy().Settings

	if settings.MaxArgumentSizeBytes > 0 && len(callReq.Arguments) > settings.MaxArgumentSizeBytes {
		return policy.Decision{
			Action: policy.ActionDeny,
			Reason: fmt.Sprintf("argument size %d exceeds max %d bytes", len(callReq.Arguments), settings.MaxArgumentSizeBytes),
		}
	}

	if settings.SessionMaxTools > 0 && p.session.ToolCallCount() >= settings.SessionMaxTools {
		return policy.Decision{
			Action: policy.ActionDeny,
			Reason: fmt.Sprintf("session tool limit %d exceeded", settings.SessionMaxTools),
		}
	}

	if settings.SessionTimeoutSecs > 0 && time.Since(p.session.CreatedAt) > time.Duration(settings.SessionTimeoutSecs)*time.Second {
		return policy.Decision{
			Action: policy.ActionDeny,
			Reason: fmt.Sprintf("session timeout %d seconds exceeded", settings.SessionTimeoutSecs),
		}
	}

	return policy.Decision{Action: policy.ActionAllow, Reason: "runtime limits passed"}
}

func (p *Proxy) logDenied(serverName, toolName string, args map[string]any, reason string, risk policy.RiskLevel) {
	p.logAudit(audit.Event{
		EventType: audit.EventToolDenied,
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
		Server:    serverName,
		Tool:      toolName,
		Arguments: args,
		Decision:  string(policy.ActionDeny),
		Reason:    reason,
		RiskLevel: string(risk),
	})
}

func (p *Proxy) requestApproval(serverName string, callReq mcp.ToolsCallRequest, redactedArgs map[string]any, reason string, risk policy.RiskLevel, raw json.RawMessage, chainContext []string) approvalOutcome {
	approvalReq := approval.Request{
		ID:        fmt.Sprintf("%s-%s-%d", p.session.ID, callReq.Name, p.session.ToolCallCount()),
		Tool:      callReq.Name,
		Server:    serverName,
		Arguments: redactedArgs,
		Reason:    reason,
		RiskLevel: string(risk),
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
	}
	evidence := p.buildApprovalEvidence(raw, redactedArgs, chainContext)

	p.logger.Warn("approval requested",
		"tool", callReq.Name,
		"id", approvalReq.ID,
		"session", p.session.ID,
	)

	p.metrics.IncrementApprovals()
	p.logAudit(audit.Event{
		EventType:            audit.EventToolApprovalRequired,
		SessionID:            p.session.ID,
		AgentID:              p.cfg.ClientID,
		Server:               serverName,
		Tool:                 callReq.Name,
		Arguments:            redactedArgs,
		Decision:             string(policy.ActionRequireApproval),
		Reason:               reason,
		RiskLevel:            string(risk),
		ChainContext:         chainContext,
		RequestHash:          evidence.RequestHash,
		RedactedArgumentHash: evidence.RedactedArgumentHash,
		PolicyHash:           evidence.PolicyHash,
		ChainContextHash:     evidence.ChainContextHash,
	})

	approved, err := p.approval.RequestApproval(approvalReq)
	if err != nil || !approved {
		denyReason := fmt.Sprintf("approval denied: %v", err)
		p.logAudit(audit.Event{
			EventType:            audit.EventToolDenied,
			SessionID:            p.session.ID,
			AgentID:              p.cfg.ClientID,
			Server:               serverName,
			Tool:                 callReq.Name,
			Arguments:            redactedArgs,
			Decision:             string(policy.ActionDeny),
			Reason:               denyReason,
			RiskLevel:            string(risk),
			ChainContext:         chainContext,
			RequestHash:          evidence.RequestHash,
			RedactedArgumentHash: evidence.RedactedArgumentHash,
			PolicyHash:           evidence.PolicyHash,
			ChainContextHash:     evidence.ChainContextHash,
		})
		p.logger.Warn("approval denied", "tool", callReq.Name, "session", p.session.ID)
		return approvalOutcome{Approved: false, Reason: denyReason}
	}

	rec, err := receipt.NewReceipt(
		approvalReq.ID,
		p.session.ID,
		p.cfg.ClientID,
		serverName,
		callReq.Name,
		string(raw),
		evidence.RedactedArgsJSON,
		p.engine.Policy().Version,
		evidence.PolicyJSON,
		evidence.ChainContextJSON,
		reason,
		string(risk),
		"human-operator",
		"approve",
		time.Duration(p.engine.Policy().Settings.ApprovalTimeoutSecs)*time.Second,
	)
	if err != nil {
		errReason := fmt.Sprintf("approval receipt creation failed: %v", err)
		p.logDenied(serverName, callReq.Name, redactedArgs, errReason, risk)
		return approvalOutcome{Approved: false, Reason: errReason}
	}
	if p.approvalSigner == nil {
		errReason := "approval receipt signing failed: signer is not configured"
		p.logDenied(serverName, callReq.Name, redactedArgs, errReason, risk)
		return approvalOutcome{Approved: false, Reason: errReason}
	}
	if err := rec.SignWith(p.approvalSigner); err != nil {
		errReason := fmt.Sprintf("approval receipt signing failed: %v", err)
		p.logDenied(serverName, callReq.Name, redactedArgs, errReason, risk)
		return approvalOutcome{Approved: false, Reason: errReason}
	}

	return approvalOutcome{Approved: true, Receipt: rec}
}

func (p *Proxy) buildApprovalEvidence(raw json.RawMessage, redactedArgs map[string]any, chainContext []string) approvalEvidence {
	argsJSON := marshalEvidence(redactedArgs)
	policyJSON := marshalEvidence(p.engine.Policy())
	chainJSON := marshalEvidence(chainContext)
	return approvalEvidence{
		RequestHash:          sha256Hex(raw),
		RedactedArgumentHash: sha256Hex([]byte(argsJSON)),
		PolicyHash:           sha256Hex([]byte(policyJSON)),
		ChainContextHash:     sha256Hex([]byte(chainJSON)),
		RedactedArgsJSON:     argsJSON,
		PolicyJSON:           policyJSON,
		ChainContextJSON:     chainJSON,
	}
}

func (p *Proxy) attachReceiptEvidence(event *audit.Event, rec *receipt.DecisionReceipt) {
	if rec == nil {
		return
	}
	event.RequestHash = rec.OriginalRequest
	event.RedactedArgumentHash = rec.RedactedArgs
	event.PolicyHash = rec.PolicyHash
	event.ChainContextHash = rec.ChainContextHash
	data, err := rec.Marshal()
	if err != nil {
		return
	}
	event.ApprovalReceiptHash = sha256Hex(data)
	var recMap map[string]any
	if err := json.Unmarshal(data, &recMap); err == nil {
		event.ApprovalReceipt = recMap
	}
}

func (p *Proxy) logAudit(event audit.Event) {
	p.audit.Log(event)
	if p.webhook != nil {
		p.webhook.Emit(event)
	}
	if p.siem != nil {
		if err := p.siem.Export(event); err != nil {
			p.logger.Warn("siem export failed", "error", err)
		}
	}
}

func marshalEvidence(v any) string {
	if v == nil {
		return "null"
	}
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(data)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (p *Proxy) closeEventSinks() {
	p.shutdownObservability()
	if p.webhook != nil {
		p.webhook.Close()
	}
	if p.siem != nil {
		_ = p.siem.Close()
	}
}

func (cfg Config) buildWebhookEmitter() *webhook.Emitter {
	if len(cfg.WebhookURLs) == 0 {
		return nil
	}
	return webhook.NewEmitter(webhook.Config{
		URLs:       cfg.WebhookURLs,
		HMACSecret: cfg.WebhookHMACSecret,
	})
}

func (cfg Config) buildSIEMExporter() *siem.Exporter {
	if len(cfg.SIEMTargets) == 0 {
		return nil
	}
	format := siem.FormatJSON
	switch cfg.SIEMFormat {
	case string(siem.FormatSyslog5424):
		format = siem.FormatSyslog5424
	case string(siem.FormatCEF):
		format = siem.FormatCEF
	case "", string(siem.FormatJSON):
		format = siem.FormatJSON
	default:
		fmt.Fprintf(os.Stderr, "siem exporter: unknown format %q, using json\n", cfg.SIEMFormat)
	}
	return siem.MustExporter(siem.Config{
		Format:  format,
		Targets: cfg.SIEMTargets,
	})
}

func (cfg Config) buildApprovalSigner() signer.Signer {
	if cfg.ApprovalSigner != nil {
		return cfg.ApprovalSigner
	}

	if cfg.Vault.Addr != "" {
		s, err := cfg.buildSigner()
		if err != nil {
			fmt.Fprintf(os.Stderr, "approval signer: %v\n", err)
			return nil
		}
		return s
	}

	if cfg.ApprovalSigningKey != "" {
		s, err := signer.LoadApprovalSigner(cfg.ApprovalSigningKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "approval signer: %v\n", err)
			return nil
		}
		return s
	}

	s, err := signer.NewApprovalSigner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "approval signer: %v\n", err)
		return nil
	}
	return s
}

func serverNameOrDefault(serverName, fallback string) string {
	if serverName != "" {
		return serverName
	}
	return fallback
}

func (p *Proxy) SetLogLevel(level slog.Level) {
	p.logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
}

func (p *Proxy) Tracer() trace.TraceLogger {
	return p.tracer
}
