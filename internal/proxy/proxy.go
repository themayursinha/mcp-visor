package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/redaction"
)

type Proxy struct {
	cfg      Config
	session  *Session
	logger   *slog.Logger
	engine   *policy.Engine
	audit    *audit.Logger
	redactor *redaction.Engine
}

type Config struct {
	ServerCommand string
	ServerArgs    []string
	ClientID      string
	SessionID     string
	Policy        *policy.Policy
	AuditLogPath  string
}

func New(cfg Config) *Proxy {
	if cfg.SessionID == "" {
		cfg.SessionID = fmt.Sprintf("sess-%d", os.Getpid())
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "mcp-client"
	}
	p := cfg.Policy
	if p == nil {
		p = policy.DefaultPolicy()
	}

	al := audit.MustLogger(cfg.AuditLogPath)
	al.SetRedactionPatterns(p.Redaction.Patterns)

	eng := policy.NewEngine(p)
	red := redaction.NewEngine(p.Redaction)

	return &Proxy{
		cfg:      cfg,
		session:  NewSession(cfg.SessionID, cfg.ClientID),
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
		engine:   eng,
		audit:    al,
		redactor: red,
	}
}

func (p *Proxy) Run(ctx context.Context) error {
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
		serverCmd.Wait()
		p.audit.Log(audit.Event{
			EventType: audit.EventSessionEnded,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    p.cfg.ServerCommand,
			Message:   "session ended",
		})
		p.audit.Close()
	}()
	p.logger.Info("mcp server started", "command", p.cfg.ServerCommand)

	p.audit.Log(audit.Event{
		EventType: audit.EventSessionStarted,
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
		Server:    p.cfg.ServerCommand,
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
		"server", p.cfg.ServerCommand,
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
	req, err := mcp.NewParser(nil, nil).DecodeRequest(raw)
	if err != nil || req.IsNotification() {
		return raw, "forward"
	}

	if req.Method != mcp.MethodToolsCall {
		return raw, "forward"
	}

	var callReq mcp.ToolsCallRequest
	if err := json.Unmarshal(req.Params, &callReq); err != nil {
		return raw, "forward"
	}

	serverName := p.cfg.ServerCommand
	argsMap := extractArgs(callReq.Arguments)

	redactedArgs, redactionResult := p.redactor.RedactArgs(argsMap)
	if redactionResult.Redacted {
		p.logger.Info("arguments redacted",
			"tool", callReq.Name,
			"fields", redactionResult.RedactedFields,
			"session", p.session.ID,
		)
		p.audit.Log(audit.Event{
			EventType: audit.EventToolAllowed,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Arguments: redactedArgs,
			Decision:  "redact_then_allow",
			Reason:    fmt.Sprintf("redacted fields: %v", redactionResult.RedactedFields),
			RiskLevel: string(p.engine.GetRiskLevel(serverName, callReq.Name)),
		})
		rewritten, err := p.rewriteArgs(raw, redactedArgs)
		if err == nil {
			raw = rewritten
		}
	}

	sensitivePath := p.extractPath(callReq)
	if sensitivePath != "" && p.redactor.IsSensitiveFile(sensitivePath) {
		errResp := mcp.NewErrorResponse(req.ID, -32000, fmt.Sprintf("access to sensitive file denied: %s", sensitivePath))
		client.EncodeResponse(errResp)

		p.audit.Log(audit.Event{
			EventType: audit.EventToolDenied,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Arguments: redactedArgs,
			Decision:  string(policy.ActionDeny),
			Reason:    fmt.Sprintf("sensitive file: %s", sensitivePath),
			RiskLevel: string(p.engine.GetRiskLevel(serverName, callReq.Name)),
		})

		p.logger.Warn("sensitive file denied",
			"tool", callReq.Name,
			"path", sensitivePath,
			"session", p.session.ID,
		)
		return raw, "denied"
	}

	decision := p.engine.Evaluate(serverName, callReq)
	risk := p.engine.GetRiskLevel(serverName, callReq.Name)

	switch decision.Action {
	case policy.ActionDeny:
		errResp := mcp.NewErrorResponse(req.ID, -32000, decision.Reason)
		client.EncodeResponse(errResp)

		p.audit.Log(audit.Event{
			EventType: audit.EventToolDenied,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Arguments: redactedArgs,
			Decision:  string(decision.Action),
			Reason:    decision.Reason,
			RiskLevel: string(risk),
		})

		p.logger.Warn("policy denied",
			"tool", callReq.Name,
			"reason", decision.Reason,
			"session", p.session.ID,
		)
		return raw, "denied"

	case policy.ActionRequireApproval:
		p.audit.Log(audit.Event{
			EventType: audit.EventToolApprovalRequired,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      callReq.Name,
			Arguments: redactedArgs,
			Decision:  string(decision.Action),
			Reason:    decision.Reason,
			RiskLevel: string(risk),
		})

		p.logger.Warn("approval required",
			"tool", callReq.Name,
			"session", p.session.ID,
		)
		return raw, "forward"

	case policy.ActionAllow:
		windowSize := p.engine.Policy().Settings.ChainWindowSize
		if windowSize == 0 {
			windowSize = 10
		}
		previousCalls := p.session.RecentCallChain(windowSize)
		chainDecision := p.engine.EvaluateChain(serverName, callReq, previousCalls)

		if chainDecision.Action == policy.ActionDeny {
			errResp := mcp.NewErrorResponse(req.ID, -32000, chainDecision.Reason)
			client.EncodeResponse(errResp)

			p.audit.Log(audit.Event{
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
			return raw, "denied"
		}

		if chainDecision.Action == policy.ActionRequireApproval {
			p.audit.Log(audit.Event{
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
		}

		return raw, "forward"

	default:
		return raw, "forward"
	}
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
	for i, content := range result.Content {
		if content.Text != "" {
			redacted := p.redactor.RedactOutput(content.Text)
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
		p.session.RecordToolCall(p.cfg.ServerCommand, call, "")
		risk := p.engine.GetRiskLevel(p.cfg.ServerCommand, call.Name)
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
		Name      string         `json:"name"`
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
