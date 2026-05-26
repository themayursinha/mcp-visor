package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/themayursinha/mcp-visor/internal/approval"
	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/transport"
)

func (p *Proxy) RunRemote(ctx context.Context) error {
	httpCfg := transport.HTTPConfig{
		BaseURL: p.cfg.ServerURL,
		SSEPath: p.cfg.SSEPath,
		Timeout: 30 * time.Second,
	}
	if p.cfg.InsecureTLS {
		httpCfg.TLS = &transport.TLSConfig{InsecureSkip: true}
	}

	remoteTransport, err := transport.NewHTTPTransport(httpCfg)
	if err != nil {
		return fmt.Errorf("create HTTP transport: %w", err)
	}
	defer remoteTransport.Close()

	if err := remoteTransport.ConnectSSE(); err != nil {
		return fmt.Errorf("connect SSE: %w", err)
	}

	p.logger.Info("connected to remote MCP server via SSE",
		"url", p.cfg.ServerURL,
		"sse_path", httpCfg.SSEPath,
	)

	p.audit.Log(audit.Event{
		EventType: audit.EventSessionStarted,
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
		Server:    p.cfg.ServerName,
		Message:   "session started (remote)",
	})

	clientParser := mcp.NewParser(os.Stdin, os.Stdout)

	if err := p.runRemoteHandshake(ctx, clientParser, remoteTransport); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	p.logger.Info("proxy ready",
		"session", p.session.ID,
		"server", p.cfg.ServerName,
		"default_action", p.engine.Policy().DefaultAction,
		"transport", "http+sse",
	)

	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- p.relayClientToRemoteServer(ctx, clientParser, remoteTransport)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- p.relayRemoteServerToClient(ctx, remoteTransport, clientParser)
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

	p.audit.Log(audit.Event{
		EventType: audit.EventSessionEnded,
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
		Server:    p.cfg.ServerName,
		Message:   "session ended (remote)",
	})
	return nil
}

func (p *Proxy) runRemoteHandshake(ctx context.Context, client *mcp.Parser, remote transport.Transport) error {
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

	if err := remote.EncodeRaw(raw); err != nil {
		return fmt.Errorf("forward initialize to remote server: %w", err)
	}

	raw, err = remote.ReadRaw()
	if err != nil {
		return fmt.Errorf("read initialize response from remote: %w", err)
	}

	resp, err := decodeRemoteResponse(raw)
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
		return remote.EncodeRaw(raw)
	}
	if notif.Method != mcp.MethodInitialized {
		p.logger.Warn("expected initialized, got", "method", notif.Method)
	}
	return remote.EncodeRaw(raw)
}

func (p *Proxy) relayClientToRemoteServer(ctx context.Context, client *mcp.Parser, remote transport.Transport) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		raw, err := client.ReadRaw()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read from client: %w", err)
		}

		modified, action := p.interceptAndModifyRemote(raw, client, remote)
		if action == "denied" {
			continue
		}

		p.logClientMessage(modified)

		if err := remote.EncodeRaw(modified); err != nil {
			return fmt.Errorf("forward to remote server: %w", err)
		}
	}
}

func (p *Proxy) interceptAndModifyRemote(raw json.RawMessage, client *mcp.Parser, remote transport.Transport) (json.RawMessage, string) {
	req, err := client.DecodeRequest(raw)
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

	serverName := p.cfg.ServerName
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
		resp := mcp.NewErrorResponse(req.ID, -32000, fmt.Sprintf("access to sensitive file denied: %s", sensitivePath))
		_ = encodeAndForwardToClient(resp, client)

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
			"tool", callReq.Name, "path", sensitivePath, "session", p.session.ID,
		)
		return raw, "denied"
	}

	decision := p.engine.Evaluate(serverName, callReq)
	risk := p.engine.GetRiskLevel(serverName, callReq.Name)

	if decision.Action != policy.ActionDeny {
		chainResult := p.checkChain(serverName, callReq, redactedArgs, risk)
		if chainResult == "denied" {
			resp := mcp.NewErrorResponse(req.ID, -32000, "chain rule: tool sequence matches dangerous pattern")
			_ = encodeAndForwardToClient(resp, client)
			return raw, "denied"
		}
	}

	switch decision.Action {
	case policy.ActionDeny:
		resp := mcp.NewErrorResponse(req.ID, -32000, decision.Reason)
		_ = encodeAndForwardToClient(resp, client)

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
			"tool", callReq.Name, "reason", decision.Reason, "session", p.session.ID,
		)
		return raw, "denied"

	case policy.ActionRequireApproval:
		approved := p.handleApproval(callReq.Name, serverName, redactedArgs, decision.Reason, risk)
		if !approved {
			resp := mcp.NewErrorResponse(req.ID, -32000, "execution denied: approval not granted")
			_ = encodeAndForwardToClient(resp, client)
			return raw, "denied"
		}
		return raw, "forward"

	case policy.ActionAllow:
		return raw, "forward"

	default:
		return raw, "forward"
	}
}

func (p *Proxy) relayRemoteServerToClient(ctx context.Context, remote transport.Transport, client *mcp.Parser) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		raw, err := remote.ReadRaw()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read from remote server: %w", err)
		}

		raw = p.redactServerResponse(raw)
		p.logServerMessage(raw)

		if err := client.EncodeRaw(raw); err != nil {
			return fmt.Errorf("forward to client: %w", err)
		}
	}
}

func decodeRemoteResponse(raw json.RawMessage) (mcp.Response, error) {
	var resp mcp.Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return mcp.Response{}, fmt.Errorf("decode response: %w", err)
	}
	return resp, nil
}

func encodeAndForwardToClient(resp mcp.Response, client *mcp.Parser) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return client.EncodeRaw(data)
}

func (p *Proxy) handleApproval(toolName, serverName string, args map[string]any, reason string, risk policy.RiskLevel) bool {
	approvalReq := approval.Request{
		ID:        fmt.Sprintf("%s-%s-%d", p.session.ID, toolName, p.session.ToolCallCount()),
		Tool:      toolName,
		Server:    serverName,
		Arguments: args,
		Reason:    reason,
		RiskLevel: string(risk),
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
	}
	p.logger.Warn("approval requested", "tool", toolName, "session", p.session.ID)
	approved, err := p.approval.RequestApproval(approvalReq)
	if err != nil || !approved {
		p.audit.Log(audit.Event{
			EventType: audit.EventToolDenied,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    serverName,
			Tool:      toolName,
			Arguments: args,
			Decision:  string(policy.ActionDeny),
			Reason:    fmt.Sprintf("approval denied: %v", err),
			RiskLevel: string(risk),
		})
		p.logger.Warn("approval denied", "tool", toolName, "session", p.session.ID)
		return false
	}
	p.audit.Log(audit.Event{
		EventType: audit.EventToolAllowed,
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
		Server:    serverName,
		Tool:      toolName,
		Arguments: args,
		Decision:  string(policy.ActionAllow),
		Reason:    "approved by human operator",
		RiskLevel: string(risk),
	})
	p.logger.Info("approval granted", "tool", toolName, "session", p.session.ID)
	return true
}
