package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/transport"
)

func (p *Proxy) RunRemote(ctx context.Context) error {
	httpCfg := transport.HTTPConfig{
		BaseURL: p.cfg.ServerURL,
		SSEPath: p.cfg.SSEPath,
		Timeout: 30 * time.Second,
	}
	if p.cfg.InsecureTLS || p.cfg.RemoteCert != "" || p.cfg.RemoteKey != "" || p.cfg.RemoteCA != "" || p.cfg.RemoteServerName != "" {
		httpCfg.TLS = &transport.TLSConfig{
			CertFile:     p.cfg.RemoteCert,
			KeyFile:      p.cfg.RemoteKey,
			CAFile:       p.cfg.RemoteCA,
			InsecureSkip: p.cfg.InsecureTLS,
			ServerName:   p.cfg.RemoteServerName,
		}
		if p.cfg.InsecureTLS {
			p.logger.Warn("remote TLS certificate verification is disabled")
		}
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

	p.logAudit(audit.Event{
		EventType: audit.EventSessionStarted,
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
		Server:    p.cfg.ServerName,
		Message:   "session started (remote)",
	})
	defer func() {
		p.logAudit(audit.Event{
			EventType: audit.EventSessionEnded,
			SessionID: p.session.ID,
			AgentID:   p.cfg.ClientID,
			Server:    p.cfg.ServerName,
			Message:   "session ended (remote)",
		})
		_ = p.audit.Close()
		p.closeEventSinks()
		p.engine.Close()
	}()

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

		modified, action := p.interceptAndModifyRemote(raw, client)
		if action == "denied" {
			continue
		}

		p.logClientMessage(modified)

		if err := remote.EncodeRaw(modified); err != nil {
			return fmt.Errorf("forward to remote server: %w", err)
		}
	}
}

func (p *Proxy) interceptAndModifyRemote(raw json.RawMessage, client *mcp.Parser) (json.RawMessage, string) {
	serverName := serverNameOrDefault(p.cfg.ServerName, p.cfg.ServerURL)
	respond := func(id any, message string) {
		resp := mcp.NewErrorResponse(id, -32000, message)
		_ = encodeAndForwardToClient(resp, client)
	}
	return p.interceptClientToServerEnvelope(raw, serverName, respond)
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
