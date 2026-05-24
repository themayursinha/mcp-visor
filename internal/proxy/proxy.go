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

	"github.com/themayursinha/mcp-visor/internal/mcp"
)

type Proxy struct {
	cfg     Config
	session *Session
	logger  *slog.Logger
}

type Config struct {
	ServerCommand string
	ServerArgs    []string
	ClientID      string
	SessionID     string
}

func New(cfg Config) *Proxy {
	if cfg.SessionID == "" {
		cfg.SessionID = fmt.Sprintf("sess-%d", os.Getpid())
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "mcp-client"
	}
	return &Proxy{
		cfg:     cfg,
		session: NewSession(cfg.SessionID, cfg.ClientID),
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
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
	defer serverCmd.Wait()
	p.logger.Info("mcp server started", "command", p.cfg.ServerCommand)

	go p.streamStderr(serverStderr)

	clientParser := mcp.NewParser(os.Stdin, os.Stdout)
	serverParser := mcp.NewParser(serverStdout, serverStdin)

	if err := p.runHandshake(clientParser, serverParser); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	p.logger.Info("proxy ready", "session", p.session.ID, "server", p.cfg.ServerCommand)

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

		p.logClientMessage(raw)

		if err := server.EncodeRaw(raw); err != nil {
			return fmt.Errorf("forward to server: %w", err)
		}
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

		p.logServerMessage(raw)

		if err := client.EncodeRaw(raw); err != nil {
			return fmt.Errorf("forward to client: %w", err)
		}
	}
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
		p.logger.Info("tool call",
			"session", p.session.ID,
			"tool", call.Name,
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
		"is_error", result.IsError,
		"preview", preview,
	)
}

func (p *Proxy) Session() *Session {
	return p.session
}

var sessionCounter int

func GenerateSessionID() string {
	sessionCounter++
	return fmt.Sprintf("sess-%d-%d", os.Getpid(), sessionCounter)
}
