package proxy

import (
	"encoding/json"
	"fmt"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

const (
	reasonNotificationToolsCallBlocked = "notification-form tools/call blocked"
	reasonInvalidToolsCallRequest      = "invalid tools/call request"
)

// interceptClientToServerEnvelope is the shared stdio/remote client→server gate for tools/call.
func (p *Proxy) interceptClientToServerEnvelope(
	raw json.RawMessage,
	serverName string,
	respond toolsCallResponder,
) (json.RawMessage, string) {
	env := mcp.ClassifyClientEnvelope(raw)
	switch env.Kind {
	case mcp.EnvelopeForward:
		return raw, "forward"
	case mcp.EnvelopeToolsCallNotification:
		toolName := toolNameFromToolsCallParams(env.Request.Params)
		p.denyToolsCallEnvelope(serverName, toolName, reasonNotificationToolsCallBlocked, nil)
		return raw, "denied"
	case mcp.EnvelopeToolsCallMalformed:
		respond(env.Request.ID, reasonInvalidToolsCallRequest)
		p.logDenied(serverName, toolNameFromToolsCallParams(env.Request.Params), nil, reasonInvalidToolsCallRequest, policy.RiskUnknown)
		p.metrics.IncrementProcessed()
		p.metrics.IncrementDenied()
		return raw, "denied"
	case mcp.EnvelopeToolsCallRequest:
		req := env.Request
		var callReq mcp.ToolsCallRequest
		if err := json.Unmarshal(req.Params, &callReq); err != nil {
			respond(req.ID, "invalid tools/call parameters")
			p.logDenied(serverName, "", nil, "invalid tools/call parameters", policy.RiskUnknown)
			return raw, "denied"
		}
		originalRaw := raw
		return p.processToolsCall(req, callReq, raw, originalRaw, serverName, respond)
	default:
		return raw, "forward"
	}
}

func (p *Proxy) denyToolsCallEnvelope(serverName, toolName, reason string, args map[string]any) {
	p.metrics.IncrementProcessed()
	p.metrics.IncrementDenied()
	p.logDenied(serverName, toolName, args, reason, policy.RiskUnknown)
	p.logger.Warn("tools/call envelope denied",
		"tool", toolName,
		"reason", reason,
		"session", p.session.ID,
	)
}

// enforceHandshakeEnvelope applies the shared envelope gate to the client's
// post-initialize message. A denied message terminates the handshake.
func (p *Proxy) enforceHandshakeEnvelope(raw json.RawMessage, client *mcp.Parser) error {
	serverName, respond := p.handshakeEnvelopeResponder(client)
	_, action := p.interceptClientToServerEnvelope(raw, serverName, respond)
	if action == "denied" {
		return fmt.Errorf("post-initialize message denied")
	}
	return nil
}

func (p *Proxy) handshakeEnvelopeResponder(client *mcp.Parser) (string, toolsCallResponder) {
	if p.cfg.ServerURL != "" {
		serverName := serverNameOrDefault(p.cfg.ServerName, p.cfg.ServerURL)
		respond := func(id any, message string) {
			resp := mcp.NewErrorResponse(id, -32000, message)
			_ = encodeAndForwardToClient(resp, client)
		}
		return serverName, respond
	}
	serverName := serverNameOrDefault(p.cfg.ServerName, p.cfg.ServerCommand)
	respond := func(id any, message string) {
		_ = client.EncodeResponse(mcp.NewErrorResponse(id, -32000, message))
	}
	return serverName, respond
}

func toolNameFromToolsCallParams(params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	var peek struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &peek); err != nil {
		return ""
	}
	return peek.Name
}
