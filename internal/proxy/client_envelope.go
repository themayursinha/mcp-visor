package proxy

import (
	"encoding/json"

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
