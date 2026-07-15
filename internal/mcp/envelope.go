package mcp

import "encoding/json"

// ClientEnvelopeKind classifies client-to-proxy JSON-RPC lines at the tools/call gate.
type ClientEnvelopeKind int

const (
	EnvelopeForward ClientEnvelopeKind = iota
	EnvelopeToolsCallRequest
	EnvelopeToolsCallNotification
	EnvelopeToolsCallMalformed
)

// ClientEnvelope is the result of ClassifyClientEnvelope.
type ClientEnvelope struct {
	Kind    ClientEnvelopeKind
	Request Request
}

type envelopePeek struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id"`
}

func (p envelopePeek) hasResponseID() bool {
	if len(p.ID) == 0 {
		return false
	}
	return string(p.ID) != "null"
}

// ClassifyClientEnvelope decides whether a client message should be forwarded,
// handled as a valid tools/call request, or fail-closed as a tools/call bypass attempt.
// Unrelated traffic (including non-tools notifications) is forwarded unchanged.
func ClassifyClientEnvelope(raw json.RawMessage) ClientEnvelope {
	data := trimEnvelopeJSON(raw)

	var req Request
	if err := json.Unmarshal(data, &req); err == nil {
		if req.Method != MethodToolsCall {
			return ClientEnvelope{Kind: EnvelopeForward}
		}
		if req.IsNotification() {
			return ClientEnvelope{Kind: EnvelopeToolsCallNotification, Request: req}
		}
		if req.JSONRPC != JSONRPCVersion {
			return ClientEnvelope{Kind: EnvelopeToolsCallMalformed, Request: req}
		}
		return ClientEnvelope{Kind: EnvelopeToolsCallRequest, Request: req}
	}

	var peek envelopePeek
	if err := json.Unmarshal(data, &peek); err != nil || peek.Method != MethodToolsCall {
		return ClientEnvelope{Kind: EnvelopeForward}
	}
	if !peek.hasResponseID() {
		return ClientEnvelope{Kind: EnvelopeToolsCallNotification, Request: Request{Method: MethodToolsCall}}
	}
	return ClientEnvelope{Kind: EnvelopeToolsCallMalformed, Request: Request{
		Method: peek.Method,
		ID:     decodePeekID(peek.ID),
	}}
}

func trimEnvelopeJSON(raw json.RawMessage) []byte {
	data := []byte(raw)
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r') {
		data = data[:len(data)-1]
	}
	return data
}

func decodePeekID(id json.RawMessage) any {
	var decoded any
	if err := json.Unmarshal(id, &decoded); err != nil {
		return nil
	}
	return decoded
}
