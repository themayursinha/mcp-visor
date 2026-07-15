package mcp

import (
	"bytes"
	"encoding/json"
)

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

type clientEnvelopeScan struct {
	hasToolsCallMethod bool
	methodCount        int
	id                 json.RawMessage
}

func (s clientEnvelopeScan) hasResponseID() bool {
	if len(s.id) == 0 {
		return false
	}
	return string(s.id) != "null"
}

// ClassifyClientEnvelope decides whether a client message should be forwarded,
// handled as a valid tools/call request, or fail-closed as a tools/call bypass attempt.
// Unrelated traffic (including non-tools notifications) is forwarded unchanged.
func ClassifyClientEnvelope(raw json.RawMessage) ClientEnvelope {
	data := trimEnvelopeJSON(raw)
	scan := scanClientEnvelope(data)

	var req Request
	if err := json.Unmarshal(data, &req); err == nil {
		if req.Method != MethodToolsCall {
			if !scan.hasToolsCallMethod {
				return ClientEnvelope{Kind: EnvelopeForward}
			}
			return classifyScannedToolsCall(scan)
		}
		if scan.methodCount > 1 {
			return classifyScannedToolsCall(scan)
		}
		if req.IsNotification() {
			return ClientEnvelope{Kind: EnvelopeToolsCallNotification, Request: req}
		}
		if req.JSONRPC != JSONRPCVersion {
			return ClientEnvelope{Kind: EnvelopeToolsCallMalformed, Request: req}
		}
		return ClientEnvelope{Kind: EnvelopeToolsCallRequest, Request: req}
	}

	if !scan.hasToolsCallMethod {
		return ClientEnvelope{Kind: EnvelopeForward}
	}
	return classifyScannedToolsCall(scan)
}

func scanClientEnvelope(data []byte) clientEnvelopeScan {
	var scan clientEnvelopeScan
	decoder := json.NewDecoder(bytes.NewReader(data))

	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return scan
	}

	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return scan
		}
		key, ok := keyToken.(string)
		if !ok {
			return scan
		}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return scan
		}

		switch key {
		case "method":
			scan.methodCount++
			var method string
			if err := json.Unmarshal(value, &method); err == nil && method == MethodToolsCall {
				scan.hasToolsCallMethod = true
			}
		case "id":
			scan.id = value
		}
	}

	return scan
}

func classifyScannedToolsCall(scan clientEnvelopeScan) ClientEnvelope {
	if !scan.hasResponseID() {
		return ClientEnvelope{Kind: EnvelopeToolsCallNotification, Request: Request{Method: MethodToolsCall}}
	}
	return ClientEnvelope{Kind: EnvelopeToolsCallMalformed, Request: Request{
		Method: MethodToolsCall,
		ID:     decodePeekID(scan.id),
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
