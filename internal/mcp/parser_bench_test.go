package mcp_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func toolsCallRequestJSON() []byte {
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      42,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "file_read",
			"arguments": map[string]any{
				"path":    "/home/user/test.txt",
				"mode":    "r",
				"maxSize": 1048576,
			},
		},
	}
	data, _ := json.Marshal(req)
	return data
}

func toolsCallResultJSON() []byte {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      42,
		"result": map[string]any{
			"content": []map[string]any{{
				"type": "text",
				"text": "File contents: Hello, World!",
			}},
			"isError": false,
		},
	}
	data, _ := json.Marshal(resp)
	return data
}

func BenchmarkParserDecodeRequest(b *testing.B) {
	r := bytes.NewReader(nil)
	w := bytes.NewBuffer(nil)
	p := mcp.NewParser(r, w)
	raw := toolsCallRequestJSON()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.DecodeRequest(raw)
	}
}

func BenchmarkParserDecodeResponse(b *testing.B) {
	r := bytes.NewReader(nil)
	w := bytes.NewBuffer(nil)
	p := mcp.NewParser(r, w)
	raw := toolsCallResultJSON()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.DecodeResponse(raw)
	}
}

func BenchmarkParserEncodeResponse(b *testing.B) {
	r := bytes.NewReader(nil)
	w := bytes.NewBuffer(nil)
	p := mcp.NewParser(r, w)
	resp := mcp.Response{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      42,
		Result:  json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		raw, _ := json.Marshal(resp)
		_ = p.Write(raw)
		w.Reset()
	}
}

func BenchmarkParserEncodeErrorResponse(b *testing.B) {
	r := bytes.NewReader(nil)
	w := bytes.NewBuffer(nil)
	p := mcp.NewParser(r, w)
	errResp := mcp.NewErrorResponse(42, mcp.ErrCodeInvalidRequest, "tool not found")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		raw, _ := json.Marshal(errResp)
		_ = p.Write(raw)
		w.Reset()
	}
}

func BenchmarkParserDecodeNotification(b *testing.B) {
	r := bytes.NewReader(nil)
	w := bytes.NewBuffer(nil)
	p := mcp.NewParser(r, w)
	notifJSON, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.DecodeNotification(notifJSON)
	}
}
