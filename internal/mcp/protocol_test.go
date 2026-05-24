package mcp_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func TestDecodeRequest(t *testing.T) {
	payload := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"file_read","arguments":{"path":"/tmp/test"}}}` + "\n"
	p := mcp.NewParser(strings.NewReader(payload), new(bytes.Buffer))

	raw, err := p.ReadRaw()
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}

	req, err := p.DecodeRequest(raw)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if req.Method != "tools/call" {
		t.Errorf("expected tools/call, got %s", req.Method)
	}
	if req.ID == nil {
		t.Error("expected non-nil ID")
	}

	var callReq mcp.ToolsCallRequest
	if err := json.Unmarshal(req.Params, &callReq); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
	if callReq.Name != "file_read" {
		t.Errorf("expected file_read, got %s", callReq.Name)
	}
}

func TestDecodeResponse(t *testing.T) {
	payload := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}` + "\n"
	p := mcp.NewParser(strings.NewReader(payload), new(bytes.Buffer))

	raw, err := p.ReadRaw()
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}

	resp, err := p.DecodeResponse(raw)
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if resp.Error != nil {
		t.Error("expected nil error")
	}

	var result mcp.ToolsCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content")
	}
	if result.Content[0].Text != "hello" {
		t.Errorf("expected hello, got %s", result.Content[0].Text)
	}
}

func TestDecodeErrorResponse(t *testing.T) {
	payload := `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}` + "\n"
	p := mcp.NewParser(strings.NewReader(payload), new(bytes.Buffer))

	raw, err := p.ReadRaw()
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}

	resp, err := p.DecodeResponse(raw)
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != -32600 {
		t.Errorf("expected -32600, got %d", resp.Error.Code)
	}
}

func TestDecodeNotification(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	p := mcp.NewParser(strings.NewReader(payload), new(bytes.Buffer))

	raw, err := p.ReadRaw()
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}

	notif, err := p.DecodeNotification(raw)
	if err != nil {
		t.Fatalf("DecodeNotification: %v", err)
	}
	if notif.Method != "notifications/initialized" {
		t.Errorf("expected notifications/initialized, got %s", notif.Method)
	}
}

func TestEncodeResponse(t *testing.T) {
	buf := new(bytes.Buffer)
	p := mcp.NewParser(new(bytes.Buffer), buf)

	resp := mcp.Response{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      1.0,
		Result:  json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`),
	}

	if err := p.EncodeResponse(resp); err != nil {
		t.Fatalf("EncodeResponse: %v", err)
	}

	output := buf.String()
	if !strings.HasSuffix(output, "\n") {
		t.Error("expected newline terminator")
	}

	decoded := new(bytes.Buffer)
	p2 := mcp.NewParser(strings.NewReader(output), decoded)

	raw, err := p2.ReadRaw()
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	resp2, err := p2.DecodeResponse(raw)
	if err != nil {
		t.Fatalf("decode back: %v", err)
	}
	if resp2.ID != 1.0 {
		t.Errorf("expected ID 1, got %v", resp2.ID)
	}
}

func TestEncodeRequest(t *testing.T) {
	buf := new(bytes.Buffer)
	p := mcp.NewParser(new(bytes.Buffer), buf)

	req := mcp.Request{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      "req-1",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"test"}`),
	}

	if err := p.EncodeRequest(req); err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}

	output := buf.String()
	if !strings.HasSuffix(output, "\n") {
		t.Error("expected newline terminator")
	}
}

func TestParserRejectsNonJSONRPC20(t *testing.T) {
	payload := `{"jsonrpc":"1.0","id":1,"method":"test"}` + "\n"
	p := mcp.NewParser(strings.NewReader(payload), new(bytes.Buffer))

	raw, err := p.ReadRaw()
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}

	_, err = p.DecodeRequest(raw)
	if err == nil {
		t.Error("expected error for non-2.0 jsonrpc version")
	}
}

func TestMultiMessage(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"

	p := mcp.NewParser(strings.NewReader(input), new(bytes.Buffer))

	for i, expectedMethod := range []string{"ping", "tools/list"} {
		raw, err := p.ReadRaw()
		if err != nil {
			t.Fatalf("message %d ReadRaw: %v", i, err)
		}
		req, err := p.DecodeRequest(raw)
		if err != nil {
			t.Fatalf("message %d DecodeRequest: %v", i, err)
		}
		if req.Method != expectedMethod {
			t.Errorf("message %d: expected %s, got %s", i, expectedMethod, req.Method)
		}
	}
}

func TestInitializeRequestRoundTrip(t *testing.T) {
	initReq := mcp.InitializeRequest{
		ProtocolVersion: "2024-11-05",
		Capabilities: mcp.Capabilities{
			Tools: &mcp.ToolsCapability{ListChanged: true},
		},
		ClientInfo: mcp.Implementation{
			Name:    "test-client",
			Version: "1.0.0",
		},
	}

	params, err := json.Marshal(initReq)
	if err != nil {
		t.Fatalf("marshal init: %v", err)
	}

	req := mcp.Request{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      1,
		Method:  mcp.MethodInitialize,
		Params:  params,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	encoded := string(data) + "\n"
	p := mcp.NewParser(strings.NewReader(encoded), new(bytes.Buffer))

	raw, err := p.ReadRaw()
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}

	decoded, err := p.DecodeRequest(raw)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}

	var decodedInit mcp.InitializeRequest
	if err := json.Unmarshal(decoded.Params, &decodedInit); err != nil {
		t.Fatalf("unmarshal init params: %v", err)
	}

	if decodedInit.ProtocolVersion != "2024-11-05" {
		t.Errorf("expected 2024-11-05, got %s", decodedInit.ProtocolVersion)
	}
	if decodedInit.ClientInfo.Name != "test-client" {
		t.Errorf("expected test-client, got %s", decodedInit.ClientInfo.Name)
	}
}
