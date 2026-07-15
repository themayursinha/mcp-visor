package proxy

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func encodeResponseVia(client *mcp.Parser) toolsCallResponder {
	return func(id any, message string) {
		_ = client.EncodeResponse(mcp.NewErrorResponse(id, -32000, message))
	}
}

func TestInterceptDeniesNotificationToolsCallStdio(t *testing.T) {
	p := New(Config{
		ServerName: "demo",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "demo"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
`),
	})
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	respond := encodeResponseVia(client)

	raw := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"file_read","arguments":{"path":"/tmp/x"}}}` + "\n")
	modified, action := p.interceptClientToServerEnvelope(raw, "demo", respond)

	if action != "denied" {
		t.Fatalf("action=%q want denied", action)
	}
	if !bytes.Equal(modified, raw) {
		t.Fatalf("expected unmodified raw on drop")
	}
	if out.Len() != 0 {
		t.Fatalf("notification must not get JSON-RPC response, got %q", out.String())
	}
	if p.metrics.MessagesDenied != 1 {
		t.Fatalf("denied metric=%d want 1", p.metrics.MessagesDenied)
	}
}

func TestInterceptForwardsInitializedNotificationStdio(t *testing.T) {
	p := New(Config{ServerName: "demo", Policy: mustLoadPolicy(t, `version: "1.0"
default_action: deny`)})
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	respond := encodeResponseVia(client)

	raw := json.RawMessage(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	_, action := p.interceptClientToServerEnvelope(raw, "demo", respond)
	if action != "forward" {
		t.Fatalf("action=%q want forward", action)
	}
}

func TestInterceptDeniesNotificationToolsCallRemoteParity(t *testing.T) {
	p := New(Config{
		ServerName: "demo",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "demo"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
`),
	})
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	raw := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"file_read","arguments":{"path":"/tmp/x"}}}` + "\n")
	_, action := p.interceptAndModifyRemote(raw, client)

	if action != "denied" {
		t.Fatalf("remote parity action=%q want denied", action)
	}
	if out.Len() != 0 {
		t.Fatalf("must not respond to notification tools/call")
	}
}

func TestInterceptForwardsInitializedNotificationRemote(t *testing.T) {
	p := New(Config{
		ServerName: "demo",
		ServerURL:  "https://example.invalid/mcp",
		Policy: mustLoadPolicy(t, `version: "1.0"
default_action: deny`),
	})
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	raw := json.RawMessage(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	modified, action := p.interceptAndModifyRemote(raw, client)
	if action != "forward" {
		t.Fatalf("action=%q want forward", action)
	}
	if !bytes.Equal(modified, raw) {
		t.Fatalf("expected notification forwarded unchanged")
	}
}

func TestInterceptMalformedToolsCallWithIDReturnsErrorStdio(t *testing.T) {
	p := New(Config{ServerName: "demo", Policy: mustLoadPolicy(t, `version: "1.0"
default_action: deny`)})
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	respond := encodeResponseVia(client)

	raw := json.RawMessage(`{"jsonrpc":"1.0","id":4,"method":"tools/call","params":{"name":"file_read"}}` + "\n")
	_, action := p.interceptClientToServerEnvelope(raw, "demo", respond)
	if action != "denied" {
		t.Fatalf("action=%q want denied", action)
	}
	if !strings.Contains(out.String(), "invalid tools/call request") {
		t.Fatalf("expected error response, got %q", out.String())
	}
}

func TestInterceptMalformedToolsCallWithIDRemoteResponseIsLineDelimited(t *testing.T) {
	p := New(Config{
		ServerName: "demo",
		ServerURL:  "https://example.invalid/mcp",
		Policy: mustLoadPolicy(t, `version: "1.0"
default_action: deny`),
	})
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)

	raw := json.RawMessage(`{"jsonrpc":"1.0","id":4,"method":"tools/call","params":{"name":"file_read"}}` + "\n")
	_, action := p.interceptAndModifyRemote(raw, client)
	if action != "denied" {
		t.Fatalf("action=%q want denied", action)
	}
	if !bytes.HasSuffix(out.Bytes(), []byte("\n")) {
		t.Fatalf("remote error response must be newline-delimited, got %q", out.String())
	}
}

func TestInterceptMalformedToolsCallParamsUsesExistingPath(t *testing.T) {
	p := New(Config{ServerName: "demo", Policy: mustLoadPolicy(t, `version: "1.0"
default_action: deny`)})
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	respond := encodeResponseVia(client)

	raw := json.RawMessage(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":"not-an-object"}` + "\n")
	_, action := p.interceptClientToServerEnvelope(raw, "demo", respond)
	if action != "denied" {
		t.Fatalf("action=%q want denied", action)
	}
	if !strings.Contains(out.String(), "invalid tools/call parameters") {
		t.Fatalf("expected params error, got %q", out.String())
	}
}

func TestInterceptDeniesBatchContainingToolsCall(t *testing.T) {
	p := New(Config{
		ServerName: "demo",
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "demo"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
`),
	})
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	respond := encodeResponseVia(client)

	notifBatch := json.RawMessage(`[{"jsonrpc":"2.0","method":"tools/call","params":{"name":"file_read"}}]` + "\n")
	_, action := p.interceptClientToServerEnvelope(notifBatch, "demo", respond)
	if action != "denied" {
		t.Fatalf("notification batch action=%q want denied", action)
	}
	if out.Len() != 0 {
		t.Fatalf("notification batch must not get response, got %q", out.String())
	}

	requestBatch := json.RawMessage(`[{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"file_read"}}]` + "\n")
	_, action = p.interceptClientToServerEnvelope(requestBatch, "demo", respond)
	if action != "denied" {
		t.Fatalf("request batch action=%q want denied", action)
	}
	if !strings.Contains(out.String(), "invalid tools/call request") {
		t.Fatalf("request batch expected error response, got %q", out.String())
	}
}

func TestDenyNotificationToolsCallDoesNotLeakArgumentsInAudit(t *testing.T) {
	auditPath := t.TempDir() + "/audit.jsonl"
	p := New(Config{
		ServerName:   "demo",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "demo"
    allowed: true
`),
	})
	client := mcp.NewParser(nil, &bytes.Buffer{})
	respond := encodeResponseVia(client)
	raw := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"file_read","arguments":{"path":"/secret/path"}}}` + "\n")
	_, _ = p.interceptClientToServerEnvelope(raw, "demo", respond)

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	body := string(data)
	if strings.Contains(body, "/secret/path") {
		t.Fatalf("audit leaked arguments: %s", body)
	}
	if !strings.Contains(body, "notification-form tools/call blocked") {
		t.Fatalf("expected denial reason in audit, got %s", body)
	}
}
