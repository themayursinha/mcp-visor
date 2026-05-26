package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
)

func TestEmitterDelivery(t *testing.T) {
	received := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", r.Header.Get("Content-Type"))
		}
		var buf []byte
		r.Body.Read(buf)
		received <- buf
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.URLs = []string{server.URL}

	e := NewEmitter(cfg)
	defer e.Close()

	event := audit.Event{
		Timestamp: "2026-05-26T10:00:00Z",
		EventType: audit.EventToolAllowed,
		SessionID: "sess-001",
		AgentID:   "agent-001",
		Server:    "filesystem",
		Tool:      "file_read",
		Decision:  "allow",
		Reason:    "allowed by policy",
		RiskLevel: "medium",
	}

	err := e.EmitDirect(event)
	if err != nil {
		t.Fatalf("EmitDirect: %v", err)
	}
}

func TestEmitterAsyncEvent(t *testing.T) {
	received := make(chan EventPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload EventPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.URLs = []string{server.URL}

	e := NewEmitter(cfg)
	defer e.Close()

	event := audit.Event{
		Timestamp: "2026-05-26T10:00:00Z",
		EventType: audit.EventToolDenied,
		SessionID: "sess-002",
		AgentID:   "agent-002",
		Server:    "shell",
		Tool:      "shell_exec",
		Decision:  "deny",
		Reason:    "dangerous command",
		RiskLevel: "critical",
	}

	e.Emit(event)
	time.Sleep(100 * time.Millisecond)

	select {
	case payload := <-received:
		if payload.SessionID != "sess-002" {
			t.Errorf("session ID: got %s", payload.SessionID)
		}
		if payload.Decision != "deny" {
			t.Errorf("decision: got %s", payload.Decision)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for webhook delivery")
	}
}

func TestEmitterHMACSignature(t *testing.T) {
	var receivedSig string
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-MCP-Visor-Signature")
		receivedBody = make([]byte, r.ContentLength)
		r.Body.Read(receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	secret := "test-hmac-secret"
	cfg := Config{
		URLs:           []string{server.URL},
		HMACSecret:     secret,
		RequestTimeout: 5 * time.Second,
		BufferSize:     16,
	}

	e := NewEmitter(cfg)
	defer e.Close()

	event := audit.Event{
		Timestamp: "2026-05-26T10:00:00Z",
		EventType: audit.EventToolApprovalRequired,
		SessionID: "sess-003",
		AgentID:   "agent-003",
		Server:    "slack",
		Tool:      "slack_send_message",
		Decision:  "require_approval",
		Reason:    "needs human approval",
		RiskLevel: "high",
	}

	e.EmitDirect(event)

	if receivedSig == "" {
		t.Error("X-MCP-Visor-Signature header missing")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(receivedBody)
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(receivedSig), []byte(expected)) {
		t.Errorf("HMAC signature mismatch: got %s, expected %s", receivedSig, expected)
	}
}

func TestEmitterRetryOnFailure(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.URLs = []string{server.URL}

	e := NewEmitter(cfg)
	defer e.Close()

	event := audit.Event{
		Timestamp: "2026-05-26T10:00:00Z",
		EventType: audit.EventSessionStarted,
		SessionID: "sess-004",
		Decision:  "allow",
	}

	err := e.EmitDirect(event)
	if err != nil {
		t.Fatalf("EmitDirect: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestEmitterEmptyConfig(t *testing.T) {
	e := NewEmitter(Config{})
	defer e.Close()

	if e == nil {
		t.Fatal("emitter should not be nil for empty config")
	}

	event := audit.Event{EventType: audit.EventSessionStarted}
	err := e.EmitDirect(event)
	if err != nil {
		t.Fatalf("EmitDirect with no URLs: expected nil, got %v", err)
	}
}

func TestEmitterEventChanFull(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BufferSize = 2

	e := NewEmitter(cfg)
	defer e.Close()

	e.eventCh <- EventPayload{}
	e.eventCh <- EventPayload{}

	event := audit.Event{EventType: audit.EventSessionStarted}
	e.Emit(event)
}

func TestEmitterApproveRequiredEvent(t *testing.T) {
	received := make(chan EventPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload EventPayload
		json.NewDecoder(r.Body).Decode(&payload)
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.URLs = []string{server.URL}

	e := NewEmitter(cfg)
	defer e.Close()

	event := audit.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EventType: audit.EventToolApprovalRequired,
		SessionID: "sess-approval-test",
		AgentID:   "copilot-agent",
		Server:    "cloud",
		Tool:      "aws_iam_create_user",
		Decision:  "require_approval",
		Reason:    "critical cloud IAM operation requires human approval",
		RiskLevel: "critical",
		Message:   fmt.Sprintf("approval-id: %s", "appr-12345"),
	}

	e.Emit(event)
	time.Sleep(100 * time.Millisecond)

	select {
	case payload := <-received:
		if payload.EventType != string(audit.EventToolApprovalRequired) {
			t.Errorf("event type: got %s", payload.EventType)
		}
		if payload.Tool != "aws_iam_create_user" {
			t.Errorf("tool: got %s", payload.Tool)
		}
		if payload.RiskLevel != "critical" {
			t.Errorf("risk level: got %s", payload.RiskLevel)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for webhook")
	}
}
