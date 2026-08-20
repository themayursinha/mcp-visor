package audit_test

import (
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
)

func TestVerifyEventHashRejectsPayloadMutation(t *testing.T) {
	t.Parallel()
	event := audit.Event{
		Timestamp:  "2026-01-01T00:00:00Z",
		EventType:  audit.EventToolDenied,
		SessionID:  "proof",
		Server:     "mock",
		Tool:       "http_post",
		Decision:   "deny",
		PolicyRule: "block_sensitive_egress",
		PrevHash:   "abc",
		ChainIndex: 4,
	}
	hash, err := audit.RecordHash(event)
	if err != nil {
		t.Fatalf("RecordHash: %v", err)
	}
	event.Hash = hash
	if err := audit.VerifyEventHash(event); err != nil {
		t.Fatalf("canonical event must verify: %v", err)
	}

	mutated := event
	mutated.Tool = "slack_send_message"
	if err := audit.VerifyEventHash(mutated); err == nil {
		t.Fatal("payload mutation with unchanged stored hash must fail verification")
	}

	missing := event
	missing.Hash = ""
	if err := audit.VerifyEventHash(missing); err == nil {
		t.Fatal("missing hash must fail verification")
	}

	wrong := event
	wrong.Hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := audit.VerifyEventHash(wrong); err == nil {
		t.Fatal("arbitrary hash must fail verification")
	}
}
