package mcp

import (
	"encoding/json"
	"testing"
)

func TestClassifyClientEnvelopeForwardsNonToolsNotification(t *testing.T) {
	raw := json.RawMessage(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeForward {
		t.Fatalf("kind=%v want forward", got.Kind)
	}
}

func TestClassifyClientEnvelopeForwardsNonToolsBatch(t *testing.T) {
	raw := json.RawMessage(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeForward {
		t.Fatalf("kind=%v want forward for non-tools batch", got.Kind)
	}
}

func TestClassifyClientEnvelopeDeniesBatchContainingToolsCallNotification(t *testing.T) {
	raw := json.RawMessage(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"tools/call","params":{"name":"file_read"}}]` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeToolsCallNotification {
		t.Fatalf("kind=%v want notification deny for batch containing tools/call", got.Kind)
	}
}

func TestClassifyClientEnvelopeDeniesBatchContainingToolsCallRequest(t *testing.T) {
	raw := json.RawMessage(`[{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"file_read"}}]` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeToolsCallMalformed {
		t.Fatalf("kind=%v want malformed deny for batch containing tools/call request", got.Kind)
	}
	if got.Request.ID != float64(7) {
		t.Fatalf("id=%v want 7", got.Request.ID)
	}
}

func TestClassifyClientEnvelopeDeniesBatchWithLeadingWhitespace(t *testing.T) {
	raw := json.RawMessage(` [{"jsonrpc":"2.0","method":"tools/call","params":{"name":"file_read"}}]` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeToolsCallNotification {
		t.Fatalf("kind=%v want notification deny for batch with leading whitespace", got.Kind)
	}
}

func TestClassifyClientEnvelopeDeniesNotificationToolsCall(t *testing.T) {
	raw := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"file_read","arguments":{"path":"/tmp/x"}}}` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeToolsCallNotification {
		t.Fatalf("kind=%v want notification deny", got.Kind)
	}
}

func TestClassifyClientEnvelopeAcceptsValidToolsCallRequest(t *testing.T) {
	raw := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"file_read","arguments":{"path":"/tmp/x"}}}` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeToolsCallRequest {
		t.Fatalf("kind=%v want request", got.Kind)
	}
	if got.Request.Method != MethodToolsCall || got.Request.ID != float64(1) {
		t.Fatalf("unexpected request: %+v", got.Request)
	}
}

func TestClassifyClientEnvelopeMalformedToolsCallWithID(t *testing.T) {
	raw := json.RawMessage(`{"jsonrpc":"1.0","id":2,"method":"tools/call","params":{"name":"file_read"}}` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeToolsCallMalformed {
		t.Fatalf("kind=%v want malformed", got.Kind)
	}
	if got.Request.ID != float64(2) {
		t.Fatalf("id=%v", got.Request.ID)
	}
}

func TestClassifyClientEnvelopeForwardsUnrelatedInvalidJSON(t *testing.T) {
	raw := json.RawMessage(`not-json` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeForward {
		t.Fatalf("kind=%v want forward for unrelated invalid JSON", got.Kind)
	}
}

func TestClassifyClientEnvelopeMalformedToolsCallPeekWithID(t *testing.T) {
	raw := json.RawMessage(`{"jsonrpc":2.0,"id":3,"method":"tools/call"}` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeToolsCallMalformed {
		t.Fatalf("kind=%v want malformed tools/call peek", got.Kind)
	}
	if got.Request.ID != float64(3) {
		t.Fatalf("id=%v", got.Request.ID)
	}
}

func TestClassifyClientEnvelopeDeniesTypedDuplicateNotificationToolsCall(t *testing.T) {
	raw := json.RawMessage(`{"jsonrpc":"2.0","method":123,"method":"tools/call","params":{"name":"file_read","arguments":{"path":"/tmp/x"}}}` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeToolsCallNotification {
		t.Fatalf("kind=%v want notification deny for typed duplicate method", got.Kind)
	}
}

func TestClassifyClientEnvelopeDeniesDuplicateMethodWhenToolsCallAppearsLast(t *testing.T) {
	raw := json.RawMessage(`{"jsonrpc":"2.0","method":"ping","method":"tools/call","params":{"name":"file_read","arguments":{"path":"/tmp/x"}}}` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeToolsCallNotification {
		t.Fatalf("kind=%v want notification deny when duplicate tools/call appears last", got.Kind)
	}
}

func TestClassifyClientEnvelopeDeniesDuplicateMethodWhenToolsCallAppearsLastWithID(t *testing.T) {
	raw := json.RawMessage(`{"jsonrpc":"2.0","method":"ping","method":"tools/call","id":1,"params":{"name":"file_read","arguments":{"path":"/tmp/x"}}}` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeToolsCallMalformed {
		t.Fatalf("kind=%v want malformed deny when duplicate tools/call appears last with id", got.Kind)
	}
}

func TestClassifyClientEnvelopeDeniesDuplicateMethodWhenToolsCallAppearsFirst(t *testing.T) {
	raw := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","method":"ping","params":{"name":"file_read","arguments":{"path":"/tmp/x"}}}` + "\n")
	got := ClassifyClientEnvelope(raw)
	if got.Kind != EnvelopeToolsCallNotification {
		t.Fatalf("kind=%v want notification deny when any duplicate method is tools/call", got.Kind)
	}
}

func TestHasResponseID(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"absent", `{"method":"tools/call"}`, false},
		{"null", `{"method":"tools/call","id":null}`, false},
		{"numeric", `{"method":"tools/call","id":1}`, true},
		{"string", `{"method":"tools/call","id":"abc"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scan := scanClientEnvelope([]byte(tc.raw))
			if got := scan.hasResponseID(); got != tc.want {
				t.Fatalf("hasResponseID=%v want %v", got, tc.want)
			}
		})
	}
}
