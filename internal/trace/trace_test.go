package trace

import (
	"strings"
	"testing"
)

func TestEvent_Summarize(t *testing.T) {
	tests := []struct {
		name     string
		event    Event
		expected string
	}{
		{
			name: "client to server method",
			event: Event{
				Direction: DirClientToServer,
				Method:   "tools/call",
				ID:       1,
			},
			expected: "C->S tools/call(id=1)",
		},
		{
			name: "server to client response",
			event: Event{
				Direction: DirServerToClient,
				Method:   "tools/list",
				ID:       5,
			},
			expected: "S->C tools/list(id=5)",
		},
		{
			name: "error response",
			event: Event{
				Direction: DirServerToClient,
				Error:    "connection refused",
				ID:       2,
			},
			expected: "S->C error(id=2): connection refused",
		},
		{
			name: "notification",
			event: Event{
				Direction: DirClientToServer,
				Method:   "initialized",
			},
			expected: "C->S notification",
		},
		{
			name: "notification with ID",
			event: Event{
				Direction: DirClientToServer,
				Method:    "initialized",
				ID:        42,
			},
			expected: "C->S initialized(id=42)",
		},
		{
			name: "internal event",
			event: Event{
				Direction: DirInternal,
				Method:   "decision",
			},
			expected: "INT decision",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.event.Summarize()
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestTextLogger(t *testing.T) {
	logger := TextLogger{}
	event := &Event{
		Direction: DirClientToServer,
		Method:   "tools/call",
		ID:       1,
		Raw:      `{"jsonrpc":"2.0","method":"tools/call"}`,
	}
	logger.Log(event)
}

func TestJSONLLogger(t *testing.T) {
	logger := JSONLLogger{}
	event := &Event{
		Direction: DirClientToServer,
		Method:    "tools/call_batch",
		ID:        10,
	}
	logger.Log(event)
}

func TestSummaryLogger(t *testing.T) {
	logger := NewSummaryLogger()

	logger.Log(&Event{Direction: DirClientToServer, Method: "tools/call", ID: 1})
	logger.Log(&Event{Direction: DirClientToServer, Method: "tools/call", ID: 2})
	logger.Log(&Event{Direction: DirClientToServer, Method: "tools/list", ID: 3})
	logger.Log(&Event{Direction: DirServerToClient, Method: "tools/call", ID: 1})
	logger.Log(&Event{Direction: DirServerToClient, Method: "tools/call", ID: 2})
	logger.Log(&Event{Direction: DirServerToClient, Error: "server error", ID: nil})
	logger.Log(&Event{Direction: DirInternal, Method: "policy_deny"})

	report := logger.Report()

	if !strings.Contains(report, "messages: 7") {
		t.Errorf("expected 'messages: 7', got: %s", report)
	}
	if !strings.Contains(report, "errors: 1") {
		t.Errorf("expected 'errors: 1', got: %s", report)
	}
	if !strings.Contains(report, "C->S: 3") {
		t.Errorf("expected 'C->S: 3', got: %s", report)
	}
	if !strings.Contains(report, "S->C: 3") {
		t.Errorf("expected 'S->C: 3', got: %s", report)
	}
	if !strings.Contains(report, "tools/call: 4") {
		t.Errorf("expected 'tools/call: 4', got: %s", report)
	}
}

func TestSummaryLogger_Empty(t *testing.T) {
	logger := NewSummaryLogger()
	report := logger.Report()
	if !strings.Contains(report, "messages: 0") {
		t.Errorf("expected 'messages: 0', got: %s", report)
	}
}

func TestHexDumper(t *testing.T) {
	dumper := HexDumper{}
	data := []byte("Hello, World! This is a test of the hex dumper.\n")
	output := dumper.Dump(data)
	if !strings.Contains(output, "0000:") {
		t.Errorf("expected hex output to start with offset")
	}
	if !strings.Contains(output, "Hello") {
		t.Errorf("expected hex output to contain ASCII representation")
	}
}

func TestHexDumper_Empty(t *testing.T) {
	dumper := HexDumper{}
	output := dumper.Dump([]byte{})
	if output != "" {
		t.Errorf("expected empty output, got: %s", output)
	}
}

func TestHexDumper_SpecialChars(t *testing.T) {
	dumper := HexDumper{}
	data := []byte{0x00, 0x01, 0x02, 0x7F, 0xFF, 0x80}
	output := dumper.Dump(data)
	if !strings.Contains(output, "....") {
		t.Errorf("expected non-printable chars to be replaced with dots, got: %s", output)
	}
}

func TestLogEvent(t *testing.T) {
	logger := NewSummaryLogger()
	LogEvent(logger, DirClientToServer, "tools/call", "2.0", 42, []byte(`{"test":true}`), nil)
	LogEvent(logger, DirServerToClient, "", "2.0", 42, nil, nil)

	report := logger.Report()
	if !strings.Contains(report, "messages: 2") {
		t.Errorf("expected 2 messages: %s", report)
	}
}
