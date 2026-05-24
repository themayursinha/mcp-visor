package proxy_test

import (
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/proxy"
)

func TestSessionRecordToolCall(t *testing.T) {
	s := proxy.NewSession("sess-1", "client-1")

	callReq := mcp.ToolsCallRequest{
		Name:      "file_read",
		Arguments: []byte(`{"path":"/tmp/test"}`),
	}
	s.RecordToolCall("filesystem", callReq, "")

	if s.ToolCallCount() != 1 {
		t.Errorf("expected 1 call, got %d", s.ToolCallCount())
	}

	calls := s.RecentCalls(10)
	if len(calls) != 1 {
		t.Fatalf("expected 1 recent call, got %d", len(calls))
	}
	if calls[0].ToolName != "file_read" {
		t.Errorf("expected file_read, got %s", calls[0].ToolName)
	}
	if calls[0].ServerName != "filesystem" {
		t.Errorf("expected filesystem, got %s", calls[0].ServerName)
	}
}

func TestSessionMultipleCalls(t *testing.T) {
	s := proxy.NewSession("sess-2", "client-2")

	for i, name := range []string{"file_read", "database_query", "http_post", "slack_send"} {
		s.RecordToolCall("server-1", mcp.ToolsCallRequest{Name: name, Arguments: []byte(`{}`)}, "")
		if s.ToolCallCount() != i+1 {
			t.Errorf("expected %d calls, got %d", i+1, s.ToolCallCount())
		}
	}

	calls := s.RecentCalls(2)
	if len(calls) != 2 {
		t.Fatalf("expected 2 recent calls, got %d", len(calls))
	}
	if calls[0].ToolName != "http_post" {
		t.Errorf("expected http_post, got %s", calls[0].ToolName)
	}
	if calls[1].ToolName != "slack_send" {
		t.Errorf("expected slack_send, got %s", calls[1].ToolName)
	}
}

func TestRecentCallsEmpty(t *testing.T) {
	s := proxy.NewSession("sess-3", "client-3")

	calls := s.RecentCalls(10)
	if len(calls) != 0 {
		t.Errorf("expected 0 calls, got %d", len(calls))
	}
}

func TestRecentCallsMoreThanAvailable(t *testing.T) {
	s := proxy.NewSession("sess-4", "client-4")

	s.RecordToolCall("srv", mcp.ToolsCallRequest{Name: "tool1", Arguments: []byte(`{}`)}, "")
	s.RecordToolCall("srv", mcp.ToolsCallRequest{Name: "tool2", Arguments: []byte(`{}`)}, "")

	calls := s.RecentCalls(10)
	if len(calls) != 2 {
		t.Errorf("expected 2 calls, got %d", len(calls))
	}
}

func TestSessionConcurrency(t *testing.T) {
	s := proxy.NewSession("sess-5", "client-5")
	done := make(chan struct{})

	go func() {
		for i := 0; i < 100; i++ {
			s.RecordToolCall("srv", mcp.ToolsCallRequest{Name: "tool_a", Arguments: []byte(`{}`)}, "")
		}
		done <- struct{}{}
	}()

	go func() {
		for i := 0; i < 100; i++ {
			s.RecordToolCall("srv", mcp.ToolsCallRequest{Name: "tool_b", Arguments: []byte(`{}`)}, "")
		}
		done <- struct{}{}
	}()

	<-done
	<-done

	if s.ToolCallCount() != 200 {
		t.Errorf("expected 200 calls, got %d", s.ToolCallCount())
	}
}

func TestNewProxyWithDefaults(t *testing.T) {
	p := proxy.New(proxy.Config{
		ServerCommand: "echo",
		ServerArgs:    []string{"test"},
	})

	s := p.Session()
	if s == nil {
		t.Fatal("expected non-nil session")
	}
	if s.ID == "" {
		t.Error("expected non-empty session ID")
	}
	if s.ClientID == "" {
		t.Error("expected non-empty client ID")
	}
}

func TestGenerateSessionID(t *testing.T) {
	id1 := proxy.GenerateSessionID()
	id2 := proxy.GenerateSessionID()

	if id1 == "" {
		t.Error("expected non-empty session ID")
	}
	if id1 == id2 {
		t.Error("expected different session IDs")
	}
}
