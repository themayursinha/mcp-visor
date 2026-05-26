package dashboard_test

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/dashboard"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

type stubProvider struct{}

func (s *stubProvider) SessionCount() int                             { return 3 }
func (s *stubProvider) ToolCallCount() int                             { return 42 }
func (s *stubProvider) Uptime() time.Duration                          { return 5 * time.Minute }
func (s *stubProvider) RecentCalls(n int) []dashboard.CallInfo {
	return []dashboard.CallInfo{
		{
			Timestamp:  time.Now(),
			ServerName: "filesystem",
			ToolName:   "file_read",
			Arguments:  map[string]any{"path": "/tmp/test"},
			Result:     "ok",
			Risk:       "medium",
		},
	}
}
func (s *stubProvider) Metrics() dashboard.MetricsSnapshot {
	return dashboard.MetricsSnapshot{
		MessagesProcessed: 100,
		MessagesDenied:    10,
		MessagesAllowed:   85,
		MessagesApproved:  5,
		BytesRedacted:     4096,
		ApprovalRequests:  15,
		ChainDetections:   3,
	}
}
func (s *stubProvider) Policy() *policy.Policy {
	return &policy.Policy{
		Version:        "1.0",
		Description:    "test policy",
		DefaultAction:  policy.ActionDeny,
		Servers:        []policy.Server{{Name: "srv1", Allowed: true}},
		ToolChains:     []policy.ChainRule{{Name: "exfil"}},
		Identities:     []policy.Identity{{Name: "agent-1"}},
		Redaction:      policy.RedactionConfig{OutputRedaction: true, Patterns: []policy.RedactionPattern{{Name: "test"}}},
	}
}

func TestDashboardAPIStatus(t *testing.T) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := listener.Addr().String()
	listener.Close()

	srv := dashboard.NewServer(addr, &stubProvider{})

	go srv.Start()
	time.Sleep(50 * time.Millisecond)
	defer srv.Stop()

	resp, err := http.Get("http://" + addr + "/api/status")
	if err != nil {
		t.Fatalf("GET /api/status: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)

	if data["session_count"] != float64(3) {
		t.Errorf("expected 3 sessions, got %v", data["session_count"])
	}
}

func TestDashboardAPIMetrics(t *testing.T) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := listener.Addr().String()
	listener.Close()

	srv := dashboard.NewServer(addr, &stubProvider{})

	go srv.Start()
	time.Sleep(50 * time.Millisecond)
	defer srv.Stop()

	resp, err := http.Get("http://" + addr + "/api/metrics")
	if err != nil {
		t.Fatalf("GET /api/metrics: %v", err)
	}
	defer resp.Body.Close()

	var m dashboard.MetricsSnapshot
	json.NewDecoder(resp.Body).Decode(&m)

	if m.MessagesProcessed != 100 {
		t.Errorf("expected 100 processed, got %d", m.MessagesProcessed)
	}
	if m.MessagesDenied != 10 {
		t.Errorf("expected 10 denied, got %d", m.MessagesDenied)
	}
}

func TestDashboardAPICalls(t *testing.T) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := listener.Addr().String()
	listener.Close()

	srv := dashboard.NewServer(addr, &stubProvider{})

	go srv.Start()
	time.Sleep(50 * time.Millisecond)
	defer srv.Stop()

	resp, err := http.Get("http://" + addr + "/api/calls")
	if err != nil {
		t.Fatalf("GET /api/calls: %v", err)
	}
	defer resp.Body.Close()

	var data struct {
		Calls []dashboard.CallInfo `json:"calls"`
	}
	json.NewDecoder(resp.Body).Decode(&data)

	if len(data.Calls) != 1 {
		t.Errorf("expected 1 call, got %d", len(data.Calls))
	}
}

func TestDashboardAPIPolicy(t *testing.T) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := listener.Addr().String()
	listener.Close()

	srv := dashboard.NewServer(addr, &stubProvider{})

	go srv.Start()
	time.Sleep(50 * time.Millisecond)
	defer srv.Stop()

	resp, err := http.Get("http://" + addr + "/api/policy")
	if err != nil {
		t.Fatalf("GET /api/policy: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)

	if data["version"] != "1.0" {
		t.Errorf("expected version 1.0, got %v", data["version"])
	}
}

func TestDashboardHTML(t *testing.T) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := listener.Addr().String()
	listener.Close()

	srv := dashboard.NewServer(addr, &stubProvider{})

	go srv.Start()
	time.Sleep(50 * time.Millisecond)
	defer srv.Stop()

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("expected text/html, got %s", resp.Header.Get("Content-Type"))
	}
}
