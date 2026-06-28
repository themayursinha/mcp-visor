package observability

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsHandler(t *testing.T) {
	snap := func() Snapshot {
		return Snapshot{MessagesProcessed: 5, MessagesDenied: 1}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsHandler(snap).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "mcp_visor_messages_processed_total 5") {
		t.Fatalf("body missing counter: %s", body)
	}
}

func TestRuntimeStartMetricsOnly(t *testing.T) {
	rt, err := New(Config{MetricsListenAddr: "127.0.0.1:0"}, func() Snapshot {
		return Snapshot{MessagesAllowed: 3}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rt.Shutdown(t.Context()) }()

	addr := rt.metricsAddr
	if addr == "" {
		t.Fatal("expected bound metrics addr")
	}
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "mcp_visor_messages_allowed_total 3") {
		t.Fatalf("unexpected body: %s", b)
	}
}
