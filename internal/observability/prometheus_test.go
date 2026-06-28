package observability

import (
	"strings"
	"testing"
)

func TestWritePrometheus(t *testing.T) {
	var b strings.Builder
	WritePrometheus(&b, Snapshot{
		MessagesProcessed: 10,
		MessagesDenied:    2,
		MessagesAllowed:   7,
		MessagesApproved:  1,
		BytesRedacted:     99,
		ApprovalRequests:  3,
		ChainDetections:   1,
	})
	out := b.String()
	for _, want := range []string{
		"mcp_visor_messages_processed_total 10",
		"mcp_visor_messages_denied_total 2",
		"mcp_visor_messages_allowed_total 7",
		"mcp_visor_messages_approved_total 1",
		"# TYPE mcp_visor_bytes_redacted_total counter",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestConfigEnabled(t *testing.T) {
	if (Config{}).Enabled() {
		t.Fatal("empty config should not be enabled")
	}
	metricsCfg := Config{MetricsListenAddr: "127.0.0.1:9091"}
	if !metricsCfg.Enabled() {
		t.Fatal("metrics addr should enable")
	}
	otelCfg := Config{OTLPEndpoint: "localhost:4317"}
	if !otelCfg.Enabled() {
		t.Fatal("otlp should enable")
	}
}
