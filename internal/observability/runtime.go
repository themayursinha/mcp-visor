// Package observability exports mcp-visor proxy metrics for Prometheus scrape
// and optional OpenTelemetry (OTLP) traces and metrics.
package observability

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config controls optional Prometheus and OTLP export (all off by default).
type Config struct {
	MetricsListenAddr string  // e.g. 127.0.0.1:9091; empty disables /metrics server
	OTLPEndpoint      string  // e.g. localhost:4317; empty disables OTLP
	OTLPInsecure      bool    // skip TLS for OTLP gRPC (typical for local LGTM)
	ServiceName       string  // OTel service.name
	TraceSampleRatio  float64 // 0..1, default 1 when OTLP enabled
}

func (c Config) Enabled() bool {
	return c.MetricsListenAddr != "" || c.OTLPEndpoint != ""
}

func (c Config) normalized() Config {
	out := c
	if out.ServiceName == "" {
		out.ServiceName = "mcp-visor"
	}
	if out.OTLPEndpoint != "" && out.TraceSampleRatio <= 0 {
		out.TraceSampleRatio = 1
	}
	if out.TraceSampleRatio > 1 {
		out.TraceSampleRatio = 1
	}
	return out
}

// Snapshot is a point-in-time copy of proxy counters.
type Snapshot struct {
	MessagesProcessed int64
	MessagesDenied    int64
	MessagesAllowed   int64
	MessagesApproved  int64
	BytesRedacted     int64
	ApprovalRequests  int64
	ChainDetections   int64
}

// MetricsProvider returns current proxy metrics (called on Prometheus scrape).
type MetricsProvider func() Snapshot

// ToolCallEvent describes one tools/call policy outcome (no argument payloads).
type ToolCallEvent struct {
	SessionID      string
	ServerName     string
	ToolName       string
	Decision       string // denied, allowed, approved
	Reason         string
	Risk           string
	ChainTriggered bool
	Duration       time.Duration
}

// Runtime hosts Prometheus scrape and optional OTLP export.
type Runtime struct {
	cfg     Config
	metrics MetricsProvider

	httpServer  *http.Server
	metricsAddr string // actual listen address (after :0 bind)
	otel        *otelPipeline
	mu          sync.Mutex
}

// New builds a runtime; call Start before serving traffic.
func New(cfg Config, metrics MetricsProvider) (*Runtime, error) {
	cfg = cfg.normalized()
	if !cfg.Enabled() {
		return nil, fmt.Errorf("observability: at least one of metrics listen addr or OTLP endpoint is required")
	}
	if metrics == nil {
		return nil, fmt.Errorf("observability: metrics provider is required")
	}

	r := &Runtime{cfg: cfg, metrics: metrics}
	if cfg.OTLPEndpoint != "" {
		otel, err := newOTelPipeline(cfg)
		if err != nil {
			return nil, err
		}
		r.otel = otel
	}
	return r, nil
}

// Start listens for Prometheus scrape when configured.
func (r *Runtime) Start() error {
	if r.cfg.MetricsListenAddr == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("/metrics", metricsHandler(r.metrics))

	ln, err := net.Listen("tcp", r.cfg.MetricsListenAddr)
	if err != nil {
		return fmt.Errorf("metrics listen %s: %w", r.cfg.MetricsListenAddr, err)
	}
	r.metricsAddr = ln.Addr().String()

	r.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = r.httpServer.Serve(ln)
	}()
	return nil
}

func metricsHandler(provider MetricsProvider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WritePrometheus(w, provider())
	})
}

// Shutdown stops HTTP and flushes OTLP exporters (best-effort).
func (r *Runtime) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var errs []string
	if r.httpServer != nil {
		if err := r.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, err.Error())
		}
		r.httpServer = nil
	}
	if r.otel != nil {
		if err := r.otel.shutdown(ctx); err != nil {
			errs = append(errs, err.Error())
		}
		r.otel = nil
	}
	if len(errs) > 0 {
		return fmt.Errorf("observability shutdown: %s", strings.Join(errs, "; "))
	}
	return nil
}

// RecordToolCall emits an OTel span and counters when OTLP is enabled.
// Never blocks the proxy hot path on export failures.
func (r *Runtime) RecordToolCall(ctx context.Context, ev ToolCallEvent) {
	if r == nil || r.otel == nil {
		return
	}
	r.otel.recordToolCall(ctx, ev)
}
