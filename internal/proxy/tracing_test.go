package proxy

import (
	"testing"

	"github.com/themayursinha/mcp-visor/internal/trace"
)

func TestProxyMetrics(t *testing.T) {
	m := &ProxyMetrics{}

	m.IncrementProcessed()
	m.IncrementDenied()
	m.IncrementAllowed()
	m.IncrementApproved()
	m.AddBytesRedacted(1024)
	m.IncrementApprovals()
	m.IncrementChains()

	if m.MessagesProcessed != 1 {
		t.Errorf("expected 1 processed, got %d", m.MessagesProcessed)
	}
	if m.MessagesDenied != 1 {
		t.Errorf("expected 1 denied, got %d", m.MessagesDenied)
	}
	if m.MessagesAllowed != 1 {
		t.Errorf("expected 1 allowed, got %d", m.MessagesAllowed)
	}
	if m.MessagesApproved != 1 {
		t.Errorf("expected 1 approved, got %d", m.MessagesApproved)
	}
	if m.BytesRedacted != 1024 {
		t.Errorf("expected 1024 bytes redacted, got %d", m.BytesRedacted)
	}
	if m.ApprovalRequests != 1 {
		t.Errorf("expected 1 approval request, got %d", m.ApprovalRequests)
	}
	if m.ChainDetections != 1 {
		t.Errorf("expected 1 chain detection, got %d", m.ChainDetections)
	}
}

func TestTracingConfig(t *testing.T) {
	cfg := TracingConfig{
		Enabled:       true,
		Format:        TraceFormatJSONL,
		LogDecisions:  true,
		LogRedactions: true,
		LogChains:     true,
		LogHandshake:  true,
	}

	if cfg.Format != TraceFormatJSONL {
		t.Errorf("expected format to be jsonl, got %s", cfg.Format)
	}
}

func TestTraceFormatConstants(t *testing.T) {
	if TraceFormatText != "text" {
		t.Errorf("expected text, got %s", TraceFormatText)
	}
	if TraceFormatJSONL != "jsonl" {
		t.Errorf("expected jsonl, got %s", TraceFormatJSONL)
	}
	if TraceFormatSummary != "summary" {
		t.Errorf("expected summary, got %s", TraceFormatSummary)
	}
}

func TestNewWithTracing(t *testing.T) {
	cfg := Config{
		ServerCommand: "echo",
		Tracing: TracingConfig{
			Enabled: true,
			Format:  TraceFormatText,
		},
	}
	p := NewWithTracing(cfg)
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	if p.tracer == nil {
		t.Error("expected non-nil tracer when tracing is enabled")
	}
	if p.Tracer() == nil {
		t.Error("Tracer() should return non-nil")
	}
}

func TestNewWithTracingDisabled(t *testing.T) {
	cfg := Config{
		ServerCommand: "echo",
		Tracing: TracingConfig{
			Enabled: false,
		},
	}
	p := NewWithTracing(cfg)
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	if p.tracer != nil {
		t.Error("expected nil tracer when tracing is disabled")
	}
}

func TestNewWithTracingSummary(t *testing.T) {
	cfg := Config{
		ServerCommand: "echo",
		Tracing: TracingConfig{
			Enabled: true,
			Format:  TraceFormatSummary,
		},
	}
	p := NewWithTracing(cfg)
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	if p.tracer == nil {
		t.Error("expected non-nil tracer for summary format")
	}
	var ok bool
	_, ok = p.tracer.(*trace.SummaryLogger)
	if !ok {
		t.Error("expected summary logger type")
	}
}

func TestProxyMetrics_Multiple(t *testing.T) {
	m := &ProxyMetrics{}

	for i := 0; i < 100; i++ {
		m.IncrementProcessed()
	}
	for i := 0; i < 10; i++ {
		m.IncrementDenied()
	}
	for i := 0; i < 80; i++ {
		m.IncrementAllowed()
	}
	for i := 0; i < 5; i++ {
		m.IncrementApproved()
	}

	if m.MessagesProcessed != 100 {
		t.Errorf("expected 100 processed, got %d", m.MessagesProcessed)
	}
	if m.MessagesDenied != 10 {
		t.Errorf("expected 10 denied, got %d", m.MessagesDenied)
	}
	if m.MessagesAllowed != 80 {
		t.Errorf("expected 80 allowed, got %d", m.MessagesAllowed)
	}
	if m.MessagesApproved != 5 {
		t.Errorf("expected 5 approved, got %d", m.MessagesApproved)
	}
}

func TestProxyMetrics_AllZeros(t *testing.T) {
	m := &ProxyMetrics{}

	if m.MessagesProcessed != 0 {
		t.Errorf("expected 0, got %d", m.MessagesProcessed)
	}
	if m.MessagesDenied != 0 {
		t.Errorf("expected 0, got %d", m.MessagesDenied)
	}
}
