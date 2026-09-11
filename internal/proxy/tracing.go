package proxy

import "sync/atomic"

type TracingConfig struct {
	Enabled       bool
	OutputFile    string
	Format        TraceFormat
	MaxRawLen     int
	LogDecisions  bool
	LogRedactions bool
	LogChains     bool
	LogHandshake  bool
}

type TraceFormat string

const (
	TraceFormatText    TraceFormat = "text"
	TraceFormatJSONL   TraceFormat = "jsonl"
	TraceFormatSummary TraceFormat = "summary"
)

type ProxyMetrics struct {
	MessagesProcessed int64
	MessagesDenied    int64
	MessagesAllowed   int64
	MessagesApproved  int64
	BytesRedacted     int64
	ApprovalRequests  int64
	ChainDetections   int64
}

// Counters use atomic ops: concurrent calls share one ProxyMetrics, and
// the delegation-ceiling tests prove concurrent authorization stays exact.
func (m *ProxyMetrics) IncrementProcessed()      { atomic.AddInt64(&m.MessagesProcessed, 1) }
func (m *ProxyMetrics) IncrementDenied()         { atomic.AddInt64(&m.MessagesDenied, 1) }
func (m *ProxyMetrics) IncrementAllowed()        { atomic.AddInt64(&m.MessagesAllowed, 1) }
func (m *ProxyMetrics) IncrementApproved()       { atomic.AddInt64(&m.MessagesApproved, 1) }
func (m *ProxyMetrics) AddBytesRedacted(n int64) { atomic.AddInt64(&m.BytesRedacted, n) }
func (m *ProxyMetrics) IncrementApprovals()      { atomic.AddInt64(&m.ApprovalRequests, 1) }
func (m *ProxyMetrics) IncrementChains()         { atomic.AddInt64(&m.ChainDetections, 1) }

// Load returns a point-in-time copy safe to read from any goroutine.
func (m *ProxyMetrics) Load() ProxyMetrics {
	return ProxyMetrics{
		MessagesProcessed: atomic.LoadInt64(&m.MessagesProcessed),
		MessagesDenied:    atomic.LoadInt64(&m.MessagesDenied),
		MessagesAllowed:   atomic.LoadInt64(&m.MessagesAllowed),
		MessagesApproved:  atomic.LoadInt64(&m.MessagesApproved),
		BytesRedacted:     atomic.LoadInt64(&m.BytesRedacted),
		ApprovalRequests:  atomic.LoadInt64(&m.ApprovalRequests),
		ChainDetections:   atomic.LoadInt64(&m.ChainDetections),
	}
}
