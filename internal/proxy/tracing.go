package proxy

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

func (m *ProxyMetrics) IncrementProcessed()      { m.MessagesProcessed++ }
func (m *ProxyMetrics) IncrementDenied()         { m.MessagesDenied++ }
func (m *ProxyMetrics) IncrementAllowed()        { m.MessagesAllowed++ }
func (m *ProxyMetrics) IncrementApproved()       { m.MessagesApproved++ }
func (m *ProxyMetrics) AddBytesRedacted(n int64) { m.BytesRedacted += n }
func (m *ProxyMetrics) IncrementApprovals()      { m.ApprovalRequests++ }
func (m *ProxyMetrics) IncrementChains()         { m.ChainDetections++ }
