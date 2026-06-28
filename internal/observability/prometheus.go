package observability

import (
	"fmt"
	"io"
	"strconv"
)

// WritePrometheus writes exposition format for mcp-visor proxy counters.
func WritePrometheus(w io.Writer, s Snapshot) {
	writeCounter := func(name, help string, v int64) {
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %s\n\n", name, help, name, name, strconv.FormatInt(v, 10))
	}
	writeCounter("mcp_visor_messages_processed_total", "MCP messages processed at the tools/call gate", s.MessagesProcessed)
	writeCounter("mcp_visor_messages_denied_total", "Tool calls denied by policy or limits", s.MessagesDenied)
	writeCounter("mcp_visor_messages_allowed_total", "Tool calls allowed without human approval", s.MessagesAllowed)
	writeCounter("mcp_visor_messages_approved_total", "Tool calls allowed after human approval", s.MessagesApproved)
	writeCounter("mcp_visor_bytes_redacted_total", "Bytes redacted from tool arguments", s.BytesRedacted)
	writeCounter("mcp_visor_approval_requests_total", "Human approval workflows started", s.ApprovalRequests)
	writeCounter("mcp_visor_chain_detections_total", "Dangerous tool chain rules triggered", s.ChainDetections)
}
