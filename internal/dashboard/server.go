package dashboard

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/themayursinha/mcp-visor/internal/policy"
)

type MetaProvider interface {
	SessionCount() int
	ToolCallCount() int
	RecentCalls(n int) []CallInfo
	Metrics() MetricsSnapshot
	Policy() *policy.Policy
	Uptime() time.Duration
}

type CallInfo struct {
	Timestamp  time.Time      `json:"timestamp"`
	ServerName string         `json:"server_name"`
	ToolName   string         `json:"tool_name"`
	Arguments  map[string]any `json:"arguments,omitempty"`
	Result     string         `json:"result,omitempty"`
	Risk       string         `json:"risk"`
}

type MetricsSnapshot struct {
	MessagesProcessed int64 `json:"messages_processed"`
	MessagesDenied    int64 `json:"messages_denied"`
	MessagesAllowed   int64 `json:"messages_allowed"`
	MessagesApproved  int64 `json:"messages_approved"`
	BytesRedacted     int64 `json:"bytes_redacted"`
	ApprovalRequests  int64 `json:"approval_requests"`
	ChainDetections   int64 `json:"chain_detections"`
}

type Server struct {
	addr       string
	http       *http.Server
	provider   MetaProvider
	mu         sync.RWMutex
}

func NewServer(addr string, provider MetaProvider) *Server {
	s := &Server{
		addr:     addr,
		provider: provider,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/calls", s.handleCalls)
	mux.HandleFunc("/api/metrics", s.handleMetrics)
	mux.HandleFunc("/api/policy", s.handlePolicy)

	s.http = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return s
}

func (s *Server) Start() error {
	return s.http.ListenAndServe()
}

func (s *Server) Stop() error {
	return s.http.Close()
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := map[string]any{
		"uptime_seconds":  s.provider.Uptime().Seconds(),
		"session_count":   s.provider.SessionCount(),
		"tool_call_count": s.provider.ToolCallCount(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleCalls(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	calls := s.provider.RecentCalls(50)
	if calls == nil {
		calls = []CallInfo{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"calls": calls,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m := s.provider.Metrics()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(m)
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pol := s.provider.Policy()
	summary := map[string]any{
		"version":        pol.Version,
		"description":    pol.Description,
		"default_action": pol.DefaultAction,
		"servers":        len(pol.Servers),
		"chain_rules":    len(pol.ToolChains),
		"identities":     len(pol.Identities),
		"time_restrictions": len(pol.TimeRestrictions),
		"redaction_patterns": len(pol.Redaction.Patterns),
		"output_redaction":   pol.Redaction.OutputRedaction,
		"sensitive_files":    len(pol.Redaction.SensitiveFiles),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(dashboardHTML))
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCP Visor Dashboard</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; background: #0d1117; color: #c9d1d9; padding: 24px; }
h1 { color: #58a6ff; margin-bottom: 8px; }
h2 { color: #f0883e; margin: 24px 0 12px; font-size: 16px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 24px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
.card h3 { color: #8b949e; font-size: 12px; text-transform: uppercase; margin-bottom: 8px; }
.card .value { font-size: 24px; font-weight: bold; color: #58a6ff; }
.metric { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #21262d; }
.metric:last-child { border-bottom: none; }
.metric .label { color: #8b949e; }
.metric .val { color: #c9d1d9; font-weight: bold; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; }
th { color: #8b949e; font-size: 12px; text-transform: uppercase; }
td { font-size: 13px; }
.risk-critical { color: #f85149; }
.risk-high { color: #f0883e; }
.risk-medium { color: #e3b341; }
.risk-low { color: #58a6ff; }
.decision-deny { color: #f85149; }
.decision-allow { color: #3fb950; }
.decision-approve { color: #f0883e; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }
.badge-allow { background: #1a3320; color: #3fb950; }
.badge-deny { background: #331a1a; color: #f85149; }
.badge-pending { background: #332e1a; color: #e3b341; }
.args { color: #8b949e; font-size: 11px; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.refresh { color: #8b949e; font-size: 11px; }
.error { color: #f85149; padding: 12px; background: #331a1a; border-radius: 8px; }
</style>
</head>
<body>
<h1>MCP Visor</h1>
<p style="color: #8b949e; margin-bottom: 24px;">Runtime Policy Enforcement & Audit Control Plane</p>

<div id="status" class="card"><p style="color: #8b949e;">Loading...</p></div>

<h2>Activity</h2>
<div id="calls"><p style="color: #8b949e;">Loading...</p></div>

<h2>Metrics</h2>
<div id="metrics"><p style="color: #8b949e;">Loading...</p></div>

<h2>Policy</h2>
<div id="policy-info"><p style="color: #8b949e;">Loading...</p></div>

<script>
async function fetchJSON(url) {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(resp.statusText);
    return resp.json();
}

async function loadStatus() {
    try {
        const data = await fetchJSON('/api/status');
        document.getElementById('status').innerHTML =
            '<div class="grid">' +
            '<div class="card"><h3>Uptime</h3><div class="value">' + Math.round(data.uptime_seconds) + 's</div></div>' +
            '<div class="card"><h3>Sessions</h3><div class="value">' + data.session_count + '</div></div>' +
            '<div class="card"><h3>Tool Calls</h3><div class="value">' + data.tool_call_count + '</div></div>' +
            '</div>';
    } catch(e) {
        document.getElementById('status').innerHTML = '<div class="error">Connection lost</div>';
    }
}

function renderCalls(calls) {
    if (!calls || calls.length === 0) return '<p style="color: #8b949e;">No tool calls recorded.</p>';
    let html = '<table><thead><tr><th>Time</th><th>Server</th><th>Tool</th><th>Risk</th><th>Args</th><th>Result</th></tr></thead><tbody>';
    for (const c of calls.slice(-20).reverse()) {
        const args = JSON.stringify(c.arguments || {}).replace(/"/g, '').slice(0, 60);
        const result = (c.result || '').slice(0, 40);
        html += '<tr>' +
            '<td>' + new Date(c.timestamp).toLocaleTimeString() + '</td>' +
            '<td>' + escapeHtml(c.server_name) + '</td>' +
            '<td>' + escapeHtml(c.tool_name) + '</td>' +
            '<td class="risk-' + (c.risk || 'low') + '">' + (c.risk || 'low') + '</td>' +
            '<td class="args">' + escapeHtml(args) + '</td>' +
            '<td style="color:#8b949e">' + escapeHtml(result) + '</td>' +
            '</tr>';
    }
    return html + '</tbody></table>';
}

async function loadCalls() {
    try {
        const data = await fetchJSON('/api/calls');
        document.getElementById('calls').innerHTML = renderCalls(data.calls);
    } catch(e) {
        document.getElementById('calls').innerHTML = '<div class="error">Failed to load calls</div>';
    }
}

async function loadMetrics() {
    try {
        const data = await fetchJSON('/api/metrics');
        document.getElementById('metrics').innerHTML =
            '<div class="card">' +
            '<div class="metric"><span class="label">Processed</span><span class="val">' + fmt(data.messages_processed) + '</span></div>' +
            '<div class="metric"><span class="label">Allowed</span><span class="val decision-allow">' + fmt(data.messages_allowed) + '</span></div>' +
            '<div class="metric"><span class="label">Denied</span><span class="val decision-deny">' + fmt(data.messages_denied) + '</span></div>' +
            '<div class="metric"><span class="label">Approved</span><span class="val decision-approve">' + fmt(data.messages_approved) + '</span></div>' +
            '<div class="metric"><span class="label">Bytes Redacted</span><span class="val">' + fmt(data.bytes_redacted) + '</span></div>' +
            '<div class="metric"><span class="label">Approval Requests</span><span class="val">' + fmt(data.approval_requests) + '</span></div>' +
            '<div class="metric"><span class="label">Chain Detections</span><span class="val">' + fmt(data.chain_detections) + '</span></div>' +
            '</div>';
    } catch(e) {
        document.getElementById('metrics').innerHTML = '<div class="error">Failed to load metrics</div>';
    }
}

async function loadPolicy() {
    try {
        const data = await fetchJSON('/api/policy');
        document.getElementById('policy-info').innerHTML =
            '<div class="card">' +
            '<div class="metric"><span class="label">Version</span><span class="val">' + escapeHtml(data.version) + '</span></div>' +
            '<div class="metric"><span class="label">Default Action</span><span class="val">' + renderDecision(data.default_action) + '</span></div>' +
            '<div class="metric"><span class="label">Servers</span><span class="val">' + data.servers + '</span></div>' +
            '<div class="metric"><span class="label">Chain Rules</span><span class="val">' + data.chain_rules + '</span></div>' +
            '<div class="metric"><span class="label">Identities</span><span class="val">' + data.identities + '</span></div>' +
            '<div class="metric"><span class="label">Time Restrictions</span><span class="val">' + data.time_restrictions + '</span></div>' +
            '<div class="metric"><span class="label">Redaction Patterns</span><span class="val">' + data.redaction_patterns + '</span></div>' +
            '<div class="metric"><span class="label">Sensitive Files</span><span class="val">' + data.sensitive_files + '</span></div>' +
            '</div>';
    } catch(e) {
        document.getElementById('policy-info').innerHTML = '<div class="error">Failed to load policy</div>';
    }
}

function fmt(n) { return n != null ? n.toLocaleString() : '0'; }
function escapeHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function renderDecision(d) {
    if (d === 'deny') return '<span class="badge badge-deny">DENY</span>';
    if (d === 'allow') return '<span class="badge badge-allow">ALLOW</span>';
    return '<span class="badge badge-pending">' + d.toUpperCase() + '</span>';
}

async function refresh() {
    await Promise.all([loadStatus(), loadCalls(), loadMetrics(), loadPolicy()]);
    document.querySelector('.refresh').textContent = 'Last refresh: ' + new Date().toLocaleTimeString();
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`
