package proxy

import (
	"time"

	"github.com/themayursinha/mcp-visor/internal/dashboard"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

type dashboardProvider struct {
	proxy  *Proxy
	bornAt time.Time
}

func (p *Proxy) DashboardProvider() dashboard.MetaProvider {
	return &dashboardProvider{proxy: p, bornAt: time.Now()}
}

func (dp *dashboardProvider) SessionCount() int {
	if dp.proxy.session != nil {
		return 1
	}
	return 0
}

func (dp *dashboardProvider) ToolCallCount() int {
	return dp.proxy.session.ToolCallCount()
}

func (dp *dashboardProvider) RecentCalls(n int) []dashboard.CallInfo {
	records := dp.proxy.session.RecentCalls(n)
	calls := make([]dashboard.CallInfo, len(records))
	for i, r := range records {
		risk := string(dp.proxy.engine.GetRiskLevel(r.ServerName, r.ToolName))
		calls[i] = dashboard.CallInfo{
			Timestamp:  r.Timestamp,
			ServerName: r.ServerName,
			ToolName:   r.ToolName,
			Arguments:  r.Arguments,
			Result:     r.Result,
			Risk:       risk,
		}
	}
	return calls
}

func (dp *dashboardProvider) Metrics() dashboard.MetricsSnapshot {
	m := &dp.proxy.metrics
	return dashboard.MetricsSnapshot{
		MessagesProcessed: m.MessagesProcessed,
		MessagesDenied:    m.MessagesDenied,
		MessagesAllowed:   m.MessagesAllowed,
		MessagesApproved:  m.MessagesApproved,
		BytesRedacted:     m.BytesRedacted,
		ApprovalRequests:  m.ApprovalRequests,
		ChainDetections:   m.ChainDetections,
	}
}

func (dp *dashboardProvider) Policy() *policy.Policy {
	return dp.proxy.engine.Policy()
}

func (dp *dashboardProvider) Uptime() time.Duration {
	return time.Since(dp.bornAt)
}
