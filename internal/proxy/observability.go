package proxy

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/themayursinha/mcp-visor/internal/observability"
)

func (p *Proxy) initObservability() error {
	cfg := p.cfg.Observability
	if !cfg.Enabled() {
		return nil
	}
	rt, err := observability.New(cfg, func() observability.Snapshot {
		m := p.metrics
		return observability.Snapshot{
			MessagesProcessed: m.MessagesProcessed,
			MessagesDenied:    m.MessagesDenied,
			MessagesAllowed:   m.MessagesAllowed,
			MessagesApproved:  m.MessagesApproved,
			BytesRedacted:     m.BytesRedacted,
			ApprovalRequests:  m.ApprovalRequests,
			ChainDetections:   m.ChainDetections,
		}
	})
	if err != nil {
		return err
	}
	p.obs = rt
	if cfg.MetricsListenAddr != "" {
		fmt.Fprintf(os.Stderr, "Prometheus metrics: http://%s/metrics\n", cfg.MetricsListenAddr)
	}
	if cfg.OTLPEndpoint != "" {
		fmt.Fprintf(os.Stderr, "OTLP export: %s (service=%s)\n", cfg.OTLPEndpoint, cfg.ServiceName)
	}
	return rt.Start()
}

func (p *Proxy) shutdownObservability() {
	if p.obs == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = p.obs.Shutdown(ctx)
	p.obs = nil
}

func (p *Proxy) observeToolCall(decision, reason, serverName, toolName, risk string, chain bool, started time.Time) {
	if p.obs == nil {
		return
	}
	p.obs.RecordToolCall(context.Background(), observability.ToolCallEvent{
		SessionID:      p.session.ID,
		ServerName:     serverName,
		ToolName:       toolName,
		Decision:       decision,
		Reason:         reason,
		Risk:           risk,
		ChainTriggered: chain,
		Duration:       time.Since(started),
	})
}
