package observability

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/credentials/insecure"
)

type otelPipeline struct {
	tracer         trace.Tracer
	toolCalls      metric.Int64Counter
	toolDenied     metric.Int64Counter
	toolAllowed    metric.Int64Counter
	toolApproved   metric.Int64Counter
	traceProvider  *sdktrace.TracerProvider
	metricProvider *sdkmetric.MeterProvider
}

func newOTelPipeline(cfg Config) (*otelPipeline, error) {
	ctx := context.Background()
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, err
	}

	endpoint := strings.TrimPrefix(cfg.OTLPEndpoint, "http://")
	endpoint = strings.TrimPrefix(endpoint, "https://")

	traceOpts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(endpoint)}
	metricOpts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(endpoint)}
	if cfg.OTLPInsecure {
		traceOpts = append(traceOpts, otlptracegrpc.WithTLSCredentials(insecure.NewCredentials()))
		metricOpts = append(metricOpts, otlpmetricgrpc.WithTLSCredentials(insecure.NewCredentials()))
	}

	traceExp, err := otlptracegrpc.New(ctx, traceOpts...)
	if err != nil {
		return nil, err
	}
	metricExp, err := otlpmetricgrpc.New(ctx, metricOpts...)
	if err != nil {
		return nil, err
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.TraceSampleRatio))
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)

	meter := mp.Meter("github.com/themayursinha/mcp-visor")
	toolCalls, _ := meter.Int64Counter("mcp_visor_tool_calls_total")
	toolDenied, _ := meter.Int64Counter("mcp_visor_tool_denied_total")
	toolAllowed, _ := meter.Int64Counter("mcp_visor_tool_allowed_total")
	toolApproved, _ := meter.Int64Counter("mcp_visor_tool_approved_total")

	return &otelPipeline{
		tracer:         tp.Tracer("mcp-visor/proxy"),
		toolCalls:      toolCalls,
		toolDenied:     toolDenied,
		toolAllowed:    toolAllowed,
		toolApproved:   toolApproved,
		traceProvider:  tp,
		metricProvider: mp,
	}, nil
}

func (o *otelPipeline) recordToolCall(ctx context.Context, ev ToolCallEvent) {
	if o == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	attrs := []attribute.KeyValue{
		attribute.String("mcp.server.name", ev.ServerName),
		attribute.String("mcp.tool.name", ev.ToolName),
		attribute.String("policy.decision", ev.Decision),
		attribute.String("policy.reason", truncate(ev.Reason, 256)),
		attribute.String("policy.risk", ev.Risk),
		attribute.Bool("policy.chain_triggered", ev.ChainTriggered),
		attribute.String("session.id", ev.SessionID),
	}
	spanName := "mcp.tools/call"
	if ev.ToolName != "" {
		spanName = "mcp.tools/call " + ev.ToolName
	}
	ctx, span := o.tracer.Start(ctx, spanName, trace.WithAttributes(attrs...))
	defer span.End()
	_ = ctx

	labels := metric.WithAttributes(
		attribute.String("mcp.tool.name", ev.ToolName),
		attribute.String("policy.decision", ev.Decision),
	)
	o.toolCalls.Add(context.Background(), 1, labels)
	switch ev.Decision {
	case "denied":
		o.toolDenied.Add(context.Background(), 1, labels)
	case "approved":
		o.toolApproved.Add(context.Background(), 1, labels)
	default:
		o.toolAllowed.Add(context.Background(), 1, labels)
	}
	if ev.Duration > 0 {
		span.SetAttributes(attribute.Int64("mcp.duration_ms", ev.Duration.Milliseconds()))
	}
}

func (o *otelPipeline) shutdown(ctx context.Context) error {
	if o == nil {
		return nil
	}
	var first error
	if o.traceProvider != nil {
		if err := o.traceProvider.Shutdown(ctx); err != nil && first == nil {
			first = err
		}
	}
	if o.metricProvider != nil {
		if err := o.metricProvider.Shutdown(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
