#!/usr/bin/env python3
"""
Minimal agent-tool observability demo: OTLP traces + metrics + structured logs.

Models an MCP-style flow: session -> model_turn -> tools/call -> policy verdict.
Run after: docker compose up -d

  OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 python3 demo_agent_tools.py

Open Grafana http://localhost:3000 and explore traces/metrics/logs (LGTM bundle).
"""
from __future__ import annotations

import logging
import os
import random
import time

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

SERVICE = "agent-tool-gateway-demo"
ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

resource = Resource.create(
    {
        "service.name": SERVICE,
        "service.version": "0.1.0",
        "deployment.environment": "local",
    }
)

trace_provider = TracerProvider(resource=resource)
trace_provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint=ENDPOINT, insecure=True))
)
trace.set_tracer_provider(trace_provider)
tracer = trace.get_tracer(__name__)

reader = PeriodicExportingMetricReader(
    OTLPMetricExporter(endpoint=ENDPOINT, insecure=True),
    export_interval_millis=3000,
)
metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[reader]))
meter = metrics.get_meter(__name__)

tool_calls = meter.create_counter("agent_tool_calls_total", description="Tool invocations")
tool_denied = meter.create_counter("agent_tool_denied_total", description="Policy denials")
tool_latency = meter.create_histogram(
    "agent_tool_latency_ms", description="Tool call latency", unit="ms"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s level=%(levelname)s %(message)s",
)

TOOLS = ("read_file", "terminal", "web_search", "patch")
DENY_TOOLS = frozenset({"terminal"})


def run_session(session_id: str) -> None:
    with tracer.start_as_current_span(
        "agent.session",
        attributes={"session.id": session_id, "mcp.component": "gateway"},
    ):
        with tracer.start_as_current_span("agent.model_turn", attributes={"turn": 1}):
            tool = random.choice(TOOLS)
            invoke_tool(tool, session_id)


def invoke_tool(name: str, session_id: str) -> None:
    start = time.perf_counter()
    with tracer.start_as_current_span(
        "mcp.tools/call",
        attributes={"tool.name": name, "session.id": session_id},
    ) as span:
        time.sleep(random.uniform(0.02, 0.12))
        allowed = name not in DENY_TOOLS
        span.set_attribute("policy.allowed", allowed)
        span.set_attribute("policy.reason", "ok" if allowed else "shell_blocked_by_spec")

        tool_calls.add(1, {"tool.name": name, "policy.allowed": str(allowed).lower()})
        ctx = span.get_span_context()
        trace_id = format(ctx.trace_id, "032x") if ctx.is_valid else "none"
        if not allowed:
            tool_denied.add(1, {"tool.name": name, "policy.reason": "shell_blocked_by_spec"})
            logging.warning(
                "policy_denied tool=%s session=%s trace_id=%s", name, session_id, trace_id
            )
        else:
            logging.info("tool_ok tool=%s session=%s trace_id=%s", name, session_id, trace_id)

        elapsed_ms = (time.perf_counter() - start) * 1000
        tool_latency.record(elapsed_ms, {"tool.name": name})


def main() -> None:
    print(f"Exporting OTLP to {ENDPOINT} (service={SERVICE})")
    for i in range(8):
        run_session(f"sess-{i:04d}")
        time.sleep(0.3)
    # Flush metrics reader
    time.sleep(4)
    print("Done. Grafana: http://localhost:3000")


if __name__ == "__main__":
    main()