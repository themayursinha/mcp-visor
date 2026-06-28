# OTel + LGTM local lab

Companion to Obsidian note: **OTel and LGTM — Agent Security Observability**.

## Quick start (Python demo)

```bash
cd examples/otel-lgtm
docker compose up -d
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 python3 demo_agent_tools.py
```

## mcp-visor with OTLP + Prometheus

With LGTM running (`docker compose up -d` above):

```bash
cd ../..   # repo root
go build -o mcp-visor ./cmd/mcp-visor

./mcp-visor serve --demo \
  --metrics-addr 127.0.0.1:9091 \
  --otel-endpoint localhost:4317 \
  --otel-service-name mcp-visor
```

- Prometheus: `curl -s http://127.0.0.1:9091/metrics | head`
- Grafana: **http://localhost:3000** → traces/metrics for `mcp-visor` and `agent-tool-gateway-demo`

## What this demonstrates

- One **OTLP** endpoint feeds **traces**, **metrics**, and (via Grafana LGTM) **logs** in a unified UI.
- Spans: **agent session → tool call → policy verdict** (Python demo + Go proxy enforcement).

## Teardown

```bash
docker compose down
# docker compose down -v   # also drop volume
```