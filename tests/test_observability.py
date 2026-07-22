"""Tests for OpenTelemetry instrumentation (opt-in, no-op when disabled)."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agent_policy_gateway.adapters.observability import otel as telemetry
from agent_policy_gateway.proxy_app import create_proxy_app

POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.json"
TOKEN = "otel-test-token"


class TestDisabledIsNoop:
    def test_noop_calls_do_not_error(self):
        telemetry.reset_for_testing()
        assert telemetry.enabled() is False
        telemetry.record_decision("db.query", "ALLOW", "agent", 1.0)
        with telemetry.request_span("x", {"a": 1}) as span:
            assert span is None
        telemetry.set_span_attributes(foo="bar")  # no error


@pytest.fixture()
def in_memory_otel():
    """Enable telemetry against in-memory exporters; reset afterwards."""
    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    metric_reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[metric_reader])
    telemetry.enable(
        tracer=tracer_provider.get_tracer("test"),
        meter=meter_provider.get_meter("test"),
    )
    try:
        yield span_exporter, metric_reader
    finally:
        telemetry.reset_for_testing()


def _counter_total(reader: InMemoryMetricReader) -> int:
    data = reader.get_metrics_data()
    total = 0
    for resource_metric in data.resource_metrics:
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                if metric.name == "apg.requests":
                    for point in metric.data.data_points:
                        total += point.value
    return total


class TestRecordDecisionUnit:
    def test_counter_records_with_attributes(self, in_memory_otel):
        _, reader = in_memory_otel
        telemetry.record_decision("db.query", "DENY", "reader", 2.5)
        telemetry.record_decision("http.get", "ALLOW", "fetcher", 1.0)
        assert _counter_total(reader) == 2


@pytest_asyncio.fixture()
async def proxy(in_memory_otel, tmp_path, monkeypatch):
    monkeypatch.setenv("APG_AGENT_TOKEN", TOKEN)
    app = create_proxy_app(
        target_url="http://unused.invalid",
        policy_path=str(POLICY_PATH),
        audit_file=str(tmp_path / "audit.jsonl"),
        mode="enforce",
    )
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
        yield client, in_memory_otel


def _rpc(method, params):
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}


class TestProxyEmitsTelemetry:
    async def test_denied_requests_produce_spans_and_metrics(self, proxy):
        client, (span_exporter, reader) = proxy

        # Auth failure (no token) — blocked before any target call.
        r1 = await client.post("/", json=_rpc("db.query", {"op": "select"}))
        assert r1.status_code == 401
        # Policy denial (valid token, disallowed op) — also no target call.
        r2 = await client.post(
            "/",
            json=_rpc("db.query", {"op": "drop", "query": "DROP TABLE users"}),
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        assert "error" in r2.json()

        spans = span_exporter.get_finished_spans()
        request_spans = [s for s in spans if s.name == "apg.proxy.request"]
        assert len(request_spans) == 2
        assert all(s.attributes.get("apg.decision") == "DENY" for s in request_spans)

        assert _counter_total(reader) == 2
