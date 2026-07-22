"""OpenTelemetry traces + metrics — off by default, no-op unless enabled.

Every function here is a cheap no-op until telemetry is turned on, so the
enforcement path and the CLI carry zero OpenTelemetry cost (and zero dependency)
unless an operator opts in with ``APG_OTEL_ENABLED=1``. When enabled, the proxy
emits one span per request and two instruments:

- ``apg.requests`` (counter) — tool-call decisions, tagged by tool/decision/agent
- ``apg.request.duration`` (histogram, ms) — request handling latency

`opentelemetry-sdk` is an optional dependency
(``pip install "agent-policy-gateway[otel]"``). Exporters are configured from the
standard ``OTEL_*`` environment variables.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from typing import Any

_enabled = False
_tracer: Any = None
_decision_counter: Any = None
_latency_histogram: Any = None


def enabled() -> bool:
    return _enabled


def enable(tracer: Any = None, meter: Any = None) -> None:
    """Turn telemetry on, creating the instruments.

    ``tracer``/``meter`` may be injected (tests use in-memory providers);
    otherwise they come from the global OpenTelemetry providers.
    """
    global _enabled, _tracer, _decision_counter, _latency_histogram
    from opentelemetry import metrics, trace

    _tracer = tracer if tracer is not None else trace.get_tracer("agent_policy_gateway")
    active_meter = meter if meter is not None else metrics.get_meter("agent_policy_gateway")
    _decision_counter = active_meter.create_counter(
        "apg.requests", unit="1", description="Count of tool-call decisions"
    )
    _latency_histogram = active_meter.create_histogram(
        "apg.request.duration", unit="ms", description="Request handling latency"
    )
    _enabled = True


def configure_from_env() -> bool:
    """Enable telemetry with OTLP exporters when ``APG_OTEL_ENABLED`` is set.

    Idempotent and safe to call when the optional SDK is not installed (returns
    False). Exporters read the standard ``OTEL_EXPORTER_OTLP_*`` env vars.
    """
    if _enabled:
        return True
    if os.environ.get("APG_OTEL_ENABLED", "").strip().lower() not in ("1", "true", "yes", "on"):
        return False
    try:
        from opentelemetry import metrics, trace
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return False

    resource = Resource.create(
        {"service.name": os.environ.get("OTEL_SERVICE_NAME", "agent-policy-gateway")}
    )
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(
        MeterProvider(
            resource=resource,
            metric_readers=[PeriodicExportingMetricReader(OTLPMetricExporter())],
        )
    )
    enable()
    return True


@contextlib.contextmanager
def request_span(name: str, attributes: dict[str, Any] | None = None) -> Iterator[Any]:
    """A span for the request, or a no-op context when telemetry is off."""
    if not _enabled or _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name, attributes=attributes or {}) as span:
        yield span


def set_span_attributes(**attributes: Any) -> None:
    """Set attributes on the current span (skipping None values)."""
    if not _enabled:
        return
    from opentelemetry import trace

    span = trace.get_current_span()
    for key, value in attributes.items():
        if value is not None:
            span.set_attribute(key, value)


def record_decision(
    tool: str | None, decision: str, agent_id: str | None, latency_ms: float
) -> None:
    """Record one decision to the counter and latency histogram."""
    if not _enabled or _decision_counter is None or _latency_histogram is None:
        return
    attrs: dict[str, Any] = {"apg.decision": decision}
    if tool:
        attrs["apg.tool"] = tool
    if agent_id:
        attrs["apg.agent_id"] = agent_id
    _decision_counter.add(1, attrs)
    _latency_histogram.record(latency_ms, attrs)


def reset_for_testing() -> None:
    """Disable telemetry and drop instruments (test isolation)."""
    global _enabled, _tracer, _decision_counter, _latency_histogram
    _enabled = False
    _tracer = None
    _decision_counter = None
    _latency_histogram = None
