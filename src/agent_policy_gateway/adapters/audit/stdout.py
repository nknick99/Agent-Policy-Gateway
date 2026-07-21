"""Structured stdout audit sink for Agent Policy Gateway.

Emits exactly one structured JSON audit event per request to stdout
for container log collection (append-only off-box destination).

This module intentionally exposes NO interface to modify or delete
existing audit entries (Requirement 9.7).

The event schema and redaction helpers live in core.audit; they are
re-exported here for backwards compatibility.
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from agent_policy_gateway.core.audit import AuditEvent, redact_params
from agent_policy_gateway.core.models import AuditDecision

__all__ = ["AuditEvent", "AuditLogger", "redact_params"]


def _configure_structlog() -> None:
    """Configure structlog for JSON output to stdout (append-only)."""
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


# Configure once at module load
_configure_structlog()


class AuditLogger:
    """Append-only structured audit sink writing to stdout.

    Emits exactly one JSON event per request to stdout for off-box
    log collection. This class intentionally provides NO methods to
    modify or delete existing audit entries.
    """

    def __init__(self) -> None:
        self._logger = structlog.get_logger("agent_policy_gateway.audit")

    def generate_correlation_id(self) -> str:
        """Generate a unique correlation ID (UUID4) for a request."""
        return str(uuid.uuid4())

    def emit(self, event: AuditEvent) -> None:
        """Emit a structured audit event to stdout.

        This method never raises exceptions. On any internal failure,
        it attempts to emit a partial event with available information.
        If even that fails, the error is silently swallowed to avoid
        disrupting the request pipeline.
        """
        try:
            event_data = self._build_event_data(event)
            self._logger.info("audit_event", **event_data)
        except Exception:
            # Requirement 9.8: still emit partial event on failure
            try:
                self._logger.info(
                    "audit_event_partial",
                    correlation_id=event.correlation_id,
                    timestamp=event.timestamp,
                    caller_identity=event.caller_identity,
                    method=event.method,
                    decision=event.decision.value,
                    error="emit_failed",
                )
            except Exception:
                # Absolute last resort: swallow to never break the pipeline
                pass

    def _build_event_data(self, event: AuditEvent) -> dict[str, Any]:
        """Build the event dict for logging, including decision-specific fields."""
        data: dict[str, Any] = {
            "correlation_id": event.correlation_id,
            "timestamp": event.timestamp,
            "caller_identity": event.caller_identity,
            "method": event.method,
            "decision": event.decision.value,
            "rule_matched": event.rule_matched,
            "params_redacted": event.params_redacted,
            "duration_ms": event.duration_ms,
        }

        if event.decision == AuditDecision.ALLOW:
            data["role_assumed"] = event.role_assumed
            data["outcome"] = event.outcome
        elif event.decision == AuditDecision.DENY:
            data["denial_reason"] = event.denial_reason

        return data
