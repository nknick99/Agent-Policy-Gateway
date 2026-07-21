"""Structured audit logging for Agent Policy Gateway Proxy.

Emits exactly one structured JSON audit event per request to stdout
for container log collection (append-only off-box destination).

This module intentionally exposes NO interface to modify or delete
existing audit entries (Requirement 9.7).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from agent_policy_gateway.core.filter import SECRET_PATTERNS
from agent_policy_gateway.core.models import AuditDecision


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


@dataclass
class AuditEvent:
    """Structured audit event emitted once per request.

    Fields are populated progressively as the pipeline executes.
    On unhandled exceptions, a partial event is emitted with whatever
    information is available at that point.
    """

    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    caller_identity: str = ""
    method: str = ""
    decision: AuditDecision = AuditDecision.DENY
    rule_matched: str = ""
    params_redacted: dict = field(default_factory=dict)
    # ALLOW-specific fields
    role_assumed: str | None = None
    outcome: str = ""
    # DENY-specific field
    denial_reason: str = ""
    duration_ms: float = 0.0


def redact_params(params: dict[str, Any]) -> dict[str, Any]:
    """Redact parameter values matching SECRET_PATTERNS.

    Returns a new dict with secret values replaced by "[REDACTED]".
    Non-string values are preserved as-is. The original dict is not mutated.
    """
    redacted: dict[str, Any] = {}
    for key, value in params.items():
        if isinstance(value, str):
            redacted[key] = _redact_string(value)
        elif isinstance(value, dict):
            redacted[key] = redact_params(value)
        elif isinstance(value, list):
            redacted[key] = [_redact_value(item) for item in value]
        else:
            redacted[key] = value
    return redacted


def _redact_value(value: Any) -> Any:
    """Redact a single value if it's a string containing secrets."""
    if isinstance(value, str):
        return _redact_string(value)
    elif isinstance(value, dict):
        return redact_params(value)
    elif isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def _redact_string(value: str) -> str:
    """Replace the entire string with [REDACTED] if any secret pattern matches."""
    for pattern in SECRET_PATTERNS:
        if pattern.search(value):
            return "[REDACTED]"
    return value


class AuditLogger:
    """Append-only structured audit logger.

    Emits exactly one JSON event per request to stdout for off-box
    log collection. This class intentionally provides NO methods to
    modify or delete existing audit entries.
    """

    def __init__(self) -> None:
        self._logger = structlog.get_logger("agent_policy_gateway.adapters.audit.stdout")

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
