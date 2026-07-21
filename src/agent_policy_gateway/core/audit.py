"""Audit domain objects — the event schema and parameter redaction.

Sinks that persist/emit these events live in adapters/audit/.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agent_policy_gateway.core.filter import SECRET_PATTERNS
from agent_policy_gateway.core.models import AuditDecision


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
