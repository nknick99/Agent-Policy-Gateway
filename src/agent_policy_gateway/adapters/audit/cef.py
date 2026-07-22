"""Common Event Format (CEF) rendering for audit events.

CEF is the lingua franca of SIEMs (ArcSight, Splunk, QRadar, …):

    CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension

The header fields escape ``\\`` and ``|``; extension values escape ``\\``, ``=``
and newlines. This module is pure so it can be unit-tested and reused by every
SIEM sink (syslog, HEC, …).
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from typing import Any

_VENDOR = "AgentPolicyGateway"
_PRODUCT = "APG"

try:
    _VERSION = version("agent-policy-gateway")
except PackageNotFoundError:  # pragma: no cover - dev tree without install
    _VERSION = "0.0.0"


def _severity(outcome: str) -> int:
    """Map an outcome to a CEF severity (0–10)."""
    upper = outcome.upper()
    if upper in ("DENY", "DENIED"):
        return 7
    if upper in ("ALLOW", "ALLOWED"):
        return 3
    return 1


def _escape_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _escape_extension(value: str) -> str:
    return (
        value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "")
    )


def to_cef(event: dict[str, Any]) -> str:
    """Render one audit event as a CEF string."""
    outcome = str(event.get("outcome", "UNKNOWN"))
    method = event.get("method") or "-"
    name = f"tool call {method} {outcome.lower()}"

    # Standard + custom CEF extension keys.
    fields: dict[str, Any] = {
        "act": outcome,
        "suser": event.get("agent_id"),
        "externalId": event.get("correlation_id"),
        "rt": event.get("timestamp"),
        "msg": event.get("reason"),
        "request": event.get("destination"),
        "cs1": method,
        "cs1Label": "tool",
        "cs2": event.get("op"),
        "cs2Label": "operation",
        "cn1": event.get("latency_ms"),
        "cn1Label": "latencyMs",
    }
    extension = " ".join(
        f"{key}={_escape_extension(str(value))}"
        for key, value in fields.items()
        if value is not None
    )

    header = "|".join(
        _escape_header(part)
        for part in (
            "CEF:0",
            _VENDOR,
            _PRODUCT,
            _VERSION,
            outcome,  # signature / event class id
            name,
        )
    )
    return f"{header}|{_severity(outcome)}|{extension}"
