"""JSONL audit sink — one JSON object per line, appended to a file.

This is the default durable-ish audit format shared by every transport (the
HTTP proxy and the stdio wrapper). Keeping it here, free of any web-framework
imports, lets both transports write the same audit schema that
`apg policy suggest` later mines.
"""

from __future__ import annotations

import json
from typing import Any


def write_event(audit_file: str, event: dict[str, Any]) -> None:
    """Append one audit event as a JSON line.

    Audit logging must never take down the request path, so any I/O error is
    swallowed — a missing audit line is preferable to a dropped request.
    """
    try:
        with open(audit_file, "a") as handle:
            handle.write(json.dumps(event) + "\n")
    except Exception:
        pass


def attempt_summary(params: dict[str, Any]) -> dict[str, Any]:
    """Extract the policy-relevant fields of an attempt for the audit log.

    Only includes keys that are present, so audit lines stay compact. These
    fields are what `apg policy suggest` mines to propose allowlist entries.
    """
    summary: dict[str, Any] = {}
    for key in ("op", "table"):
        value = params.get(key)
        if isinstance(value, str) and value:
            summary[key] = value
    destination = params.get("url") or params.get("destination")
    if isinstance(destination, str) and destination:
        summary["destination"] = destination
    return summary
