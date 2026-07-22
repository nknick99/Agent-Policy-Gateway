"""Learning mode — turn observed denials into ready-to-paste policy entries.

The default-deny model's biggest adoption cost is authoring: someone has to
enumerate every legitimate tool/operation/destination up front. Learning mode
inverts that. Run the proxy in `--mode audit` (log but don't block) against
real traffic, then `apg policy suggest` reads the audit log and proposes the
allowlist entries that would have let the observed calls through.

The suggestion is deterministic and *additive*: it never proposes removing or
loosening anything already in the policy — only the minimal additions that
would have allowed the denied calls it saw.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from agent_policy_gateway.core.models import PolicyDocument

# Outcomes in the audit log that represent a blocked/would-block call.
_DENY_OUTCOMES = {"DENY", "DENIED"}


def load_audit_events(audit_path: str) -> list[dict[str, Any]]:
    """Parse a JSONL audit file into a list of event dicts.

    Skips blank and malformed lines rather than failing — an audit log is
    append-only operational data, not a contract, and a single truncated
    line should not sink the whole analysis.
    """
    path = Path(audit_path)
    if not path.exists():
        return []

    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _normalize_destination(destination: str) -> str | None:
    """Reduce a destination URL to the scheme://host origin used in policy.

    Whitelist entries in policy.json are origins (e.g. ``https://api.example.com``),
    so a captured ``https://api.example.com/v1/x`` should suggest the origin,
    not the full path.
    """
    parsed = urlparse(destination)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    # Bare host with no scheme — keep as-is if it looks like a host.
    if not parsed.scheme and "/" not in destination and destination:
        return destination
    return None


def suggest_entries(
    events: list[dict[str, Any]], policy: PolicyDocument | None = None
) -> dict[str, dict[str, Any]]:
    """Propose policy tool entries that would have allowed the denied calls.

    Args:
        events: Parsed audit events (see :func:`load_audit_events`).
        policy: The current policy, if any. Suggestions are diffed against it
            so only genuinely new permissions are proposed.

    Returns:
        A mapping of tool name → proposed entry (or additive delta for tools
        that already exist). Empty when nothing new needs allowing.
    """
    # Aggregate observed requirements per method from the denials only.
    observed: dict[str, dict[str, set[str]]] = {}
    for event in events:
        outcome = str(event.get("outcome", "")).upper()
        if outcome not in _DENY_OUTCOMES:
            continue
        method = event.get("method")
        # Auth failures have no method and aren't a policy-authoring problem.
        if not isinstance(method, str) or not method:
            continue

        bucket = observed.setdefault(
            method, {"operations": set(), "tables": set(), "destination_whitelist": set()}
        )
        if isinstance(event.get("op"), str) and event["op"]:
            bucket["operations"].add(event["op"])
        if isinstance(event.get("table"), str) and event["table"]:
            bucket["tables"].add(event["table"])
        if isinstance(event.get("destination"), str) and event["destination"]:
            origin = _normalize_destination(event["destination"])
            if origin:
                bucket["destination_whitelist"].add(origin)

    existing = policy.tools if policy is not None else {}
    suggestions: dict[str, dict[str, Any]] = {}

    for method, bucket in sorted(observed.items()):
        current = existing.get(method)
        if current is None or not current.allow:
            # New tool (or one currently denied wholesale): propose a full entry.
            entry: dict[str, Any] = {"allow": True}
            for field in ("operations", "tables", "destination_whitelist"):
                values = sorted(bucket[field])
                if values:
                    entry[field] = values
            suggestions[method] = entry
            continue

        # Tool already allowed — propose only the additive delta.
        delta: dict[str, Any] = {}
        current_values = {
            "operations": set(current.operations),
            "tables": set(current.tables),
            "destination_whitelist": set(current.destination_whitelist),
        }
        for field in ("operations", "tables", "destination_whitelist"):
            new_values = bucket[field] - current_values[field]
            if new_values:
                delta[field] = sorted(current_values[field] | new_values)
        if delta:
            suggestions[method] = delta

    return suggestions
