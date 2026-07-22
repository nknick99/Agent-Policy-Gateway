"""AuditSink port — the interface every audit backend implements.

The transports (HTTP proxy, stdio wrapper) depend only on this Protocol, so a
deployment can append to a JSONL file (default, zero dependencies) or a SQLite
database (durable and queryable) without the enforcement path knowing which.
Postgres/OTel/SIEM sinks slot in later by implementing the same three methods.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AuditSink(Protocol):
    """A durable, append-only destination for audit events."""

    def write(self, event: dict[str, Any]) -> None:
        """Persist one audit event. Must never raise into the request path."""
        ...

    def read(
        self, limit: int | None = None, outcome: str | None = None
    ) -> list[dict[str, Any]]:
        """Return stored events oldest-first, optionally filtered/limited.

        Args:
            limit: If set, return only the most recent ``limit`` events.
            outcome: If set, return only events with this outcome
                (case-insensitive, e.g. "DENY").
        """
        ...

    def close(self) -> None:
        """Release any held resources (e.g. a database connection)."""
        ...
