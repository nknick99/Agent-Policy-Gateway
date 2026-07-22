"""SQLite audit sink — durable and queryable, still zero external services.

Each event is stored whole as a JSON blob (so the schema never has to chase the
event shape), alongside a few extracted columns — timestamp, outcome, method,
correlation_id — that make `apg audit tail --outcome DENY` a fast indexed query.
The table is append-only; there is no update or delete path.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    outcome TEXT,
    method TEXT,
    correlation_id TEXT,
    event_json TEXT NOT NULL
)
"""

_INDEX = "CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit_events(outcome)"


class SqliteAuditSink:
    """Durable audit sink backed by a local SQLite database file."""

    def __init__(self, path: str) -> None:
        parent = Path(path).expanduser().parent
        if parent and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False + a lock: the async transports write from the
        # event-loop thread while a follow reader may query from another.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute(_SCHEMA)
            self._conn.execute(_INDEX)
            self._conn.commit()

    def write(self, event: dict[str, Any]) -> None:
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO audit_events "
                    "(timestamp, outcome, method, correlation_id, event_json) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        event.get("timestamp"),
                        event.get("outcome"),
                        event.get("method"),
                        event.get("correlation_id"),
                        json.dumps(event),
                    ),
                )
                self._conn.commit()
        except Exception:
            # Audit must never take down the request path.
            pass

    def read(
        self, limit: int | None = None, outcome: str | None = None
    ) -> list[dict[str, Any]]:
        query = "SELECT event_json FROM audit_events"
        params: list[Any] = []
        if outcome:
            query += " WHERE UPPER(outcome) = ?"
            params.append(outcome.upper())
        # Newest first for the LIMIT, then reverse to chronological for display.
        query += " ORDER BY id DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        events = [json.loads(row[0]) for row in rows]
        events.reverse()
        return events

    def close(self) -> None:
        with self._lock:
            self._conn.close()
