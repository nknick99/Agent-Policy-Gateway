"""Audit sink adapters (JSONL default, SQLite durable; Postgres/OTel later)."""

from __future__ import annotations

from agent_policy_gateway.adapters.audit.jsonl import JsonlAuditSink
from agent_policy_gateway.adapters.audit.sqlite import SqliteAuditSink
from agent_policy_gateway.core.audit_sink import AuditSink

__all__ = ["AuditSink", "JsonlAuditSink", "SqliteAuditSink", "build_audit_sink"]

_SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3")


def build_audit_sink(target: str) -> AuditSink:
    """Pick an audit sink from a target string.

    - ``sqlite:///path`` / ``sqlite://path`` or a ``*.db``/``*.sqlite`` path
      → durable SQLite sink.
    - anything else (e.g. ``apg-audit.jsonl``) → append-only JSONL sink.
    """
    spec = target.strip()
    lowered = spec.lower()
    if lowered.startswith("sqlite:///"):
        return SqliteAuditSink(spec[len("sqlite:///") :])
    if lowered.startswith("sqlite://"):
        return SqliteAuditSink(spec[len("sqlite://") :])
    if lowered.endswith(_SQLITE_SUFFIXES):
        return SqliteAuditSink(spec)
    return JsonlAuditSink(spec)
