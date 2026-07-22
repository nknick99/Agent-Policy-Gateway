"""Tests for audit sinks — JSONL default, SQLite durable, and the factory."""

from __future__ import annotations

import pytest

from agent_policy_gateway.adapters.audit import (
    JsonlAuditSink,
    SqliteAuditSink,
    build_audit_sink,
)


def _events():
    return [
        {"timestamp": "t1", "outcome": "ALLOW", "method": "db.query", "reason": None},
        {"timestamp": "t2", "outcome": "DENY", "method": "db.query", "reason": "drop"},
        {"timestamp": "t3", "outcome": "DENY", "method": "fs.read", "reason": "not listed"},
    ]


class TestFactory:
    @pytest.mark.parametrize(
        "target,cls",
        [
            ("apg-audit.jsonl", JsonlAuditSink),
            ("audit.log", JsonlAuditSink),
            ("audit.db", SqliteAuditSink),
            ("data/audit.sqlite", SqliteAuditSink),
            ("audit.sqlite3", SqliteAuditSink),
            ("sqlite:///abs/path/audit.db", SqliteAuditSink),
        ],
    )
    def test_selection(self, target, cls, tmp_path):
        # Give sqlite targets a writable location.
        if cls is SqliteAuditSink:
            target = str(tmp_path / "audit.db")
        sink = build_audit_sink(target)
        try:
            assert isinstance(sink, cls)
        finally:
            sink.close()


class _SinkContract:
    """Shared behavioural tests both sinks must satisfy."""

    def make(self, tmp_path):  # pragma: no cover - overridden
        raise NotImplementedError

    def test_write_read_roundtrip_chronological(self, tmp_path):
        sink = self.make(tmp_path)
        try:
            for event in _events():
                sink.write(event)
            read = sink.read()
            assert [e["timestamp"] for e in read] == ["t1", "t2", "t3"]
        finally:
            sink.close()

    def test_limit_returns_most_recent(self, tmp_path):
        sink = self.make(tmp_path)
        try:
            for event in _events():
                sink.write(event)
            read = sink.read(limit=2)
            assert [e["timestamp"] for e in read] == ["t2", "t3"]
        finally:
            sink.close()

    def test_outcome_filter_case_insensitive(self, tmp_path):
        sink = self.make(tmp_path)
        try:
            for event in _events():
                sink.write(event)
            read = sink.read(outcome="deny")
            assert [e["method"] for e in read] == ["db.query", "fs.read"]
        finally:
            sink.close()

    def test_read_missing_is_empty(self, tmp_path):
        sink = self.make(tmp_path)
        try:
            assert sink.read() == []
        finally:
            sink.close()


class TestJsonlSink(_SinkContract):
    def make(self, tmp_path):
        return JsonlAuditSink(str(tmp_path / "audit.jsonl"))


class TestSqliteSink(_SinkContract):
    def make(self, tmp_path):
        return SqliteAuditSink(str(tmp_path / "audit.db"))

    def test_persists_across_reopen(self, tmp_path):
        path = str(tmp_path / "audit.db")
        first = SqliteAuditSink(path)
        for event in _events():
            first.write(event)
        first.close()

        second = SqliteAuditSink(path)
        try:
            assert len(second.read()) == 3
        finally:
            second.close()

    def test_creates_parent_directory(self, tmp_path):
        sink = SqliteAuditSink(str(tmp_path / "nested" / "dir" / "audit.db"))
        try:
            sink.write(_events()[0])
            assert len(sink.read()) == 1
        finally:
            sink.close()
