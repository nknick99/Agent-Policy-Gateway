"""Tests for the `apg audit tail` presentation layer."""

from __future__ import annotations

from agent_policy_gateway.cli import _format_audit_event


def test_format_includes_key_fields():
    line = _format_audit_event(
        {
            "timestamp": "2026-07-21T00:00:00.000Z",
            "outcome": "DENY",
            "method": "db.query",
            "latency_ms": 0.42,
            "reason": "operation 'drop' not allowed",
        }
    )
    assert "2026-07-21T00:00:00.000Z" in line
    assert "DENY" in line
    assert "db.query" in line
    assert "0.42ms" in line
    assert "operation 'drop' not allowed" in line


def test_format_tolerates_missing_fields():
    # A pass-through event has no method/reason/latency.
    line = _format_audit_event({"timestamp": "t", "outcome": "PASS_THROUGH"})
    assert "PASS_THROUGH" in line
    assert "-" in line  # method rendered as a dash
