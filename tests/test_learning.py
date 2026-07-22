"""Tests for learning mode — `apg policy suggest`."""

from __future__ import annotations

from pathlib import Path

from agent_policy_gateway.core.learning import (
    load_audit_events,
    suggest_entries,
)
from agent_policy_gateway.core.policy import load_policy_document

POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.json"


def _deny(method, **fields):
    return {"outcome": "DENY", "method": method, **fields}


class TestLoadAuditEvents:
    def test_parses_jsonl_and_skips_junk(self, tmp_path):
        f = tmp_path / "audit.jsonl"
        f.write_text(
            '{"outcome": "DENY", "method": "fs.read"}\n'
            "\n"
            "not-json\n"
            '{"outcome": "ALLOW", "method": "db.query"}\n'
        )
        events = load_audit_events(str(f))
        assert len(events) == 2
        assert events[0]["method"] == "fs.read"

    def test_missing_file_returns_empty(self, tmp_path):
        assert load_audit_events(str(tmp_path / "nope.jsonl")) == []


class TestSuggestEntries:
    def test_new_tool_gets_full_entry(self):
        events = [_deny("fs.read", op="read")]
        suggestions = suggest_entries(events, policy=None)
        assert suggestions == {"fs.read": {"allow": True, "operations": ["read"]}}

    def test_only_denials_are_considered(self):
        events = [
            {"outcome": "ALLOW", "method": "db.query", "op": "select"},
            _deny("fs.read", op="read"),
        ]
        suggestions = suggest_entries(events, policy=None)
        assert set(suggestions) == {"fs.read"}

    def test_auth_failures_without_method_are_skipped(self):
        events = [{"outcome": "DENY", "method": None, "reason": "Authentication failed"}]
        assert suggest_entries(events, policy=None) == {}

    def test_destination_normalized_to_origin(self):
        events = [_deny("http.get", op="GET", destination="https://vendor.example.com/v1/x?y=1")]
        suggestions = suggest_entries(events, policy=None)
        assert suggestions["http.get"]["destination_whitelist"] == [
            "https://vendor.example.com"
        ]

    def test_operations_deduped_and_sorted(self):
        events = [_deny("db.write", op="update"), _deny("db.write", op="delete"),
                  _deny("db.write", op="update")]
        suggestions = suggest_entries(events, policy=None)
        assert suggestions["db.write"]["operations"] == ["delete", "update"]

    def test_existing_allowed_tool_gets_additive_delta(self):
        # policy.json allows db.query for op=select; a denied op=update should
        # yield a delta that unions the existing + new operations.
        policy = load_policy_document(str(POLICY_PATH))
        events = [_deny("db.query", op="update")]
        suggestions = suggest_entries(events, policy=policy)
        assert suggestions["db.query"]["operations"] == ["select", "update"]

    def test_already_permitted_call_yields_no_suggestion(self):
        # A denial whose op is already in the allowlist adds nothing new.
        policy = load_policy_document(str(POLICY_PATH))
        events = [_deny("db.query", op="select")]
        assert suggest_entries(events, policy=policy) == {}

    def test_new_whitelist_entry_unions_with_existing(self):
        policy = load_policy_document(str(POLICY_PATH))
        events = [_deny("http.get", op="GET", destination="https://new.example.com/data")]
        wl = suggest_entries(events, policy=policy)["http.get"]["destination_whitelist"]
        assert "https://new.example.com" in wl
        assert "https://api.example.com" in wl  # existing preserved
