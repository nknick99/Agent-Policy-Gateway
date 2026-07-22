"""Unit tests for the stdio transport's message router.

`route_message` is where all policy logic for `apg wrap` lives, so it is tested
exhaustively here without spawning a subprocess. The end-to-end plumbing is
covered separately in tests/integration/test_wrap_e2e.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_policy_gateway.adapters.transports.stdio import route_message
from agent_policy_gateway.core.policy import PolicyEvaluator, load_policy_document

POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.json"


@pytest.fixture()
def evaluator() -> PolicyEvaluator:
    return PolicyEvaluator.from_document(load_policy_document(str(POLICY_PATH)))


def _call(name: str, arguments: dict, req_id: int = 1) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    ).encode()


class TestPassThrough:
    def test_initialize_forwarded(self, evaluator):
        line = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode()
        result = route_message(line, evaluator)
        assert result.forward is True
        assert result.outcome == "PASS_THROUGH"
        assert result.method is None

    def test_tools_list_forwarded(self, evaluator):
        line = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
        assert route_message(line, evaluator).forward is True

    def test_notification_forwarded(self, evaluator):
        line = json.dumps({"jsonrpc": "2.0", "method": "notifications/x"}).encode()
        assert route_message(line, evaluator).forward is True

    def test_non_json_forwarded(self, evaluator):
        result = route_message(b"not json\n", evaluator)
        assert result.forward is True
        assert result.outcome == "PASS_THROUGH"


class TestEnforcement:
    def test_allowed_call_forwarded(self, evaluator):
        result = route_message(_call("db.query", {"op": "select", "query": "SELECT 1"}), evaluator)
        assert result.forward is True
        assert result.outcome == "ALLOW"
        assert result.method == "db.query"
        assert result.response is None

    def test_denied_call_blocked_with_error(self, evaluator):
        result = route_message(_call("db.query", {"op": "drop"}, req_id=7), evaluator)
        assert result.forward is False
        assert result.outcome == "DENY"
        assert result.reason is not None
        # A JSON-RPC error is returned to the client with the original id.
        error = json.loads(result.response)
        assert error["id"] == 7
        assert "Policy denied" in error["error"]["message"]

    def test_unknown_tool_denied(self, evaluator):
        result = route_message(_call("fs.read", {"path": "/etc/passwd"}), evaluator)
        assert result.forward is False
        assert result.outcome == "DENY"

    def test_egress_whitelisted_allowed(self, evaluator):
        result = route_message(
            _call("http.get", {"op": "GET", "url": "https://api.example.com/x"}), evaluator
        )
        assert result.forward is True
        assert result.outcome == "ALLOW"

    def test_egress_non_whitelisted_denied(self, evaluator):
        result = route_message(
            _call("http.get", {"op": "GET", "url": "https://evil.example.net/x"}), evaluator
        )
        assert result.forward is False
        assert "Egress denied" in result.reason


class TestAuditMode:
    def test_denied_call_forwarded_but_flagged(self, evaluator):
        result = route_message(_call("db.query", {"op": "drop"}), evaluator, mode="audit")
        # Audit mode logs the denial but still forwards it.
        assert result.forward is True
        assert result.outcome == "DENY"
        assert result.response is None


class TestAttemptSummary:
    def test_summary_populated_for_learning_mode(self, evaluator):
        result = route_message(
            _call("http.get", {"op": "GET", "url": "https://evil.example.net/x"}), evaluator
        )
        assert result.attempt["op"] == "GET"
        assert result.attempt["destination"] == "https://evil.example.net/x"
