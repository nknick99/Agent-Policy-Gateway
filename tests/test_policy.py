"""Tests for the deterministic policy evaluation engine."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agent_policy_gateway.models import Decision
from agent_policy_gateway.policy import PolicyEvaluator, PolicyResult


# --- Fixtures ---


def _make_policy_file(policy_data: dict[str, Any]) -> str:
    """Write policy data to a temp file and return the path."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump(policy_data, f)
    f.close()
    return f.name


def _valid_policy() -> dict[str, Any]:
    """Return a valid minimal policy document."""
    return {
        "version": 1,
        "default": "deny",
        "caller_auth": {
            "method": "shared_token",
            "token_env": "APG_AGENT_TOKEN",
        },
        "session_limits": {
            "max_calls_per_session": 200,
            "max_records_per_session": 5000,
        },
        "tools": {
            "db.query": {
                "allow": True,
                "operations": ["select"],
                "tables": ["users", "orders", "products"],
                "constraints": {"limit": {"max": 100}},
                "deny_keywords": ["DROP", "DELETE", "UPDATE", "INSERT"],
            },
            "http.post": {
                "allow": True,
                "operations": ["POST"],
                "tables": [],
                "constraints": {},
                "deny_keywords": ["password", "secret"],
                "destination_whitelist": ["https://api.example.com"],
                "deny_destinations": ["169.254.169.254"],
            },
            "disabled.tool": {
                "allow": False,
                "operations": [],
                "tables": [],
                "deny_keywords": [],
            },
        },
    }


@pytest.fixture
def policy_path() -> str:
    """Create a valid policy file and return its path."""
    return _make_policy_file(_valid_policy())


@pytest.fixture
def evaluator(policy_path: str) -> PolicyEvaluator:
    """Create a PolicyEvaluator with a valid policy."""
    return PolicyEvaluator(policy_path=policy_path)


# --- Startup/Init Tests ---


class TestPolicyEvaluatorInit:
    """Tests for PolicyEvaluator initialization and startup validation."""

    def test_loads_valid_policy(self, policy_path: str) -> None:
        """PolicyEvaluator loads a valid policy file without error."""
        evaluator = PolicyEvaluator(policy_path=policy_path)
        assert evaluator.policy is not None
        assert evaluator.policy.default == "deny"

    def test_missing_policy_file_exits(self) -> None:
        """Requirement 10.2: Missing policy file → terminate with non-zero exit."""
        with pytest.raises(SystemExit) as exc_info:
            PolicyEvaluator(policy_path="/nonexistent/path/policy.json")
        assert exc_info.value.code != 0

    def test_unparseable_policy_file_exits(self, tmp_path: Path) -> None:
        """Requirement 10.2: Unparseable policy file → terminate."""
        bad_file = tmp_path / "bad_policy.json"
        bad_file.write_text("not valid json {{{", encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            PolicyEvaluator(policy_path=str(bad_file))
        assert exc_info.value.code != 0

    def test_default_not_deny_exits(self, tmp_path: Path) -> None:
        """Requirement 10.3: default != 'deny' → terminate."""
        policy = _valid_policy()
        # The Pydantic model enforces Literal["deny"], so we bypass validation
        # by testing with invalid raw data that would fail validation
        bad_file = tmp_path / "bad_default.json"
        policy_raw = policy.copy()
        policy_raw["default"] = "allow"
        bad_file.write_text(json.dumps(policy_raw), encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            PolicyEvaluator(policy_path=str(bad_file))
        assert exc_info.value.code != 0

    def test_policy_is_frozen(self, evaluator: PolicyEvaluator) -> None:
        """Requirement 11.1: Policy stored as frozen read-only structure."""
        # The tools map should be a MappingProxyType (read-only)
        with pytest.raises(TypeError):
            evaluator._tools_map["new_tool"] = None  # type: ignore[index]

    def test_policy_document_is_immutable(self, evaluator: PolicyEvaluator) -> None:
        """Requirement 11.5: Any attempt to mutate policy model raises error."""
        with pytest.raises(ValidationError):
            evaluator.policy.version = 99  # type: ignore[misc]

    def test_tool_config_is_immutable(self, evaluator: PolicyEvaluator) -> None:
        """Requirement 11.5: ToolConfig cannot be mutated after load."""
        tool = evaluator.policy.tools["db.query"]
        with pytest.raises(ValidationError):
            tool.allow = False  # type: ignore[misc]

    def test_session_limits_is_immutable(self, evaluator: PolicyEvaluator) -> None:
        """Requirement 11.5: SessionLimits cannot be mutated after load."""
        with pytest.raises(ValidationError):
            evaluator.policy.session_limits.max_calls_per_session = 9999  # type: ignore[misc]

    def test_startup_log_emitted(
        self, policy_path: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Requirement 11.1: Startup log confirms policy loaded as immutable."""
        import logging

        with caplog.at_level(logging.INFO, logger="agent_policy_gateway.policy"):
            PolicyEvaluator(policy_path=policy_path)
        assert any("Policy loaded as immutable" in msg for msg in caplog.messages)


# --- Evaluation Order Tests ---


class TestToolLookup:
    """Requirement 3.1: Method not in tools map → DENY 'tool_not_listed'."""

    def test_unknown_method_denied(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate("unknown.method", {})
        assert result.decision == Decision.DENY
        assert result.rule_matched == "tool_not_listed"
        assert result.tool_config is None

    def test_empty_method_denied(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate("", {})
        assert result.decision == Decision.DENY
        assert result.rule_matched == "tool_not_listed"


class TestAllowFlag:
    """Requirement 3.2: Tool allow=false → DENY 'tool_disabled'."""

    def test_disabled_tool_denied(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate("disabled.tool", {})
        assert result.decision == Decision.DENY
        assert result.rule_matched == "tool_disabled"


class TestOperationCheck:
    """Requirement 3.3: Operation not in operations allowlist → DENY."""

    def test_disallowed_operation_denied(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate("db.query", {"op": "delete"})
        assert result.decision == Decision.DENY
        assert result.rule_matched == "operation_not_allowed"

    def test_allowed_operation_passes(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate(
            "db.query", {"op": "select", "table": "users", "max": 10}
        )
        assert result.decision == Decision.ALLOW

    def test_skip_operation_check_when_no_op_param(
        self, evaluator: PolicyEvaluator
    ) -> None:
        """Requirement 3.10: Skip check if param not present."""
        result = evaluator.evaluate("db.query", {"table": "users"})
        assert result.decision == Decision.ALLOW


class TestResourceScope:
    """Requirement 3.4: Resource not in tables list → DENY."""

    def test_disallowed_table_denied(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate(
            "db.query", {"op": "select", "table": "secret_data"}
        )
        assert result.decision == Decision.DENY
        assert result.rule_matched == "resource_out_of_scope"

    def test_allowed_table_passes(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate("db.query", {"op": "select", "table": "orders"})
        assert result.decision == Decision.ALLOW

    def test_skip_resource_check_when_no_table_param(
        self, evaluator: PolicyEvaluator
    ) -> None:
        """Requirement 3.10: Skip check if param not present."""
        result = evaluator.evaluate("db.query", {"op": "select"})
        assert result.decision == Decision.ALLOW

    def test_skip_resource_check_when_tables_list_empty(
        self, evaluator: PolicyEvaluator
    ) -> None:
        """http.post has empty tables list, so resource check is skipped."""
        result = evaluator.evaluate(
            "http.post", {"op": "POST", "table": "anything"}
        )
        assert result.decision == Decision.ALLOW


class TestConstraints:
    """Requirement 3.5: Numeric param exceeds constraint max → DENY."""

    def test_exceeding_max_denied(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate(
            "db.query", {"op": "select", "table": "users", "max": 200}
        )
        assert result.decision == Decision.DENY
        assert result.rule_matched == "constraint_violated"

    def test_within_max_passes(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate(
            "db.query", {"op": "select", "table": "users", "max": 50}
        )
        assert result.decision == Decision.ALLOW

    def test_equal_to_max_passes(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate(
            "db.query", {"op": "select", "table": "users", "max": 100}
        )
        assert result.decision == Decision.ALLOW

    def test_non_numeric_param_not_checked(self, evaluator: PolicyEvaluator) -> None:
        """Non-numeric values for constraint params should not trigger deny."""
        result = evaluator.evaluate(
            "db.query", {"op": "select", "table": "users", "max": "many"}
        )
        assert result.decision == Decision.ALLOW


class TestDenyKeywords:
    """Requirement 3.6: Deny keyword found → DENY 'deny_keyword_found'."""

    def test_keyword_found_denied(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate(
            "db.query",
            {"op": "select", "table": "users", "query": "DROP TABLE users"},
        )
        assert result.decision == Decision.DENY
        assert result.rule_matched == "deny_keyword_found"

    def test_keyword_case_insensitive(self, evaluator: PolicyEvaluator) -> None:
        """Case-insensitive substring match."""
        result = evaluator.evaluate(
            "db.query",
            {"op": "select", "table": "users", "query": "drop table users"},
        )
        assert result.decision == Decision.DENY
        assert result.rule_matched == "deny_keyword_found"

    def test_keyword_as_substring(self, evaluator: PolicyEvaluator) -> None:
        """Keyword detected even as a substring."""
        result = evaluator.evaluate(
            "db.query",
            {"op": "select", "table": "users", "query": "xDROPx"},
        )
        assert result.decision == Decision.DENY
        assert result.rule_matched == "deny_keyword_found"

    def test_no_keyword_passes(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate(
            "db.query",
            {"op": "select", "table": "users", "query": "SELECT * FROM users"},
        )
        assert result.decision == Decision.ALLOW

    def test_non_string_params_not_checked(self, evaluator: PolicyEvaluator) -> None:
        """Non-string params should not be checked for keywords."""
        result = evaluator.evaluate(
            "db.query",
            {"op": "select", "table": "users", "count": 42},
        )
        assert result.decision == Decision.ALLOW


class TestAllowDecision:
    """Requirement 3.7: All checks pass → ALLOW with matched tool config."""

    def test_allow_includes_tool_config(self, evaluator: PolicyEvaluator) -> None:
        result = evaluator.evaluate(
            "db.query", {"op": "select", "table": "users", "max": 50}
        )
        assert result.decision == Decision.ALLOW
        assert result.tool_config is not None
        assert result.tool_config["allow"] is True
        assert "select" in result.tool_config["operations"]


class TestEvaluationOrder:
    """Requirement 3.8: Fixed eval order, halt on first DENY."""

    def test_tool_not_listed_halts_before_operation_check(
        self, evaluator: PolicyEvaluator
    ) -> None:
        """Tool lookup fails first, operation never checked."""
        result = evaluator.evaluate("nonexistent", {"op": "delete"})
        assert result.rule_matched == "tool_not_listed"

    def test_tool_disabled_halts_before_operation_check(
        self, evaluator: PolicyEvaluator
    ) -> None:
        """Allow flag fails, operation never checked."""
        result = evaluator.evaluate("disabled.tool", {"op": "anything"})
        assert result.rule_matched == "tool_disabled"

    def test_operation_halts_before_resource_check(
        self, evaluator: PolicyEvaluator
    ) -> None:
        """Operation check fails, resource scope never checked."""
        result = evaluator.evaluate(
            "db.query", {"op": "delete", "table": "secret_data"}
        )
        assert result.rule_matched == "operation_not_allowed"

    def test_resource_halts_before_constraint_check(
        self, evaluator: PolicyEvaluator
    ) -> None:
        """Resource scope fails, constraints never checked."""
        result = evaluator.evaluate(
            "db.query", {"op": "select", "table": "secret_data", "max": 999}
        )
        assert result.rule_matched == "resource_out_of_scope"


class TestDeterminism:
    """Requirement 3.9: Deterministic results for identical inputs."""

    def test_same_input_same_output(self, evaluator: PolicyEvaluator) -> None:
        params = {"op": "select", "table": "users", "max": 50}
        result1 = evaluator.evaluate("db.query", params)
        result2 = evaluator.evaluate("db.query", params)
        assert result1.decision == result2.decision
        assert result1.rule_matched == result2.rule_matched
        assert result1.reason == result2.reason

    def test_deny_deterministic(self, evaluator: PolicyEvaluator) -> None:
        params = {"op": "delete", "table": "users"}
        result1 = evaluator.evaluate("db.query", params)
        result2 = evaluator.evaluate("db.query", params)
        assert result1.decision == result2.decision
        assert result1.rule_matched == result2.rule_matched
