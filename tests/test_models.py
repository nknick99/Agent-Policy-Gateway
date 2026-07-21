"""Tests for Agent Policy Gateway data models and shared types."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agent_policy_gateway.core.models import (
    AuditDecision,
    CallerAuth,
    Constraints,
    Decision,
    PolicyDocument,
    SessionLimits,
    SessionState,
    ToolConfig,
)

# --- Enum Tests ---


class TestDecision:
    def test_allow_value(self):
        assert Decision.ALLOW.value == "allow"

    def test_deny_value(self):
        assert Decision.DENY.value == "deny"


class TestAuditDecision:
    def test_allow_value(self):
        assert AuditDecision.ALLOW.value == "allow"

    def test_deny_value(self):
        assert AuditDecision.DENY.value == "deny"


# --- CallerAuth Tests ---


class TestCallerAuth:
    def test_valid_shared_token(self):
        auth = CallerAuth(method="shared_token")
        assert auth.method == "shared_token"
        assert auth.token_env == "APG_AGENT_TOKEN"

    def test_custom_token_env(self):
        auth = CallerAuth(method="shared_token", token_env="MY_TOKEN")
        assert auth.token_env == "MY_TOKEN"

    def test_invalid_method_rejected(self):
        with pytest.raises(ValidationError):
            CallerAuth(method="oauth2")


# --- SessionLimits Tests ---


class TestSessionLimits:
    def test_defaults(self):
        limits = SessionLimits()
        assert limits.max_calls_per_session == 200
        assert limits.max_records_per_session == 5000

    def test_custom_values(self):
        limits = SessionLimits(max_calls_per_session=50, max_records_per_session=1000)
        assert limits.max_calls_per_session == 50
        assert limits.max_records_per_session == 1000

    def test_zero_calls_rejected(self):
        with pytest.raises(ValidationError):
            SessionLimits(max_calls_per_session=0)

    def test_negative_records_rejected(self):
        with pytest.raises(ValidationError):
            SessionLimits(max_records_per_session=-1)


# --- Constraints Tests ---


class TestConstraints:
    def test_with_limit(self):
        c = Constraints(limit={"max": 100})
        assert c.limit == {"max": 100}

    def test_none_limit(self):
        c = Constraints()
        assert c.limit is None


# --- ToolConfig Tests ---


class TestToolConfig:
    def test_defaults(self):
        tc = ToolConfig()
        assert tc.allow is False
        assert tc.operations == []
        assert tc.tables == []
        assert tc.constraints is None
        assert tc.deny_keywords == []
        assert tc.destination_whitelist == []
        assert tc.deny_destinations == []
        assert tc.aws_role == ""
        assert tc.session_policy == {}

    def test_full_config(self):
        tc = ToolConfig(
            allow=True,
            operations=["SELECT"],
            tables=["users"],
            constraints=Constraints(limit={"max": 100}),
            deny_keywords=["DROP"],
            destination_whitelist=["api.example.com"],
            deny_destinations=["evil.com"],
            aws_role="arn:aws:iam::123456789012:role/Test",
            session_policy={"Version": "2012-10-17"},
        )
        assert tc.allow is True
        assert tc.operations == ["SELECT"]
        assert tc.constraints.limit == {"max": 100}


# --- PolicyDocument Tests ---


class TestPolicyDocument:
    def test_valid_policy(self):
        policy = PolicyDocument(
            caller_auth=CallerAuth(method="shared_token"),
            session_limits=SessionLimits(),
            tools={
                "db.query": ToolConfig(allow=True, operations=["SELECT"]),
            },
        )
        assert policy.version == 1
        assert policy.default == "deny"
        assert "db.query" in policy.tools

    def test_default_must_be_deny(self):
        with pytest.raises(ValidationError):
            PolicyDocument(
                default="allow",
                caller_auth=CallerAuth(method="shared_token"),
                session_limits=SessionLimits(),
                tools={},
            )

    def test_missing_caller_auth_rejected(self):
        with pytest.raises(ValidationError):
            PolicyDocument(session_limits=SessionLimits(), tools={})


# --- SessionState Tests ---


class TestSessionState:
    def test_initial_state(self):
        state = SessionState(session_id="sess-1", caller_identity="agent-1")
        assert state.call_count == 0
        assert state.record_count == 0
        assert state.session_id == "sess-1"
        assert state.caller_identity == "agent-1"
        assert isinstance(state.created_at, datetime)
        assert state.created_at.tzinfo == UTC

    def test_increment_calls(self):
        state = SessionState(session_id="s", caller_identity="a")
        state.increment_calls()
        assert state.call_count == 1
        state.increment_calls()
        assert state.call_count == 2

    def test_add_records(self):
        state = SessionState(session_id="s", caller_identity="a")
        state.add_records(10)
        assert state.record_count == 10
        state.add_records(5)
        assert state.record_count == 15

    def test_exceeds_limits_call_count(self):
        limits = SessionLimits(max_calls_per_session=3, max_records_per_session=100)
        state = SessionState(session_id="s", caller_identity="a")
        assert state.exceeds_limits(limits) is False
        state.call_count = 3
        assert state.exceeds_limits(limits) is True

    def test_exceeds_limits_record_count(self):
        limits = SessionLimits(max_calls_per_session=100, max_records_per_session=50)
        state = SessionState(session_id="s", caller_identity="a")
        state.record_count = 50
        assert state.exceeds_limits(limits) is True

    def test_within_limits(self):
        limits = SessionLimits(max_calls_per_session=100, max_records_per_session=5000)
        state = SessionState(session_id="s", caller_identity="a")
        state.call_count = 99
        state.record_count = 4999
        assert state.exceeds_limits(limits) is False
