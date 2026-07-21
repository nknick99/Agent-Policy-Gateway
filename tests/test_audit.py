"""Tests for agent_policy_gateway.adapters.audit.stdout module.

Covers: correlation ID generation, event emission, redaction,
decision-specific fields, exception safety, and immutability.
"""

import json
import uuid

import pytest

from agent_policy_gateway.adapters.audit.stdout import AuditEvent, AuditLogger, redact_params
from agent_policy_gateway.core.models import AuditDecision


class TestGenerateCorrelationId:
    """Requirement 9.1: Generate unique UUID for every request."""

    def test_returns_valid_uuid4(self):
        logger = AuditLogger()
        cid = logger.generate_correlation_id()
        parsed = uuid.UUID(cid, version=4)
        assert str(parsed) == cid

    def test_generates_unique_ids(self):
        logger = AuditLogger()
        ids = {logger.generate_correlation_id() for _ in range(100)}
        assert len(ids) == 100


class TestAuditEventDefaults:
    """AuditEvent dataclass default field behavior."""

    def test_default_correlation_id_is_uuid4(self):
        event = AuditEvent()
        parsed = uuid.UUID(event.correlation_id, version=4)
        assert str(parsed) == event.correlation_id

    def test_default_timestamp_is_utc_iso(self):
        event = AuditEvent()
        assert event.timestamp.endswith("+00:00") or event.timestamp.endswith("Z")

    def test_default_decision_is_deny(self):
        event = AuditEvent()
        assert event.decision == AuditDecision.DENY

    def test_unique_correlation_ids_across_events(self):
        e1 = AuditEvent()
        e2 = AuditEvent()
        assert e1.correlation_id != e2.correlation_id


class TestEmitAllowEvent:
    """Requirement 9.2: ALLOW events include role_assumed and outcome."""

    def test_allow_event_contains_required_fields(self, capsys):
        logger = AuditLogger()
        event = AuditEvent(
            correlation_id="test-cid-allow",
            caller_identity="agent-1",
            method="tools/call",
            decision=AuditDecision.ALLOW,
            rule_matched="db_query",
            role_assumed="arn:aws:iam::123:role/test",
            outcome="success",
        )
        logger.emit(event)
        captured = capsys.readouterr()
        output = json.loads(captured.out.strip())
        assert output["correlation_id"] == "test-cid-allow"
        assert output["caller_identity"] == "agent-1"
        assert output["method"] == "tools/call"
        assert output["decision"] == "allow"
        assert output["rule_matched"] == "db_query"
        assert output["role_assumed"] == "arn:aws:iam::123:role/test"
        assert output["outcome"] == "success"

    def test_allow_event_does_not_contain_denial_reason(self, capsys):
        logger = AuditLogger()
        event = AuditEvent(
            decision=AuditDecision.ALLOW,
            role_assumed="some-role",
            outcome="success",
        )
        logger.emit(event)
        captured = capsys.readouterr()
        output = json.loads(captured.out.strip())
        assert "denial_reason" not in output


class TestEmitDenyEvent:
    """Requirement 9.3: DENY events include denial_reason."""

    def test_deny_event_contains_denial_reason(self, capsys):
        logger = AuditLogger()
        event = AuditEvent(
            correlation_id="test-cid-deny",
            caller_identity="agent-2",
            method="tools/call",
            decision=AuditDecision.DENY,
            rule_matched="default_deny",
            denial_reason="tool not in allowed list",
        )
        logger.emit(event)
        captured = capsys.readouterr()
        output = json.loads(captured.out.strip())
        assert output["correlation_id"] == "test-cid-deny"
        assert output["decision"] == "deny"
        assert output["denial_reason"] == "tool not in allowed list"

    def test_deny_event_does_not_contain_role_assumed(self, capsys):
        logger = AuditLogger()
        event = AuditEvent(
            decision=AuditDecision.DENY,
            denial_reason="forbidden",
        )
        logger.emit(event)
        captured = capsys.readouterr()
        output = json.loads(captured.out.strip())
        assert "role_assumed" not in output
        assert "outcome" not in output


class TestRedactParams:
    """Requirement 9.4: Redact param values matching SECRET_PATTERNS."""

    def test_aws_key_redacted(self):
        params = {"access_key": "AKIAIOSFODNN7EXAMPLE1"}
        result = redact_params(params)
        assert result["access_key"] == "[REDACTED]"

    def test_jwt_token_redacted(self):
        params = {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"}
        result = redact_params(params)
        assert result["token"] == "[REDACTED]"

    def test_pem_key_redacted(self):
        params = {"key": "-----BEGIN RSA PRIVATE KEY-----\ndata"}
        result = redact_params(params)
        assert result["key"] == "[REDACTED]"

    def test_api_key_redacted(self):
        params = {"api_key": "sk-abcdefghijklmnopqrstuvwxyz123456"}
        result = redact_params(params)
        assert result["api_key"] == "[REDACTED]"

    def test_safe_values_preserved(self):
        params = {"name": "hello", "count": 42, "flag": True}
        result = redact_params(params)
        assert result == {"name": "hello", "count": 42, "flag": True}

    def test_nested_dict_redacted(self):
        params = {"nested": {"secret": "AKIAIOSFODNN7EXAMPLE1", "ok": "safe"}}
        result = redact_params(params)
        assert result["nested"]["secret"] == "[REDACTED]"
        assert result["nested"]["ok"] == "safe"

    def test_list_values_redacted(self):
        params = {"keys": ["AKIAIOSFODNN7EXAMPLE1", "normal"]}
        result = redact_params(params)
        assert result["keys"] == ["[REDACTED]", "normal"]

    def test_original_not_mutated(self):
        params = {"secret": "AKIAIOSFODNN7EXAMPLE1"}
        redact_params(params)
        assert params["secret"] == "AKIAIOSFODNN7EXAMPLE1"


class TestEmitExceptionSafety:
    """Requirement 9.8: emit still works on unhandled exceptions."""

    def test_emit_never_raises_on_bad_event(self):
        """Even with a totally broken event, emit should not raise."""
        logger = AuditLogger()
        # Pass something that's not an AuditEvent
        try:
            logger.emit(object())  # type: ignore
        except Exception:
            pytest.fail("emit() raised an exception")

    def test_emit_partial_on_internal_failure(self, capsys):
        """When _build_event_data fails, partial event is emitted."""
        logger = AuditLogger()

        # Create event where _build_event_data will fail
        event = AuditEvent(correlation_id="partial-test")
        # Monkey-patch to force failure in _build_event_data
        def fail_build(e):
            raise RuntimeError("simulated failure")
        logger._build_event_data = fail_build

        logger.emit(event)
        captured = capsys.readouterr()
        output = json.loads(captured.out.strip())
        assert output["correlation_id"] == "partial-test"
        assert output["error"] == "emit_failed"


class TestNoModifyDeleteInterface:
    """Requirement 9.7: AuditLogger exposes no modify/delete interface."""

    def test_no_delete_method(self):
        logger = AuditLogger()
        assert not hasattr(logger, "delete")
        assert not hasattr(logger, "remove")
        assert not hasattr(logger, "clear")

    def test_no_update_method(self):
        logger = AuditLogger()
        assert not hasattr(logger, "update")
        assert not hasattr(logger, "modify")
        assert not hasattr(logger, "edit")

    def test_only_expected_public_methods(self):
        logger = AuditLogger()
        public_methods = [m for m in dir(logger) if not m.startswith("_")]
        # Only emit and generate_correlation_id should be public
        assert set(public_methods) == {"emit", "generate_correlation_id"}


class TestExactlyOneEventPerRequest:
    """Requirement 9.6: Exactly one audit event per request."""

    def test_emit_produces_exactly_one_log_line(self, capsys):
        logger = AuditLogger()
        event = AuditEvent(
            caller_identity="test",
            method="tools/call",
            decision=AuditDecision.ALLOW,
            role_assumed="role",
            outcome="ok",
        )
        logger.emit(event)
        captured = capsys.readouterr()
        lines = [line for line in captured.out.strip().split("\n") if line.strip()]
        assert len(lines) == 1


class TestAppendOnlyOutput:
    """Requirement 9.5: Events emitted to stdout (append-only off-box)."""

    def test_output_is_valid_json(self, capsys):
        logger = AuditLogger()
        event = AuditEvent(
            caller_identity="test",
            method="tools/call",
            decision=AuditDecision.DENY,
            denial_reason="test",
        )
        logger.emit(event)
        captured = capsys.readouterr()
        # Should be parseable JSON
        parsed = json.loads(captured.out.strip())
        assert isinstance(parsed, dict)

    def test_output_contains_structured_fields(self, capsys):
        logger = AuditLogger()
        event = AuditEvent(
            correlation_id="struct-test",
            caller_identity="agent",
            method="tools/call",
            decision=AuditDecision.DENY,
            denial_reason="blocked",
        )
        logger.emit(event)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert "correlation_id" in parsed
        assert "timestamp" in parsed
        assert "level" in parsed
