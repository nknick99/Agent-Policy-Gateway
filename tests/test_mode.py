"""Unit tests for kirogate.mode module."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from kirogate.mode import ModeController, OperatingMode, get_operating_mode


class TestGetOperatingMode:
    """Tests for get_operating_mode() function."""

    def test_returns_enforce_when_env_is_enforce(self):
        with patch.dict(os.environ, {"KIROGATE_MODE": "enforce"}):
            assert get_operating_mode() == OperatingMode.ENFORCE

    def test_returns_audit_when_env_is_audit(self):
        with patch.dict(os.environ, {"KIROGATE_MODE": "audit"}):
            assert get_operating_mode() == OperatingMode.AUDIT

    def test_case_insensitive_enforce(self):
        with patch.dict(os.environ, {"KIROGATE_MODE": "ENFORCE"}):
            assert get_operating_mode() == OperatingMode.ENFORCE

    def test_case_insensitive_audit(self):
        with patch.dict(os.environ, {"KIROGATE_MODE": "AUDIT"}):
            assert get_operating_mode() == OperatingMode.AUDIT

    def test_mixed_case_audit(self):
        with patch.dict(os.environ, {"KIROGATE_MODE": "Audit"}):
            assert get_operating_mode() == OperatingMode.AUDIT

    def test_defaults_to_enforce_when_missing(self):
        with patch.dict(os.environ, {}, clear=True):
            # Remove KIROGATE_MODE if present
            os.environ.pop("KIROGATE_MODE", None)
            assert get_operating_mode() == OperatingMode.ENFORCE

    def test_defaults_to_enforce_on_invalid_value(self):
        with patch.dict(os.environ, {"KIROGATE_MODE": "debug"}):
            assert get_operating_mode() == OperatingMode.ENFORCE

    def test_defaults_to_enforce_on_empty_string(self):
        with patch.dict(os.environ, {"KIROGATE_MODE": ""}):
            assert get_operating_mode() == OperatingMode.ENFORCE

    def test_handles_whitespace(self):
        with patch.dict(os.environ, {"KIROGATE_MODE": "  audit  "}):
            assert get_operating_mode() == OperatingMode.AUDIT


class TestModeController:
    """Tests for ModeController class."""

    def test_enforce_mode_properties(self):
        with patch.dict(os.environ, {"KIROGATE_MODE": "enforce"}):
            ctrl = ModeController()
            assert ctrl.mode == OperatingMode.ENFORCE
            assert ctrl.is_enforce_mode is True
            assert ctrl.is_audit_mode is False

    def test_audit_mode_properties(self):
        with patch.dict(os.environ, {"KIROGATE_MODE": "audit"}):
            ctrl = ModeController()
            assert ctrl.mode == OperatingMode.AUDIT
            assert ctrl.is_audit_mode is True
            assert ctrl.is_enforce_mode is False

    def test_should_block_policy_denial_in_enforce(self):
        """Req 12.1: Enforce mode blocks policy denials."""
        with patch.dict(os.environ, {"KIROGATE_MODE": "enforce"}):
            ctrl = ModeController()
            assert ctrl.should_block_policy_denial() is True

    def test_should_not_block_policy_denial_in_audit(self):
        """Req 12.2: Audit mode does NOT block policy denials."""
        with patch.dict(os.environ, {"KIROGATE_MODE": "audit"}):
            ctrl = ModeController()
            assert ctrl.should_block_policy_denial() is False

    def test_should_block_auth_failure_in_enforce(self):
        """Auth always blocks regardless of mode."""
        with patch.dict(os.environ, {"KIROGATE_MODE": "enforce"}):
            ctrl = ModeController()
            assert ctrl.should_block_auth_failure() is True

    def test_should_block_auth_failure_in_audit(self):
        """Req 12.6: Audit mode still enforces auth."""
        with patch.dict(os.environ, {"KIROGATE_MODE": "audit"}):
            ctrl = ModeController()
            assert ctrl.should_block_auth_failure() is True

    def test_should_block_schema_failure_in_enforce(self):
        """Schema validation always blocks regardless of mode."""
        with patch.dict(os.environ, {"KIROGATE_MODE": "enforce"}):
            ctrl = ModeController()
            assert ctrl.should_block_schema_failure() is True

    def test_should_block_schema_failure_in_audit(self):
        """Req 12.6: Audit mode still enforces schema validation."""
        with patch.dict(os.environ, {"KIROGATE_MODE": "audit"}):
            ctrl = ModeController()
            assert ctrl.should_block_schema_failure() is True

    def test_no_runtime_mode_change(self):
        """Req 12.7: No API to switch modes at runtime."""
        with patch.dict(os.environ, {"KIROGATE_MODE": "enforce"}):
            ctrl = ModeController()
            # Verify there's no setter or method to change mode
            assert not hasattr(ctrl, "set_mode")
            assert not hasattr(ctrl, "switch_mode")
            # The _mode attribute is internal; verify it can't be changed via property
            with pytest.raises(AttributeError):
                ctrl.mode = OperatingMode.AUDIT  # type: ignore[misc]


class TestBuildProposedPolicyEntry:
    """Tests for ModeController.build_proposed_policy_entry()."""

    def test_returns_entry_in_audit_mode(self):
        """Req 12.3: Emit proposed policy entry in Audit mode."""
        with patch.dict(os.environ, {"KIROGATE_MODE": "audit"}):
            ctrl = ModeController()
            entry = ctrl.build_proposed_policy_entry(
                method="db.query",
                params={"op": "select", "table": "orders", "limit": 50},
            )
            assert entry == {
                "method": "db.query",
                "operation": "select",
                "resource": "orders",
            }

    def test_returns_empty_in_enforce_mode(self):
        """No proposed entry emitted in Enforce mode."""
        with patch.dict(os.environ, {"KIROGATE_MODE": "enforce"}):
            ctrl = ModeController()
            entry = ctrl.build_proposed_policy_entry(
                method="db.query",
                params={"op": "select", "table": "orders"},
            )
            assert entry == {}

    def test_handles_missing_params_gracefully(self):
        """Proposed entry handles params without op/table keys."""
        with patch.dict(os.environ, {"KIROGATE_MODE": "audit"}):
            ctrl = ModeController()
            entry = ctrl.build_proposed_policy_entry(
                method="http.post",
                params={"url": "https://example.com"},
            )
            assert entry == {
                "method": "http.post",
                "operation": "",
                "resource": "",
            }

    def test_handles_empty_params(self):
        """Proposed entry handles empty params dict."""
        with patch.dict(os.environ, {"KIROGATE_MODE": "audit"}):
            ctrl = ModeController()
            entry = ctrl.build_proposed_policy_entry(
                method="some.method",
                params={},
            )
            assert entry == {
                "method": "some.method",
                "operation": "",
                "resource": "",
            }
