"""Tests for Agent Policy Gateway authentication module."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from agent_policy_gateway.adapters.identity.shared_token import _TOKEN_ENV_VAR, authenticate_caller, validate_startup


class TestAuthenticateCaller:
    """Tests for authenticate_caller function."""

    def test_valid_token_returns_true(self):
        """Matching token should authenticate successfully."""
        with patch.dict(os.environ, {_TOKEN_ENV_VAR: "secret-token-123"}):
            assert authenticate_caller("secret-token-123") is True

    def test_invalid_token_returns_false(self):
        """Non-matching token should fail authentication."""
        with patch.dict(os.environ, {_TOKEN_ENV_VAR: "secret-token-123"}):
            assert authenticate_caller("wrong-token") is False

    def test_empty_provided_token_returns_false(self):
        """Empty provided token should fail immediately."""
        with patch.dict(os.environ, {_TOKEN_ENV_VAR: "secret-token-123"}):
            assert authenticate_caller("") is False

    def test_none_provided_token_returns_false(self):
        """None provided token should fail immediately."""
        with patch.dict(os.environ, {_TOKEN_ENV_VAR: "secret-token-123"}):
            assert authenticate_caller(None) is False

    def test_missing_env_var_returns_false(self):
        """Missing environment variable should fail authentication."""
        env = os.environ.copy()
        env.pop(_TOKEN_ENV_VAR, None)
        with patch.dict(os.environ, env, clear=True):
            assert authenticate_caller("any-token") is False

    def test_empty_env_var_returns_false(self):
        """Empty environment variable should fail authentication."""
        with patch.dict(os.environ, {_TOKEN_ENV_VAR: ""}):
            assert authenticate_caller("any-token") is False

    def test_uses_constant_time_comparison(self):
        """Verify hmac.compare_digest is used (constant-time)."""
        with patch.dict(os.environ, {_TOKEN_ENV_VAR: "token"}):
            with patch("agent_policy_gateway.adapters.identity.shared_token.hmac.compare_digest", return_value=True) as mock_cmp:
                result = authenticate_caller("token")
                mock_cmp.assert_called_once_with("token", "token")
                assert result is True


class TestValidateStartup:
    """Tests for validate_startup function."""

    def test_valid_token_env_passes(self):
        """Should not raise when token env var is properly set."""
        with patch.dict(os.environ, {_TOKEN_ENV_VAR: "valid-token"}):
            # Should not raise
            validate_startup()

    def test_missing_env_var_raises_system_exit(self):
        """Should raise SystemExit when token env var is missing."""
        env = os.environ.copy()
        env.pop(_TOKEN_ENV_VAR, None)
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(SystemExit) as exc_info:
                validate_startup()
            assert exc_info.value.code == 1

    def test_empty_env_var_raises_system_exit(self):
        """Should raise SystemExit when token env var is empty."""
        with patch.dict(os.environ, {_TOKEN_ENV_VAR: ""}):
            with pytest.raises(SystemExit) as exc_info:
                validate_startup()
            assert exc_info.value.code == 1
