"""Tests for operator auth — argon2 password verification, no defaults (D8)."""

from __future__ import annotations

import pytest
from argon2 import PasswordHasher

from agent_policy_gateway.auth_service.provider import LocalAuthProvider


@pytest.fixture()
def provider():
    return LocalAuthProvider()


@pytest.fixture()
def configured(monkeypatch):
    """Configure an operator with an argon2-hashed password."""
    monkeypatch.setenv("APG_OPERATOR_EMAIL", "admin@apg.dev")
    monkeypatch.setenv("APG_OPERATOR_WORKSPACE", "apg")
    monkeypatch.setenv("APG_OPERATOR_PASSWORD_HASH", PasswordHasher().hash("s3cret"))


class TestArgon2Auth:
    def test_correct_credentials_succeed(self, provider, configured):
        user = provider.authenticate("apg", "admin@apg.dev", "s3cret")
        assert user is not None
        assert user.email == "admin@apg.dev"
        assert user.role == "operator"

    def test_wrong_password_fails(self, provider, configured):
        assert provider.authenticate("apg", "admin@apg.dev", "wrong") is None

    def test_wrong_email_fails(self, provider, configured):
        assert provider.authenticate("apg", "intruder@apg.dev", "s3cret") is None

    def test_wrong_workspace_fails(self, provider, configured):
        assert provider.authenticate("other", "admin@apg.dev", "s3cret") is None


class TestNoDefaultCredentials:
    def test_unconfigured_operator_cannot_authenticate(self, provider, monkeypatch):
        # No operator env set — the old code accepted admin@apg.dev/apg-demo/apg.
        for var in (
            "APG_OPERATOR_EMAIL",
            "APG_OPERATOR_WORKSPACE",
            "APG_OPERATOR_PASSWORD_HASH",
            "APG_OPERATOR_PASSWORD",
        ):
            monkeypatch.delenv(var, raising=False)
        assert provider.authenticate("apg", "admin@apg.dev", "apg-demo") is None

    def test_identity_without_password_fails_closed(self, provider, monkeypatch):
        monkeypatch.setenv("APG_OPERATOR_EMAIL", "admin@apg.dev")
        monkeypatch.setenv("APG_OPERATOR_WORKSPACE", "apg")
        monkeypatch.delenv("APG_OPERATOR_PASSWORD_HASH", raising=False)
        monkeypatch.delenv("APG_OPERATOR_PASSWORD", raising=False)
        assert provider.authenticate("apg", "admin@apg.dev", "anything") is None


class TestPlaintextDevFallback:
    def test_plaintext_password_still_works_for_dev(self, provider, monkeypatch):
        monkeypatch.setenv("APG_OPERATOR_EMAIL", "admin@apg.dev")
        monkeypatch.setenv("APG_OPERATOR_WORKSPACE", "apg")
        monkeypatch.delenv("APG_OPERATOR_PASSWORD_HASH", raising=False)
        monkeypatch.setenv("APG_OPERATOR_PASSWORD", "devpass")
        assert provider.authenticate("apg", "admin@apg.dev", "devpass") is not None
        assert provider.authenticate("apg", "admin@apg.dev", "nope") is None
