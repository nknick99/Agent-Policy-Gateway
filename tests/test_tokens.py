"""Tests for operator session tokens (PyJWT, D12)."""

from __future__ import annotations

import time

import jwt
import pytest

from agent_policy_gateway.auth_service import tokens

# >= 32 bytes, as PyJWT recommends for HS256.
_SECRET = "test-signing-secret-0123456789abcdef"


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("APG_JWT_SECRET", _SECRET)


def test_round_trip_returns_claims():
    token = tokens.create_token("u1", "a@b.com", "ws", role="operator")
    claims = tokens.verify_token(token)
    assert claims is not None
    assert claims["sub"] == "u1"
    assert claims["email"] == "a@b.com"
    assert claims["workspace"] == "ws"
    assert claims["role"] == "operator"


def test_expired_token_is_rejected():
    token = tokens.create_token("u1", "a@b.com", "ws", ttl_seconds=-1)
    assert tokens.verify_token(token) is None


def test_tampered_token_is_rejected():
    token = tokens.create_token("u1", "a@b.com", "ws")
    tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    assert tokens.verify_token(tampered) is None


def test_token_signed_with_other_secret_is_rejected():
    forged = jwt.encode(
        {"sub": "attacker", "exp": int(time.time()) + 100},
        "a-different-secret-0123456789abcdef",
        algorithm="HS256",
    )
    assert tokens.verify_token(forged) is None


def test_garbage_token_is_rejected():
    assert tokens.verify_token("not-a-jwt") is None


def test_no_secret_configured_raises(monkeypatch):
    monkeypatch.delenv("APG_JWT_SECRET", raising=False)
    monkeypatch.delenv("APG_AGENT_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="must be set"):
        tokens.create_token("u1", "a@b.com", "ws")
