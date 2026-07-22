"""Tests for OIDC/SSO operator auth (RS256 JWT validation)."""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from agent_policy_gateway.auth_service.oidc import OidcAuthProvider, build_auth_provider
from agent_policy_gateway.auth_service.provider import LocalAuthProvider

ISSUER = "https://idp.example.com/"
AUDIENCE = "apg-dashboard"


@pytest.fixture(scope="module")
def keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture()
def provider(keys):
    _, public_key = keys
    return OidcAuthProvider(
        issuer=ISSUER,
        audience=AUDIENCE,
        signing_key_resolver=lambda _token: public_key,
    )


def _make_token(private_key, **overrides):
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "email": "operator@example.com",
        "workspace": "acme",
        "role": "operator",
        "exp": int(time.time()) + 300,
        **overrides,
    }
    return jwt.encode(claims, private_key, algorithm="RS256")


class TestValidateSsoToken:
    def test_valid_token_maps_claims(self, provider, keys):
        private_key, _ = keys
        user = provider.validate_sso_token(_make_token(private_key))
        assert user is not None
        assert user.email == "operator@example.com"
        assert user.workspace == "acme"
        assert user.role == "operator"

    def test_wrong_audience_rejected(self, provider, keys):
        private_key, _ = keys
        assert provider.validate_sso_token(_make_token(private_key, aud="other")) is None

    def test_wrong_issuer_rejected(self, provider, keys):
        private_key, _ = keys
        token = _make_token(private_key, iss="https://evil.example.com/")
        assert provider.validate_sso_token(token) is None

    def test_expired_token_rejected(self, provider, keys):
        private_key, _ = keys
        assert provider.validate_sso_token(_make_token(private_key, exp=1)) is None

    def test_token_missing_email_rejected(self, provider, keys):
        private_key, _ = keys
        # jwt.encode drops None values? set email empty and remove it.
        token = _make_token(private_key, email="")
        assert provider.validate_sso_token(token) is None

    def test_token_signed_by_other_key_rejected(self, provider):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert provider.validate_sso_token(_make_token(other)) is None

    def test_password_auth_disabled(self, provider):
        assert provider.authenticate("acme", "operator@example.com", "pw") is None

    def test_default_workspace_when_claim_absent(self, keys):
        private_key, public_key = keys
        prov = OidcAuthProvider(
            issuer=ISSUER,
            audience=AUDIENCE,
            default_workspace="fallback-ws",
            signing_key_resolver=lambda _t: public_key,
        )
        token = _make_token(private_key, workspace=None)
        user = prov.validate_sso_token(token)
        assert user is not None
        assert user.workspace == "fallback-ws"


class TestFactory:
    def test_no_issuer_uses_local(self, monkeypatch):
        monkeypatch.delenv("APG_OIDC_ISSUER", raising=False)
        assert isinstance(build_auth_provider(), LocalAuthProvider)

    def test_issuer_selects_oidc(self, monkeypatch):
        monkeypatch.setenv("APG_OIDC_ISSUER", ISSUER)
        monkeypatch.setenv("APG_OIDC_AUDIENCE", AUDIENCE)
        assert isinstance(build_auth_provider(), OidcAuthProvider)
