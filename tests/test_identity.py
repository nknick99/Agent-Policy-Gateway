"""Tests for per-agent identity — Identity, providers, and the factory."""

from __future__ import annotations

from agent_policy_gateway.adapters.identity import (
    MultiAgentIdentityProvider,
    SharedTokenIdentityProvider,
    build_identity_provider,
)
from agent_policy_gateway.core.identity import Identity
from agent_policy_gateway.core.models import PolicyDocument


class TestIdentityScope:
    def test_all_tools_when_allowed_none(self):
        ident = Identity(agent_id="a", allowed_tools=None)
        assert ident.may_call("db.query") is True
        assert ident.may_call("anything") is True

    def test_scoped_to_listed_tools(self):
        ident = Identity(agent_id="a", allowed_tools=frozenset({"db.query"}))
        assert ident.may_call("db.query") is True
        assert ident.may_call("http.post") is False


class TestSharedTokenProvider:
    def test_valid_token_returns_identity_with_all_tools(self, monkeypatch):
        monkeypatch.setenv("APG_AGENT_TOKEN", "secret")
        provider = SharedTokenIdentityProvider("APG_AGENT_TOKEN")
        ident = provider.authenticate("secret")
        assert ident is not None
        assert ident.agent_id == "agent"
        assert ident.allowed_tools is None

    def test_wrong_token_is_none(self, monkeypatch):
        monkeypatch.setenv("APG_AGENT_TOKEN", "secret")
        assert SharedTokenIdentityProvider("APG_AGENT_TOKEN").authenticate("nope") is None

    def test_empty_token_or_unset_env_is_none(self, monkeypatch):
        monkeypatch.delenv("APG_AGENT_TOKEN", raising=False)
        provider = SharedTokenIdentityProvider("APG_AGENT_TOKEN")
        assert provider.authenticate("") is None
        assert provider.authenticate("anything") is None


def _agents_policy() -> PolicyDocument:
    return PolicyDocument.model_validate(
        {
            "version": 1,
            "default": "deny",
            "caller_auth": {"method": "shared_token"},
            "session_limits": {},
            "tools": {"db.query": {"allow": True}, "http.post": {"allow": True}},
            "agents": {
                "reporting": {"token_env": "TOK_REPORTING", "tools": ["db.query"]},
                "provisioner": {"token_env": "TOK_PROV", "tools": ["*"]},
            },
        }
    )


class TestMultiAgentProvider:
    def test_resolves_correct_agent_and_scope(self, monkeypatch):
        monkeypatch.setenv("TOK_REPORTING", "r-token")
        monkeypatch.setenv("TOK_PROV", "p-token")
        provider = build_identity_provider(_agents_policy())
        assert isinstance(provider, MultiAgentIdentityProvider)

        reporting = provider.authenticate("r-token")
        assert reporting is not None
        assert reporting.agent_id == "reporting"
        assert reporting.may_call("db.query") is True
        assert reporting.may_call("http.post") is False

        provisioner = provider.authenticate("p-token")
        assert provisioner is not None
        assert provisioner.agent_id == "provisioner"
        assert provisioner.allowed_tools is None  # ["*"] -> all tools

    def test_unknown_token_is_none(self, monkeypatch):
        monkeypatch.setenv("TOK_REPORTING", "r-token")
        monkeypatch.setenv("TOK_PROV", "p-token")
        provider = build_identity_provider(_agents_policy())
        assert provider.authenticate("intruder") is None

    def test_agent_with_unset_env_cannot_authenticate(self, monkeypatch):
        # Only provisioner's token is set; reporting's env var is missing.
        monkeypatch.delenv("TOK_REPORTING", raising=False)
        monkeypatch.setenv("TOK_PROV", "p-token")
        provider = build_identity_provider(_agents_policy())
        assert provider.authenticate("") is None
        assert provider.authenticate("p-token").agent_id == "provisioner"


class TestFactory:
    def test_no_agents_uses_shared_token(self):
        policy = PolicyDocument.model_validate(
            {
                "version": 1,
                "default": "deny",
                "caller_auth": {"method": "shared_token", "token_env": "APG_AGENT_TOKEN"},
                "session_limits": {},
                "tools": {},
            }
        )
        assert isinstance(build_identity_provider(policy), SharedTokenIdentityProvider)
