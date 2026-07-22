"""Identity provider adapters — resolve a bearer token into an Identity.

Two implementations behind the one `IdentityProvider` port:

- `SharedTokenIdentityProvider`: the original single-secret model — one token,
  one identity permitted every tool. Used when a policy declares no agents.
- `MultiAgentIdentityProvider`: many named agents, each with its own token and
  tool scope, built from a policy's `agents` map.

Tokens are read from the environment live (not cached at build time), matching
the existing shared-token behavior and keeping secrets out of the policy file.
An OIDC/JWT provider slots in later behind the same port.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass

from agent_policy_gateway.core.identity import Identity, IdentityProvider
from agent_policy_gateway.core.models import PolicyDocument

# Sentinel in an agent's tool list meaning "every tool".
_ALL_TOOLS = "*"


def _allowed_tools(tools: list[str]) -> frozenset[str] | None:
    """Translate a policy tool list into an Identity's allowed_tools."""
    if _ALL_TOOLS in tools:
        return None
    return frozenset(tools)


class SharedTokenIdentityProvider:
    """Single shared token → a single identity permitted every tool."""

    def __init__(self, token_env: str = "APG_AGENT_TOKEN", agent_id: str = "agent") -> None:
        self._token_env = token_env
        self._agent_id = agent_id

    def authenticate(self, token: str) -> Identity | None:
        if not token:
            return None
        expected = os.environ.get(self._token_env, "")
        if not expected:
            return None
        if hmac.compare_digest(token, expected):
            return Identity(agent_id=self._agent_id, allowed_tools=None)
        return None


@dataclass(frozen=True)
class _Agent:
    agent_id: str
    token_env: str
    allowed_tools: frozenset[str] | None


class MultiAgentIdentityProvider:
    """Many named agents, each with its own token env var and tool scope."""

    def __init__(self, agents: list[_Agent]) -> None:
        self._agents = agents

    def authenticate(self, token: str) -> Identity | None:
        if not token:
            return None
        match: Identity | None = None
        # Check every agent (no early return) so the work done doesn't reveal
        # which agent, if any, a token belongs to.
        for agent in self._agents:
            expected = os.environ.get(agent.token_env, "")
            if expected and hmac.compare_digest(token, expected):
                match = Identity(agent_id=agent.agent_id, allowed_tools=agent.allowed_tools)
        return match


def build_identity_provider(policy: PolicyDocument) -> IdentityProvider:
    """Pick an identity provider from a policy.

    A policy with an `agents` map gets per-agent identities; otherwise the
    single shared-token model (backward compatible).
    """
    if policy.agents:
        agents = [
            _Agent(
                agent_id=agent_id,
                token_env=config.token_env,
                allowed_tools=_allowed_tools(config.tools),
            )
            for agent_id, config in policy.agents.items()
        ]
        return MultiAgentIdentityProvider(agents)
    return SharedTokenIdentityProvider(token_env=policy.caller_auth.token_env)
