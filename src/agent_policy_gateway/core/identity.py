"""Identity port — who is calling, and which tools they may call.

The gateway's original model was a single shared token: one secret, one policy
for everyone. Real deployments run many agents against the same gateway and
need each one to have its own identity and its own tool scope — so a reporting
agent can read but a provisioning agent can write, and every audit line says
*which* agent did it.

This module defines the port. Adapters resolve a credential (a bearer token
today; an OIDC/JWT subject later) into an :class:`Identity`, which carries the
agent's id and the set of tools it is authorized to call. Per-tool *rules*
(operations, tables, egress) still come from the one policy engine; identity
decides only *which tools this agent may reach at all*.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class Identity:
    """An authenticated caller and the tools it is permitted to call.

    Attributes:
        agent_id: Stable identifier recorded in the audit trail.
        allowed_tools: The tool names this agent may call, or ``None`` for
            "all tools" (the shared-token / single-agent case).
    """

    agent_id: str
    allowed_tools: frozenset[str] | None = None

    def may_call(self, tool: str) -> bool:
        """Whether this identity is authorized to call ``tool`` at all."""
        return self.allowed_tools is None or tool in self.allowed_tools


@runtime_checkable
class IdentityProvider(Protocol):
    """Resolves a credential into an :class:`Identity`."""

    def authenticate(self, token: str) -> Identity | None:
        """Return the caller's identity, or ``None`` if the token is unknown."""
        ...
