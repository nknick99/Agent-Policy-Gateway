"""Identity adapters — agent caller authentication (shared token today; OIDC later)."""

from __future__ import annotations

from agent_policy_gateway.adapters.identity.providers import (
    MultiAgentIdentityProvider,
    SharedTokenIdentityProvider,
    build_identity_provider,
)

__all__ = [
    "MultiAgentIdentityProvider",
    "SharedTokenIdentityProvider",
    "build_identity_provider",
]
