"""State adapters — shared session/quota state (in-memory default, Redis for HA)."""

from __future__ import annotations

import os

from agent_policy_gateway.adapters.state.redis_store import RedisSessionStore
from agent_policy_gateway.core.session import SessionManager, SessionStore

__all__ = ["RedisSessionStore", "build_session_store"]


def build_session_store() -> SessionStore:
    """Pick a session store from the environment.

    `APG_REDIS_URL` selects the Redis store (shared across replicas); otherwise
    the in-memory store is used. `APG_SESSION_TTL_SECONDS` optionally expires
    idle Redis sessions.
    """
    url = os.environ.get("APG_REDIS_URL")
    if url:
        ttl = os.environ.get("APG_SESSION_TTL_SECONDS")
        return RedisSessionStore.from_url(url, ttl_seconds=int(ttl) if ttl else None)
    return SessionManager()
