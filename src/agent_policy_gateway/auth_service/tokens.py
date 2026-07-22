"""Operator session tokens — signed JWTs via PyJWT.

Uses the maintained PyJWT library (HS256) rather than a hand-rolled
implementation, so signing, base64url handling, and expiry validation are done
by vetted code. The signing secret comes from APG_JWT_SECRET; there is no static
built-in secret (a well-known key would let anyone forge operator tokens).
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

import jwt

# Default token TTL: 1 hour
DEFAULT_TTL_SECONDS = 3600

_JWT_SECRET_ENV = "APG_JWT_SECRET"
_ALGORITHM = "HS256"


def _get_secret() -> str:
    """Return the JWT signing secret.

    Prefers APG_JWT_SECRET. For local dev, falls back to a value derived from
    APG_AGENT_TOKEN (still caller-specific, not a shipped constant). Raises if
    neither is set — refusing to sign with a predictable key is the point.
    """
    secret = os.environ.get(_JWT_SECRET_ENV, "")
    if secret:
        return secret
    agent_token = os.environ.get("APG_AGENT_TOKEN", "")
    if agent_token:
        return hashlib.sha256(f"jwt-{agent_token}".encode()).hexdigest()
    raise RuntimeError(
        f"{_JWT_SECRET_ENV} (or APG_AGENT_TOKEN) must be set to sign operator tokens"
    )


def create_token(
    user_id: str,
    email: str,
    workspace: str,
    role: str = "operator",
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> str:
    """Create a signed JWT for an authenticated operator."""
    now = int(time.time())
    payload = {
        "sub": user_id,
        "email": email,
        "workspace": workspace,
        "role": role,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(payload, _get_secret(), algorithm=_ALGORITHM)


def verify_token(token: str) -> dict[str, Any] | None:
    """Verify a token's signature and expiry.

    Returns the decoded claims on success, None on any failure (bad signature,
    expired, malformed). Expiry is enforced by PyJWT.
    """
    try:
        return jwt.decode(token, _get_secret(), algorithms=[_ALGORITHM])
    except jwt.InvalidTokenError:
        return None
