"""JWT token creation and verification.

Uses HMAC-SHA256 for token signing. The secret is loaded from
APG_JWT_SECRET environment variable.

Tokens are short-lived (1 hour default) to limit exposure.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any

# Default token TTL: 1 hour
DEFAULT_TTL_SECONDS = 3600

_JWT_SECRET_ENV = "APG_JWT_SECRET"


def _get_secret() -> str:
    """Get JWT signing secret from env, fallback to derived key for dev."""
    secret = os.environ.get(_JWT_SECRET_ENV, "")
    if not secret:
        # Dev fallback: derive from agent token or use a static dev key
        agent_token = os.environ.get("APG_AGENT_TOKEN", "dev-secret-key")
        secret = hashlib.sha256(f"jwt-{agent_token}".encode()).hexdigest()
    return secret


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _sign(payload: str) -> str:
    secret = _get_secret()
    signature = hmac.HMAC(
        secret.encode(), payload.encode(), hashlib.sha256
    ).digest()
    return _b64url_encode(signature)


def create_token(
    user_id: str,
    email: str,
    workspace: str,
    role: str = "operator",
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> str:
    """Create a signed JWT-like token.

    Returns a base64url-encoded token with format: header.payload.signature
    """
    secret = _get_secret()

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "email": email,
        "workspace": workspace,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl_seconds,
    }

    header_encoded = _b64url_encode(json.dumps(header).encode())
    payload_encoded = _b64url_encode(json.dumps(payload).encode())

    signing_input = f"{header_encoded}.{payload_encoded}"
    signature = hmac.HMAC(
        secret.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    signature_encoded = _b64url_encode(signature)

    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"


def verify_token(token: str) -> dict[str, Any] | None:
    """Verify a token's signature and expiration.

    Returns the decoded payload dict on success, None on failure.
    """
    secret = _get_secret()

    parts = token.split(".")
    if len(parts) != 3:
        return None

    header_encoded, payload_encoded, signature_encoded = parts
    signing_input = f"{header_encoded}.{payload_encoded}"

    # Verify signature
    expected_sig = hmac.HMAC(
        secret.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    try:
        provided_sig = _b64url_decode(signature_encoded)
    except Exception:
        return None

    if not hmac.compare_digest(expected_sig, provided_sig):
        return None

    # Decode payload
    try:
        payload = json.loads(_b64url_decode(payload_encoded))
    except Exception:
        return None

    # Check expiration
    if payload.get("exp", 0) < time.time():
        return None

    return payload
