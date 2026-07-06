"""Agent Policy Gateway authentication module.

Provides caller authentication via shared bearer token with constant-time
comparison to prevent timing attacks. Refuses to start if the expected
token environment variable is not configured.
"""

from __future__ import annotations

import hmac
import os
import sys


# Environment variable that holds the expected agent token
_TOKEN_ENV_VAR = "APG_AGENT_TOKEN"


def authenticate_caller(provided_token: str) -> bool:
    """Verify the agent's identity via shared token.

    Uses hmac.compare_digest for constant-time comparison to prevent
    timing side-channel attacks.

    Args:
        provided_token: The raw token value extracted from the Authorization
            header (without the "Bearer " prefix).

    Returns:
        True if and only if provided_token matches the expected token
        stored in the APG_AGENT_TOKEN environment variable.
        False for empty, None, or mismatched tokens.
    """
    if not provided_token:
        return False

    expected_token = os.environ.get(_TOKEN_ENV_VAR, "")
    if not expected_token:
        return False

    return hmac.compare_digest(provided_token, expected_token)


def validate_startup() -> None:
    """Check that the required token environment variable is set at startup.

    Raises SystemExit with a non-zero exit code if APG_AGENT_TOKEN
    is missing or empty, refusing to start the proxy.
    """
    token = os.environ.get(_TOKEN_ENV_VAR, "")
    if not token:
        print(
            f"FATAL: Environment variable {_TOKEN_ENV_VAR} is not set or empty. "
            "Agent Policy Gateway refuses to start without a configured agent token.",
            file=sys.stderr,
        )
        raise SystemExit(1)
