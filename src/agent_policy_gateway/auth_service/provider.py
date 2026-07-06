"""Authentication providers — swap this module for SSO.

The AuthProvider protocol defines the contract. Implement a new provider
(e.g., OIDCProvider, SAMLProvider) and register it in the router to
switch auth strategies without touching the rest of the system.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Protocol

from pydantic import BaseModel


class UserInfo(BaseModel):
    """Authenticated user identity."""

    user_id: str
    email: str
    workspace: str
    role: str = "operator"


class AuthProvider(Protocol):
    """Protocol for authentication providers.

    Implement this to add SSO, OIDC, SAML, or any other auth strategy.
    """

    def authenticate(self, workspace: str, email: str, password: str) -> UserInfo | None:
        """Authenticate a user. Returns UserInfo on success, None on failure."""
        ...

    def validate_sso_token(self, token: str) -> UserInfo | None:
        """Validate an SSO/external token. Returns UserInfo or None."""
        ...


class LocalAuthProvider:
    """Local credential-based auth for development and demo purposes.

    Reads operator credentials from environment variables.
    Replace this with OIDCProvider or SAMLProvider for production SSO.

    Environment variables:
        APG_OPERATOR_EMAIL: expected operator email
        APG_OPERATOR_PASSWORD: expected operator password (hashed in prod)
        APG_OPERATOR_WORKSPACE: allowed workspace name
    """

    def authenticate(self, workspace: str, email: str, password: str) -> UserInfo | None:
        expected_email = os.environ.get("APG_OPERATOR_EMAIL", "admin@apg.dev")
        expected_password = os.environ.get("APG_OPERATOR_PASSWORD", "apg-demo")
        expected_workspace = os.environ.get("APG_OPERATOR_WORKSPACE", "apg")

        # Constant-time comparison for password
        email_match = hmac.compare_digest(email.lower(), expected_email.lower())
        password_match = hmac.compare_digest(password, expected_password)
        workspace_match = hmac.compare_digest(workspace.lower(), expected_workspace.lower())

        if email_match and password_match and workspace_match:
            user_id = hashlib.sha256(f"{workspace}:{email}".encode()).hexdigest()[:12]
            return UserInfo(
                user_id=user_id,
                email=email,
                workspace=workspace,
                role="operator",
            )
        return None

    def validate_sso_token(self, token: str) -> UserInfo | None:
        """SSO not implemented in local provider."""
        return None
