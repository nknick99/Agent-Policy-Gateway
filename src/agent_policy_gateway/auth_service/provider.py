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

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error
from pydantic import BaseModel

_password_hasher = PasswordHasher()


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

    Reads operator credentials from environment variables. There are no
    built-in default credentials: if the operator identity or a password is not
    configured, authentication fails closed. Replace this with OIDCProvider or
    SAMLProvider for production SSO.

    Environment variables:
        APG_OPERATOR_EMAIL: expected operator email (required)
        APG_OPERATOR_WORKSPACE: allowed workspace name (required)
        APG_OPERATOR_PASSWORD_HASH: argon2 hash of the password (preferred;
            generate with `apg hash-password`)
        APG_OPERATOR_PASSWORD: plaintext password (dev-only fallback if no hash)
    """

    def authenticate(self, workspace: str, email: str, password: str) -> UserInfo | None:
        expected_email = os.environ.get("APG_OPERATOR_EMAIL", "")
        expected_workspace = os.environ.get("APG_OPERATOR_WORKSPACE", "")
        password_hash = os.environ.get("APG_OPERATOR_PASSWORD_HASH", "")
        plain_password = os.environ.get("APG_OPERATOR_PASSWORD", "")

        # No defaults: an unconfigured operator cannot authenticate.
        if not expected_email or not expected_workspace:
            return None
        if not password_hash and not plain_password:
            return None

        email_match = hmac.compare_digest(email.lower(), expected_email.lower())
        workspace_match = hmac.compare_digest(workspace.lower(), expected_workspace.lower())
        if not (email_match and workspace_match):
            return None

        if not self._password_ok(password, password_hash, plain_password):
            return None

        user_id = hashlib.sha256(f"{workspace}:{email}".encode()).hexdigest()[:12]
        return UserInfo(
            user_id=user_id,
            email=email,
            workspace=workspace,
            role="operator",
        )

    @staticmethod
    def _password_ok(password: str, password_hash: str, plain_password: str) -> bool:
        """Verify the password against the argon2 hash, or the dev plaintext."""
        if password_hash:
            try:
                return _password_hasher.verify(password_hash, password)
            except Argon2Error:
                return False
        # Dev-only fallback: constant-time plaintext compare.
        return hmac.compare_digest(password, plain_password)

    def validate_sso_token(self, token: str) -> UserInfo | None:
        """SSO not implemented in local provider."""
        return None
