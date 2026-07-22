"""OIDC/SSO operator authentication.

An `OidcAuthProvider` validates a bearer JWT issued by an OpenID Connect
provider (Okta, Entra ID, Auth0, Keycloak, …): it verifies the RS256 signature
against the issuer's JWKS and checks `iss`/`aud`/`exp`, then maps claims to a
`UserInfo`. This is the resource-server half of OIDC — the part a gateway needs
to *accept* SSO tokens — behind the same `AuthProvider` port as the local
provider, so the rest of the system is unchanged.

Configured via environment (`APG_OIDC_ISSUER` selects this provider):
    APG_OIDC_ISSUER, APG_OIDC_AUDIENCE, APG_OIDC_JWKS_URI,
    APG_OIDC_EMAIL_CLAIM, APG_OIDC_WORKSPACE_CLAIM, APG_OIDC_ROLE_CLAIM,
    APG_OIDC_WORKSPACE (default workspace when the token has no such claim).
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from typing import Any

from agent_policy_gateway.auth_service.provider import AuthProvider, LocalAuthProvider, UserInfo


class OidcAuthProvider:
    """Validate SSO JWTs from an OIDC issuer and map claims to a user."""

    def __init__(
        self,
        issuer: str,
        audience: str = "",
        jwks_uri: str | None = None,
        *,
        email_claim: str = "email",
        workspace_claim: str = "workspace",
        role_claim: str = "role",
        default_workspace: str = "",
        default_role: str = "operator",
        signing_key_resolver: Callable[[str], Any] | None = None,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._jwks_uri = jwks_uri
        self._email_claim = email_claim
        self._workspace_claim = workspace_claim
        self._role_claim = role_claim
        self._default_workspace = default_workspace
        self._default_role = default_role
        self._signing_key_resolver = signing_key_resolver

    def _resolve_key(self, token: str) -> Any:
        if self._signing_key_resolver is not None:
            return self._signing_key_resolver(token)
        import jwt

        if not self._jwks_uri:
            raise RuntimeError("APG_OIDC_JWKS_URI is required to verify SSO tokens")
        return jwt.PyJWKClient(self._jwks_uri).get_signing_key_from_jwt(token).key

    def authenticate(self, workspace: str, email: str, password: str) -> UserInfo | None:
        # Password auth is not used under OIDC — sign in through the IdP.
        return None

    def validate_sso_token(self, token: str) -> UserInfo | None:
        import jwt

        try:
            claims = jwt.decode(
                token,
                self._resolve_key(token),
                algorithms=["RS256"],
                audience=self._audience or None,
                issuer=self._issuer or None,
            )
        except Exception:
            return None

        email = claims.get(self._email_claim)
        if not email:
            return None
        workspace = claims.get(self._workspace_claim) or self._default_workspace
        role = claims.get(self._role_claim, self._default_role)
        user_id = hashlib.sha256(f"{workspace}:{email}".encode()).hexdigest()[:12]
        return UserInfo(user_id=user_id, email=email, workspace=workspace, role=role)


def build_auth_provider() -> AuthProvider:
    """Pick the operator auth provider from the environment.

    `APG_OIDC_ISSUER` selects OIDC/SSO; otherwise the local credential provider.
    """
    issuer = os.environ.get("APG_OIDC_ISSUER")
    if not issuer:
        return LocalAuthProvider()
    return OidcAuthProvider(
        issuer=issuer,
        audience=os.environ.get("APG_OIDC_AUDIENCE", ""),
        jwks_uri=os.environ.get("APG_OIDC_JWKS_URI"),
        email_claim=os.environ.get("APG_OIDC_EMAIL_CLAIM", "email"),
        workspace_claim=os.environ.get("APG_OIDC_WORKSPACE_CLAIM", "workspace"),
        role_claim=os.environ.get("APG_OIDC_ROLE_CLAIM", "role"),
        default_workspace=os.environ.get("APG_OIDC_WORKSPACE", ""),
    )
