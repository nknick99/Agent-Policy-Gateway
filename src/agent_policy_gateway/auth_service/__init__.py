"""Agent Policy Gateway Authentication Microservice.

This module is a self-contained auth service that can be:
1. Used as an internal module (current setup)
2. Extracted into a standalone microservice
3. Swapped for SSO (OIDC/SAML) by implementing the AuthProvider interface

The service issues short-lived JWTs for operator access to the console.
"""

from agent_policy_gateway.auth_service.provider import AuthProvider, LocalAuthProvider
from agent_policy_gateway.auth_service.tokens import create_token, verify_token
from agent_policy_gateway.auth_service.router import router as auth_router

__all__ = [
    "AuthProvider",
    "LocalAuthProvider",
    "create_token",
    "verify_token",
    "auth_router",
]
