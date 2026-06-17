"""Auth service FastAPI router.

Exposes /api/auth/* endpoints. This module can be:
- Mounted as a router in the main app (current)
- Extracted into a standalone FastAPI service (microservice mode)
- Replaced entirely with an SSO callback handler
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel

from kirogate.auth_service.provider import LocalAuthProvider, UserInfo
from kirogate.auth_service.tokens import create_token, verify_token

router = APIRouter(prefix="/api/auth", tags=["auth"])

# The active auth provider — swap this for SSO
_provider = LocalAuthProvider()


class LoginRequest(BaseModel):
    workspace: str
    email: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_in: int
    user: UserInfo


class MeResponse(BaseModel):
    user_id: str
    email: str
    workspace: str
    role: str


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest) -> LoginResponse:
    """Authenticate an operator and issue a session token.

    To swap to SSO: replace this endpoint with an OIDC/SAML callback
    that validates the external token and issues a local JWT.
    """
    user = _provider.authenticate(
        workspace=payload.workspace,
        email=payload.email,
        password=payload.password,
    )

    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(
        user_id=user.user_id,
        email=user.email,
        workspace=user.workspace,
        role=user.role,
    )

    return LoginResponse(
        token=token,
        expires_in=3600,
        user=user,
    )


@router.get("/me", response_model=MeResponse)
async def get_current_user(
    authorization: str = Header(default=""),
) -> MeResponse:
    """Get the current authenticated user from the session token."""
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing authorization token")

    payload = verify_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return MeResponse(
        user_id=payload["sub"],
        email=payload["email"],
        workspace=payload["workspace"],
        role=payload["role"],
    )


@router.post("/logout")
async def logout() -> dict:
    """Logout — client-side token discard.

    In a stateful session model, this would invalidate the server-side session.
    With JWTs, the client simply discards the token.
    """
    return {"status": "ok", "message": "Token discarded (client-side)"}
