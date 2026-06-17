"""Auth Service — standalone microservice.

Handles authentication, JWT token management, and user identity.
Swap the provider for SSO/OIDC when ready.

Endpoints:
    POST /api/auth/login    → authenticate and issue JWT
    GET  /api/auth/me       → get current user from token
    POST /api/auth/logout   → invalidate session (client-side)
    GET  /health            → readiness probe
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from kirogate.auth_service.router import router as auth_router

app = FastAPI(title="KiroGate Auth Service", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "auth"}
