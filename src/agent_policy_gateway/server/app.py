"""Agent Policy Gateway — FastAPI wiring.

Thin HTTP layer only: parses the request, delegates to the one
EnforcementPipeline (core/pipeline.py), and returns the JSON-RPC body.
All enforcement logic lives in the pipeline; all infrastructure is
wired here as adapters (ADR-001).
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agent_policy_gateway.adapters.audit.stdout import AuditLogger
from agent_policy_gateway.adapters.brokers.aws_sts import StsBroker
from agent_policy_gateway.adapters.brokers.null_broker import NullBroker
from agent_policy_gateway.adapters.executors.http_jsonrpc import HttpJsonRpcExecutor
from agent_policy_gateway.adapters.identity.shared_token import (
    authenticate_caller,
    validate_startup,
)
from agent_policy_gateway.adapters.state import build_session_store
from agent_policy_gateway.auth_service import auth_router
from agent_policy_gateway.core.audit import AuditEvent
from agent_policy_gateway.core.mode import ModeController
from agent_policy_gateway.core.pipeline import EnforcementPipeline
from agent_policy_gateway.core.policy import PolicyEvaluator
from agent_policy_gateway.core.session import SessionStore
from agent_policy_gateway.dashboard_api import dashboard_router
from agent_policy_gateway.live_demo.router import router as live_demo_router

# --- Module-level singletons (initialized at startup) ---

audit_logger: AuditLogger
policy_evaluator: PolicyEvaluator
session_manager: SessionStore
mode_controller: ModeController
pipeline: EnforcementPipeline


class _ModuleAuditSink:
    """Late-binding sink: resolves the module-level audit_logger at call
    time so it stays patchable in tests and swappable at runtime."""

    def emit(self, event: AuditEvent) -> None:
        audit_logger.emit(event)


def _build_broker():
    """Select the credential broker from policy (default: none)."""
    if policy_evaluator.policy.credential_broker == "aws_sts":
        endpoint_url = os.environ.get("AWS_ENDPOINT_URL")
        if endpoint_url:
            import boto3

            return StsBroker(sts_client=boto3.client("sts", endpoint_url=endpoint_url))
        return StsBroker()
    return NullBroker()


# --- Lifespan ---


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup validation and component initialization.

    Checks APG_AGENT_TOKEN, loads policy.json, validates default="deny".
    Refuses to start if any precondition fails.
    """
    global audit_logger, policy_evaluator, session_manager, mode_controller, pipeline

    # Requirement 10.2: Refuse to start without token
    validate_startup()

    # Requirement 10.3: Load and validate policy (exits on failure)
    policy_evaluator = PolicyEvaluator()

    audit_logger = AuditLogger()
    # In-memory by default; Redis when APG_REDIS_URL is set (shared across
    # replicas — required for correct quotas in a multi-replica deployment).
    session_manager = build_session_store()
    mode_controller = ModeController()

    pipeline = EnforcementPipeline(
        evaluator=policy_evaluator,
        session_manager=session_manager,
        broker=_build_broker(),
        audit_sink=_ModuleAuditSink(),
        mode_controller=mode_controller,
        executor=HttpJsonRpcExecutor(
            default_target=os.environ.get("APG_TARGET_URL") or None
        ),
        authenticate=authenticate_caller,
    )

    yield


# --- FastAPI App ---

app = FastAPI(title="Agent Policy Gateway", lifespan=lifespan)

# --- CORS (allow Next.js frontend) ---

_cors_origins = os.environ.get("CORS_ORIGINS")
app.add_middleware(
    CORSMiddleware,
    allow_origins=(
        _cors_origins.split(",")
        if _cors_origins
        else [
            "http://localhost:3000",  # Next.js dev server
            os.environ.get("FRONTEND_URL", "http://localhost:3000"),
        ]
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Mount auth, dashboard, and demo routers ---
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(live_demo_router)


@app.get("/health")
async def health():
    """Readiness probe."""
    return {"status": "ok", "service": "agent-policy-gateway"}


# --- Main RPC Endpoint ---


@app.post("/rpc")
async def handle_rpc(request: Request) -> JSONResponse:
    """POST /rpc — parse the body and run the enforcement pipeline."""
    raw_body = await request.body()

    try:
        payload = json.loads(raw_body)
    except (json.JSONDecodeError, ValueError):
        # Requirement 13.5: invalid JSON → -32700 with null id.
        # Parse errors happen before the pipeline; still audit them.
        event = AuditEvent(denial_reason="Parse error: body is not valid JSON")
        audit_logger.emit(event)
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            },
            status_code=200,
        )

    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()

    outcome = await pipeline.handle(payload, token)
    return JSONResponse(content=outcome.body, status_code=200)
