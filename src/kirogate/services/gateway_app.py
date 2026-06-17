"""KiroGate Gateway — standalone microservice.

The core policy enforcement proxy. Handles:
- JSON-RPC tool call enforcement
- Policy evaluation
- STS credential minting
- Egress control
- Response filtering
- Audit logging
- Dashboard API

Endpoints:
    POST /rpc               → JSON-RPC enforcement pipeline
    GET  /api/status        → system status
    GET  /api/policy        → current policy
    GET  /api/audit/events  → audit log
    GET  /api/pipeline/stats → pipeline counters
    POST /api/demo/run/:id  → demo scenarios
    GET  /health            → readiness probe
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from kirogate.auth import validate_startup
from kirogate.policy import PolicyEvaluator
from kirogate.audit import AuditLogger
from kirogate.session import SessionManager
from kirogate.sts_broker import StsBroker
from kirogate.mode import ModeController
from kirogate.dashboard_api.router import router as dashboard_router


# Module-level singletons
policy_evaluator: PolicyEvaluator
audit_logger: AuditLogger
session_manager: SessionManager
sts_broker: StsBroker
mode_controller: ModeController


@asynccontextmanager
async def lifespan(app: FastAPI):
    global policy_evaluator, audit_logger, session_manager, sts_broker, mode_controller
    validate_startup()
    policy_evaluator = PolicyEvaluator()
    audit_logger = AuditLogger()
    session_manager = SessionManager()

    # STS: use Floci/LocalStack in dev, real AWS in production
    import boto3
    endpoint_url = os.environ.get("AWS_ENDPOINT_URL")
    if endpoint_url:
        sts_client = boto3.client("sts", endpoint_url=endpoint_url)
    else:
        sts_client = boto3.client("sts")
    sts_broker = StsBroker(sts_client=sts_client)

    mode_controller = ModeController()
    yield


app = FastAPI(title="KiroGate Gateway", version="1.0.0", lifespan=lifespan)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dashboard API
app.include_router(dashboard_router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "gateway"}


# Import and mount the RPC endpoint from the main module
from kirogate.main import handle_rpc  # noqa: E402
app.post("/rpc")(handle_rpc)
