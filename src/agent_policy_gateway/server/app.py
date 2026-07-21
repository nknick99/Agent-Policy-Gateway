"""Agent Policy Gateway Proxy — FastAPI application with full enforcement pipeline.

Accepts POST /rpc with JSON-RPC 2.0 payloads and executes a fixed-order
enforcement pipeline:

    authenticate → schema validate → policy evaluate → egress control →
    quota check → credential mint → execute action → filter response → audit

Fail-closed: any unhandled exception returns -32603 and halts the pipeline.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agent_policy_gateway.adapters.audit.stdout import AuditEvent, AuditLogger, redact_params
from agent_policy_gateway.adapters.brokers.aws_sts import CredentialMintError, StsBroker
from agent_policy_gateway.adapters.identity.shared_token import (
    authenticate_caller,
    validate_startup,
)
from agent_policy_gateway.auth_service import auth_router
from agent_policy_gateway.core.egress import EgressController
from agent_policy_gateway.core.filter import filter_response
from agent_policy_gateway.core.mode import ModeController
from agent_policy_gateway.core.models import AuditDecision, Decision
from agent_policy_gateway.core.policy import PolicyEvaluator
from agent_policy_gateway.core.schemas import (
    SchemaValidationError,
    validate_envelope,
    validate_params,
)
from agent_policy_gateway.core.session import SessionManager
from agent_policy_gateway.dashboard_api import dashboard_router
from agent_policy_gateway.live_demo.router import router as live_demo_router

logger = logging.getLogger(__name__)

# --- Module-level singletons (initialized at startup) ---

audit_logger: AuditLogger
policy_evaluator: PolicyEvaluator
session_manager: SessionManager
sts_broker: StsBroker
mode_controller: ModeController


# --- Lifespan ---


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup validation and component initialization.

    Checks APG_AGENT_TOKEN, loads policy.json, validates default="deny".
    Refuses to start if any precondition fails.
    """
    global audit_logger, policy_evaluator, session_manager, sts_broker, mode_controller

    # Requirement 10.2: Refuse to start without token
    validate_startup()

    # Requirement 10.3: Load and validate policy (exits on failure)
    policy_evaluator = PolicyEvaluator()

    # Initialize remaining components
    audit_logger = AuditLogger()
    session_manager = SessionManager()
    sts_broker = StsBroker()
    mode_controller = ModeController()

    yield


# --- FastAPI App ---

app = FastAPI(title="Agent Policy Gateway Proxy", lifespan=lifespan)

# --- CORS (allow Next.js frontend) ---

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Next.js dev server
        os.environ.get("FRONTEND_URL", "http://localhost:3000"),
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Mount auth and dashboard API routers ---
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(live_demo_router)


# --- Helper Functions ---


def _error_response(
    request_id: int | str | None, code: int, message: str
) -> JSONResponse:
    """Build a JSON-RPC 2.0 error response.

    Requirement 13.3: error field with code and message.
    Requirement 13.4: never returns both result and error.
    Requirement 13.5: id must be present as null when request_id is None.
    """
    content: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }
    return JSONResponse(content=content, status_code=200)


def _success_response(request_id: int | str | None, result: Any) -> JSONResponse:
    """Build a JSON-RPC 2.0 success response.

    Requirement 13.2: result field with matching id.
    Requirement 13.4: never returns both result and error.
    """
    content: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }
    return JSONResponse(content=content, status_code=200)


def _caller_id_from_token(token: str) -> str:
    """Derive a caller ID from the token (SHA-256 hash for session tracking)."""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


async def _execute_action(
    method: str, params: dict[str, Any], creds: Any
) -> dict[str, Any]:
    """Placeholder for actual target execution.

    Returns the params as-is since target execution is not yet implemented.
    """
    return {"status": "executed", "method": method}


# --- Main RPC Endpoint ---


@app.post("/rpc")
async def handle_rpc(request: Request) -> JSONResponse:
    """POST /rpc — Full enforcement pipeline.

    Pipeline order (Requirement 10.4):
        1. Authenticate caller
        2. Schema validate (envelope + params)
        3. Policy evaluate
        4. Egress control
        5. Quota check
        6. Credential mint
        7. Execute action
        8. Filter response
        9. Audit

    Fail-closed (Requirement 10.1): unhandled exception → -32603, halt pipeline.
    """
    start_time = time.monotonic()
    correlation_id = AuditLogger().generate_correlation_id()
    audit_event = AuditEvent(correlation_id=correlation_id)
    request_id: int | str | None = None
    creds = None

    try:
        # --- Parse raw JSON body ---
        raw_body = await request.body()

        try:
            payload = json.loads(raw_body)
        except (json.JSONDecodeError, ValueError):
            # Requirement 13.5: invalid JSON → -32700 with null id
            audit_event.decision = AuditDecision.DENY
            audit_event.denial_reason = "Parse error: body is not valid JSON"
            return _error_response(None, -32700, "Parse error")

        # Requirement 13.6: reject batch (JSON array)
        if isinstance(payload, list):
            audit_event.decision = AuditDecision.DENY
            audit_event.denial_reason = "Batch requests not supported"
            return _error_response(None, -32600, "Batch requests not supported")

        # Requirement 13.7: reject notifications (missing id)
        if not isinstance(payload, dict):
            audit_event.decision = AuditDecision.DENY
            audit_event.denial_reason = "Invalid request: body is not a JSON object"
            return _error_response(None, -32600, "Invalid request")

        request_id = payload.get("id")

        if request_id is None:
            audit_event.decision = AuditDecision.DENY
            audit_event.denial_reason = "Notifications not supported"
            return _error_response(None, -32600, "Notifications not supported")

        # --- Step 1: Authenticate ---
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()

        if not authenticate_caller(token):
            audit_event.decision = AuditDecision.DENY
            audit_event.denial_reason = "Authentication failed"
            return _error_response(request_id, -32600, "Authentication failed")

        caller_id = _caller_id_from_token(token)
        audit_event.caller_identity = caller_id

        # --- Step 2: Schema validation (envelope) ---
        validate_envelope(payload)

        method = payload["method"]
        params = payload.get("params", {})
        audit_event.method = method
        audit_event.params_redacted = redact_params(params)

        # --- Step 3: Schema validation (params) ---
        validate_params(method, params)

        # --- Step 4: Policy evaluation ---
        policy_result = policy_evaluator.evaluate(method, params)

        if policy_result.decision == Decision.DENY:
            if mode_controller.should_block_policy_denial():
                # Enforce mode: block
                audit_event.decision = AuditDecision.DENY
                audit_event.denial_reason = f"Policy denied: {policy_result.reason}"
                audit_event.rule_matched = policy_result.rule_matched
                return _error_response(
                    request_id, -32600, f"Policy denied: {policy_result.reason}"
                )
            else:
                # Audit mode: log but continue (Requirement 12.2)
                proposed = mode_controller.build_proposed_policy_entry(method, params)
                logger.info(
                    "Audit mode: policy denial logged but not enforced. "
                    "Proposed policy entry: %s",
                    proposed,
                )
                # In audit mode with a DENY, we still want to proceed
                # but record the proposed entry. We'll set decision to ALLOW
                # since we're letting it through.
                audit_event.rule_matched = policy_result.rule_matched

        # --- Step 5: Egress control ---
        if policy_result.tool_config and (
            "url" in params or "destination" in params
        ):
            egress = EgressController(policy_result.tool_config)
            dest = params.get("url") or params.get("destination")
            egress_result = egress.check(dest)
            if not egress_result.allowed:
                audit_event.decision = AuditDecision.DENY
                audit_event.denial_reason = f"Egress denied: {egress_result.reason}"
                return _error_response(
                    request_id, -32600, f"Egress denied: {egress_result.reason}"
                )

        # --- Step 6: Quota check ---
        session_limits = policy_evaluator.policy.session_limits
        if await session_manager.check_quota(caller_id, session_limits):
            audit_event.decision = AuditDecision.DENY
            audit_event.denial_reason = "Session quota exceeded"
            return _error_response(request_id, -32600, "Session quota exceeded")

        # --- Step 7: Credential mint ---
        tool_config = policy_result.tool_config or {}
        role_arn = tool_config.get("aws_role", "")
        session_policy = tool_config.get("session_policy", {})

        creds = sts_broker.mint_credentials(
            role_arn=role_arn,
            session_policy=session_policy,
            session_name=f"apg-{correlation_id[:8]}",
        )
        audit_event.role_assumed = role_arn

        try:
            # --- Step 8: Execute action ---
            raw_result = await _execute_action(method, params, creds)

            # --- Step 9: Filter response ---
            filtered_result = filter_response(raw_result)

            # Record success in session tracking
            record_count = 0
            if isinstance(raw_result, dict):
                record_count = len(raw_result.get("rows", []))
            await session_manager.record_success(caller_id, record_count=record_count)

            # Mark audit event as success
            audit_event.decision = AuditDecision.ALLOW
            audit_event.rule_matched = policy_result.rule_matched
            audit_event.outcome = "success"

            return _success_response(request_id, filtered_result)
        finally:
            # Requirement 6.6: guaranteed credential discard in try/finally
            StsBroker.discard(creds)
            creds = None

    except SchemaValidationError as exc:
        audit_event.decision = AuditDecision.DENY
        audit_event.denial_reason = f"Schema validation: {exc.message}"
        return _error_response(request_id, exc.code, exc.message)

    except CredentialMintError:
        audit_event.decision = AuditDecision.DENY
        audit_event.denial_reason = "Credential minting failed"
        return _error_response(
            request_id, -32603, "Internal error: credential minting failed"
        )

    except Exception:
        # Requirement 10.1: fail-closed — unhandled exception → -32603
        logger.exception(
            "Unhandled exception in pipeline (correlation_id=%s)", correlation_id
        )
        audit_event.decision = AuditDecision.DENY
        audit_event.denial_reason = "Unhandled internal error"
        return _error_response(request_id, -32603, "Internal error")

    finally:
        # --- Step 10: Audit (always emit) ---
        # Requirement 10.5: if audit fails while recording DENY, still return DENY
        elapsed_ms = (time.monotonic() - start_time) * 1000
        audit_event.duration_ms = elapsed_ms
        audit_logger.emit(audit_event)
