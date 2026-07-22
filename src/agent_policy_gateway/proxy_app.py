"""Agent Policy Gateway Proxy App — transparent MCP gateway in one file.

This is the "easy integration" entry point. It:
1. Receives JSON-RPC requests from the MCP client
2. Evaluates them against policy
3. Forwards allowed requests to the real MCP server
4. Blocks denied requests before they ever reach the server
5. Logs everything to an audit file

No database, no auth service, no frontend required.
Just this + policy.json.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agent_policy_gateway.adapters.audit import build_audit_sink
from agent_policy_gateway.adapters.audit.jsonl import attempt_summary as _attempt_summary
from agent_policy_gateway.adapters.identity import build_identity_provider
from agent_policy_gateway.core.enforcement import evaluate_call
from agent_policy_gateway.core.models import PolicyDocument
from agent_policy_gateway.core.policy import (
    PolicyEvaluator,
    load_policy_document,
)

# ─── Default policy (deny all if no file provided) ───

DEFAULT_POLICY_DOCUMENT = {
    "version": 1,
    "default": "deny",
    "caller_auth": {"method": "shared_token"},
    "session_limits": {},
    "tools": {},
}


def build_evaluator(policy_path: str | None) -> PolicyEvaluator:
    """Build the shared core evaluator from a policy file, or deny-all default.

    Raises PolicyLoadError if a policy file exists but is invalid —
    fail closed at startup rather than running with a policy the
    operator didn't intend.
    """
    if policy_path and Path(policy_path).exists():
        return PolicyEvaluator.from_document(load_policy_document(policy_path))
    return PolicyEvaluator.from_document(
        PolicyDocument.model_validate(DEFAULT_POLICY_DOCUMENT)
    )


def evaluate_request(
    method: str,
    params: dict,
    evaluator: PolicyEvaluator | None = None,
) -> dict[str, Any]:
    """Evaluate a tools/call request via the core policy engine + egress control.

    This is a thin wrapper around the same PolicyEvaluator/EgressController
    used by the full gateway — there is exactly one enforcement engine.

    Returns:
        {"allowed": bool, "outcome": str, "reason": str | None}
    """
    if evaluator is None:
        evaluator = build_evaluator(os.environ.get("APG_POLICY_PATH", "policy.json"))

    decision = evaluate_call(evaluator, method, params)
    if not decision.allowed:
        return {"allowed": False, "outcome": "DENIED", "reason": decision.reason}
    return {"allowed": True, "outcome": "ALLOWED", "reason": None}


# ─── Proxy App Factory ───


def create_proxy_app(
    target_url: str,
    policy_path: str | None = None,
    audit_file: str = "apg-audit.jsonl",
    mode: str = "enforce",
) -> FastAPI:
    """Create a transparent MCP proxy with policy enforcement."""

    evaluator = build_evaluator(policy_path)
    identity_provider = build_identity_provider(evaluator.policy)
    audit_sink = build_audit_sink(audit_file)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            yield
        finally:
            audit_sink.close()

    app = FastAPI(
        title="Agent Policy Gateway Proxy",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.get("/health")
    async def health():
        return {"status": "ok", "target": target_url, "mode": mode}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy(request: Request, path: str):
        start = time.monotonic()
        correlation_id = str(uuid.uuid4())[:8]
        body = await request.body()

        # Try to parse as JSON-RPC
        is_tool_call = False
        method_name = None
        params = {}

        try:
            payload = json.loads(body) if body else {}
            if isinstance(payload, dict):
                rpc_method = payload.get("method", "")
                # MCP tools/call detection
                if rpc_method == "tools/call":
                    is_tool_call = True
                    method_name = payload.get("params", {}).get("name", "")
                    params = payload.get("params", {}).get("arguments", {})
                # Direct method call (our format)
                elif rpc_method and payload.get("jsonrpc") == "2.0":
                    is_tool_call = True
                    method_name = rpc_method
                    params = payload.get("params", {})
        except (json.JSONDecodeError, AttributeError):
            pass

        # ─── Authentication → identity (every proxied request, constant-time) ───
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()
        identity = identity_provider.authenticate(token)
        if identity is None:
            elapsed = (time.monotonic() - start) * 1000
            audit_sink.write({
                "correlation_id": correlation_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                "outcome": "DENY",
                "method": method_name,
                "agent_id": None,
                "reason": "Authentication failed",
                "latency_ms": round(elapsed, 2),
                "mode": mode,
            })
            request_id = payload.get("id") if isinstance(payload, dict) else None
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32600, "message": "Authentication failed"},
                },
                status_code=401,
            )

        # ─── Policy enforcement (only for tool calls) ───
        outcome = "PASS_THROUGH"
        reason = None

        if is_tool_call and method_name:
            # Identity scope first: is this agent allowed to call this tool at
            # all? Then the shared per-tool rules (operations, egress, SQL).
            result: dict[str, Any]
            if not identity.may_call(method_name):
                result = {
                    "allowed": False,
                    "outcome": "DENIED",
                    "reason": (
                        f"Agent '{identity.agent_id}' is not permitted to call "
                        f"'{method_name}'"
                    ),
                }
            else:
                result = evaluate_request(method_name, params, evaluator)

            if not result["allowed"] and mode == "enforce":
                # DENIED — don't forward to target
                elapsed = (time.monotonic() - start) * 1000
                audit_sink.write({
                    "correlation_id": correlation_id,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                    "outcome": "DENY",
                    "method": method_name,
                    "agent_id": identity.agent_id,
                    "reason": result["reason"],
                    "latency_ms": round(elapsed, 2),
                    "mode": mode,
                    **_attempt_summary(params),
                })

                # Return JSON-RPC error
                request_id = payload.get("id")
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32600,
                        "message": f"Policy denied: {result['reason']}",
                    },
                })

            outcome = result["outcome"]
            reason = result.get("reason")

        # ─── Forward to target MCP server ───
        target = f"{target_url.rstrip('/')}/{path}"
        headers = dict(request.headers)
        headers.pop("host", None)
        # Never forward the gateway token to the target
        headers.pop("authorization", None)

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.request(
                method=request.method,
                url=target,
                content=body,
                headers=headers,
            )

        elapsed = (time.monotonic() - start) * 1000

        # ─── Audit log ───
        if is_tool_call:
            audit_sink.write({
                "correlation_id": correlation_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                "outcome": "ALLOW" if outcome == "ALLOWED" else outcome,
                "method": method_name,
                "agent_id": identity.agent_id,
                "reason": reason,
                "latency_ms": round(elapsed, 2),
                "target_status": resp.status_code,
                "mode": mode,
                **_attempt_summary(params),
            })

        return JSONResponse(
            content=resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text,
            status_code=resp.status_code,
            headers={k: v for k, v in resp.headers.items() if k.lower() not in ("transfer-encoding", "content-encoding", "content-length")},
        )

    return app


