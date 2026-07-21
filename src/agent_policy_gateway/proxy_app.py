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
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agent_policy_gateway.core.egress import EgressController
from agent_policy_gateway.core.models import Decision, PolicyDocument
from agent_policy_gateway.core.policy import (
    PolicyEvaluator,
    PolicyLoadError,
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

    result = evaluator.evaluate(method, params)
    if result.decision == Decision.DENY:
        return {"allowed": False, "outcome": "DENIED", "reason": result.reason}

    # Egress control for tools that reach out to a destination
    destination = params.get("url") or params.get("destination")
    if destination and result.tool_config is not None:
        egress_result = EgressController(result.tool_config).check(destination)
        if not egress_result.allowed:
            return {
                "allowed": False,
                "outcome": "DENIED",
                "reason": f"Egress denied: {egress_result.reason}",
            }

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
    app = FastAPI(title="Agent Policy Gateway Proxy", docs_url=None, redoc_url=None)

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

        # ─── Policy enforcement (only for tool calls) ───
        outcome = "PASS_THROUGH"
        reason = None

        if is_tool_call and method_name:
            result = evaluate_request(method_name, params, evaluator)

            if not result["allowed"] and mode == "enforce":
                # DENIED — don't forward to target
                elapsed = (time.monotonic() - start) * 1000
                _write_audit(audit_file, {
                    "correlation_id": correlation_id,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                    "outcome": "DENY",
                    "method": method_name,
                    "reason": result["reason"],
                    "latency_ms": round(elapsed, 2),
                    "mode": mode,
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
            _write_audit(audit_file, {
                "correlation_id": correlation_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                "outcome": "ALLOW" if outcome == "ALLOWED" else outcome,
                "method": method_name,
                "reason": reason,
                "latency_ms": round(elapsed, 2),
                "target_status": resp.status_code,
                "mode": mode,
            })

        return JSONResponse(
            content=resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text,
            status_code=resp.status_code,
            headers={k: v for k, v in resp.headers.items() if k.lower() not in ("transfer-encoding", "content-encoding", "content-length")},
        )

    return app


def _write_audit(audit_file: str, event: dict):
    """Append audit event to JSONL file."""
    try:
        with open(audit_file, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass  # Don't let audit failure break the proxy
