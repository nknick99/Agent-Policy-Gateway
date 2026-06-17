"""KiroGate Proxy App — transparent MCP gateway in one file.

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

import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


# ─── Default policy (deny all if no file provided) ───

DEFAULT_POLICY = {
    "version": 1,
    "default": "deny",
    "tools": {},
}


# ─── Policy evaluation (standalone, no imports from main app) ───


def _load_policy(policy_path: str | None) -> dict:
    """Load policy from file or use deny-all default."""
    if policy_path and Path(policy_path).exists():
        return json.loads(Path(policy_path).read_text())
    return DEFAULT_POLICY


def evaluate_request(
    method: str,
    params: dict,
    policy: dict | None = None,
) -> dict[str, Any]:
    """Evaluate a tools/call request against policy.

    Returns:
        {"allowed": bool, "outcome": str, "reason": str | None}
    """
    if policy is None:
        # Use default or load from standard location
        policy_path = os.environ.get("KIROGATE_POLICY_PATH", "policy.json")
        policy = _load_policy(policy_path)

    # Default deny
    tool_config = policy.get("tools", {}).get(method)
    if tool_config is None:
        return {
            "allowed": False,
            "outcome": "DENIED",
            "reason": f"Tool '{method}' not in policy allowlist",
        }

    if not tool_config.get("allow", False):
        return {
            "allowed": False,
            "outcome": "DENIED",
            "reason": f"Tool '{method}' is explicitly denied",
        }

    # Check operations (SQL verbs)
    allowed_ops = tool_config.get("operations", [])
    if allowed_ops:
        query = params.get("query", params.get("sql", ""))
        if query:
            verb = query.strip().split()[0].upper() if query.strip() else ""
            if verb.lower() not in [op.lower() for op in allowed_ops]:
                return {
                    "allowed": False,
                    "outcome": "DENIED",
                    "reason": f"Operation '{verb}' not in allowed: {allowed_ops}",
                }

    # Check deny keywords
    deny_keywords = tool_config.get("deny_keywords", [])
    for key, value in params.items():
        if isinstance(value, str):
            for kw in deny_keywords:
                if kw.upper() in value.upper():
                    return {
                        "allowed": False,
                        "outcome": "DENIED",
                        "reason": f"Keyword '{kw}' found in parameter '{key}'",
                    }

    # Check egress (URL destinations)
    url = params.get("url", params.get("destination", ""))
    if url:
        deny_dests = tool_config.get("deny_destinations", [])
        for deny in deny_dests:
            if deny in url:
                return {
                    "allowed": False,
                    "outcome": "DENIED",
                    "reason": f"Destination '{deny}' is blocked by egress policy",
                }

        # Whitelist check (if whitelist is non-empty, URL must match)
        whitelist = tool_config.get("destination_whitelist", [])
        if whitelist:
            matched = False
            for allowed in whitelist:
                if allowed.startswith("*"):
                    if url.endswith(allowed[1:]):
                        matched = True
                        break
                elif allowed in url:
                    matched = True
                    break
            if not matched:
                return {
                    "allowed": False,
                    "outcome": "DENIED",
                    "reason": f"Destination not in approved whitelist",
                }

    return {"allowed": True, "outcome": "ALLOWED", "reason": None}


# ─── Proxy App Factory ───


def create_proxy_app(
    target_url: str,
    policy_path: str | None = None,
    audit_file: str = "kirogate-audit.jsonl",
    mode: str = "enforce",
) -> FastAPI:
    """Create a transparent MCP proxy with policy enforcement."""

    policy = _load_policy(policy_path)
    app = FastAPI(title="KiroGate Proxy", docs_url=None, redoc_url=None)

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
            result = evaluate_request(method_name, params, policy)

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
