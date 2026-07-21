"""HTTP JSON-RPC executor — forwards allowed requests to a real target.

Target resolution order:
    1. tool_config["target_url"]   (per-tool, from policy.json)
    2. default_target              (APG_TARGET_URL env, wired by the server)

Fail closed: no target configured → ExecutionError, the request is
denied with -32603 rather than fabricating a result.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx

from agent_policy_gateway.core.pipeline import ExecutionError


class HttpJsonRpcExecutor:
    """Forwards the allowed action to a JSON-RPC target over HTTP."""

    def __init__(self, default_target: str | None = None, timeout: float = 30.0) -> None:
        self.default_target = default_target
        self.timeout = timeout

    async def execute(
        self,
        method: str,
        params: dict[str, Any],
        creds: Any,
        tool_config: dict[str, Any] | None,
    ) -> Any:
        target = (tool_config or {}).get("target_url") or self.default_target
        if not target:
            raise ExecutionError(
                f"No execution target configured for tool '{method}' "
                "(set target_url in policy or APG_TARGET_URL)"
            )

        request_body = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(target, json=request_body)
        except httpx.HTTPError:
            # Never leak target internals to the agent
            raise ExecutionError("target unreachable") from None

        if response.status_code >= 500:
            raise ExecutionError(f"target returned HTTP {response.status_code}")

        try:
            data = response.json()
        except ValueError:
            raise ExecutionError("target returned a non-JSON response") from None

        if isinstance(data, dict):
            if data.get("error"):
                message = data["error"].get("message", "target error")
                raise ExecutionError(f"target error: {message}")
            if "result" in data:
                return data["result"]
        return data
