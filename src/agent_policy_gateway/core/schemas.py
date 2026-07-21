"""JSON-RPC 2.0 envelope models and validation.

The gateway fronts arbitrary MCP tools, so there are deliberately no
hardcoded per-tool parameter schemas here: whether a tool and its
parameters are acceptable is a policy decision (default deny), not a
schema decision. Per-tool parameter schemas will return as optional,
policy-defined validators (Phase 2).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

# --- JSON-RPC 2.0 Models ---


class JsonRpcRequest(BaseModel):
    """Incoming JSON-RPC 2.0 request."""

    jsonrpc: Literal["2.0"]
    id: int | str
    method: str = Field(min_length=1)
    params: dict[str, Any] = {}


class JsonRpcError(BaseModel):
    """JSON-RPC 2.0 error object."""

    code: int
    message: str
    data: dict | None = None


class JsonRpcResponse(BaseModel):
    """Outgoing JSON-RPC 2.0 response (result XOR error)."""

    jsonrpc: Literal["2.0"] = "2.0"
    id: int | str | None = None
    result: Any | None = None
    error: JsonRpcError | None = None


# --- Schema Validation Error ---


class SchemaValidationError(Exception):
    """Raised when schema validation fails. Carries a JSON-RPC error code and message."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


# --- Validation Functions ---


def validate_envelope(payload: dict[str, Any]) -> None:
    """Validate the JSON-RPC 2.0 envelope fields (jsonrpc, id, method).

    Raises SchemaValidationError with code -32600 on failure.
    """
    if "jsonrpc" not in payload:
        raise SchemaValidationError(-32600, "Missing required field: jsonrpc")

    if "id" not in payload:
        raise SchemaValidationError(-32600, "Missing required field: id")

    if "method" not in payload:
        raise SchemaValidationError(-32600, "Missing required field: method")

    if payload["jsonrpc"] != "2.0":
        raise SchemaValidationError(
            -32600,
            f"Invalid jsonrpc version: expected '2.0', got '{payload['jsonrpc']}'",
        )
