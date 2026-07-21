"""JSON-RPC 2.0 schemas and tool parameter models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

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


# --- Tool Parameter Models ---


class DbQueryParams(BaseModel):
    """Parameters for the db.query tool."""

    op: str
    table: str
    limit: int = Field(default=10, ge=1)
    filter: dict | None = None


class HttpPostParams(BaseModel):
    """Parameters for the http.post tool."""

    url: str
    body: dict | None = None
    headers: dict[str, str] | None = None


class ToolCallPayload(BaseModel):
    """Full tool call payload combining JSON-RPC envelope with params."""

    jsonrpc: Literal["2.0"]
    id: int | str
    method: str
    params: dict


# --- Schema Validation Error ---


class SchemaValidationError(Exception):
    """Raised when schema validation fails. Carries a JSON-RPC error code and message."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


# --- Method → Model Registry ---

PARAM_MODELS: dict[str, type[BaseModel]] = {
    "db.query": DbQueryParams,
    "http.post": HttpPostParams,
}


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


def validate_params(method: str, params: dict) -> BaseModel:
    """Route params to the correct Pydantic model based on method name.

    Returns the validated Pydantic model instance on success.
    Raises SchemaValidationError with the appropriate JSON-RPC error code on failure:
        -32601: Method not found (no registered model)
        -32602: Invalid params (type mismatch or missing required params)
    """
    model_cls = PARAM_MODELS.get(method)
    if model_cls is None:
        raise SchemaValidationError(
            -32601, f"Method not recognized: '{method}'"
        )

    try:
        return model_cls(**params)
    except ValidationError as e:
        # Extract meaningful error info from Pydantic validation
        errors = e.errors()
        if errors:
            first_error = errors[0]
            field = ".".join(str(loc) for loc in first_error["loc"])
            error_type = first_error["type"]

            if error_type == "missing":
                raise SchemaValidationError(
                    -32602, f"Missing required parameter: '{field}'"
                ) from e
            else:
                raise SchemaValidationError(
                    -32602,
                    f"Invalid parameter '{field}': {first_error['msg']}",
                ) from e

        raise SchemaValidationError(-32602, "Invalid params") from e
