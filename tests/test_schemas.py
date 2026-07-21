"""Tests for Agent Policy Gateway JSON-RPC envelope schemas and validation.

Per-tool parameter models were removed deliberately (Phase 1, D11):
the gateway fronts arbitrary MCP tools, so tool/param acceptance is a
policy decision, not a schema decision.
"""

import pytest
from pydantic import ValidationError

from agent_policy_gateway.core.schemas import (
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    SchemaValidationError,
    validate_envelope,
)

# --- JsonRpcRequest Tests ---


class TestJsonRpcRequest:
    def test_valid_request(self):
        req = JsonRpcRequest(
            jsonrpc="2.0", id=1, method="db.query", params={"op": "SELECT"}
        )
        assert req.jsonrpc == "2.0"
        assert req.id == 1
        assert req.method == "db.query"
        assert req.params == {"op": "SELECT"}

    def test_string_id(self):
        req = JsonRpcRequest(jsonrpc="2.0", id="abc-123", method="test")
        assert req.id == "abc-123"

    def test_empty_params_default(self):
        req = JsonRpcRequest(jsonrpc="2.0", id=1, method="test")
        assert req.params == {}

    def test_invalid_jsonrpc_version(self):
        with pytest.raises(ValidationError):
            JsonRpcRequest(jsonrpc="1.0", id=1, method="test")

    def test_empty_method_rejected(self):
        with pytest.raises(ValidationError):
            JsonRpcRequest(jsonrpc="2.0", id=1, method="")

    def test_missing_id_rejected(self):
        with pytest.raises(ValidationError):
            JsonRpcRequest(jsonrpc="2.0", method="test")

    def test_arbitrary_tool_method_accepted(self):
        """Unknown tools are valid at the envelope level — policy decides."""
        req = JsonRpcRequest(
            jsonrpc="2.0", id=1, method="fs.read", params={"path": "/tmp/x"}
        )
        assert req.method == "fs.read"


# --- JsonRpcError Tests ---


class TestJsonRpcError:
    def test_basic_error(self):
        err = JsonRpcError(code=-32600, message="Invalid request")
        assert err.code == -32600
        assert err.message == "Invalid request"
        assert err.data is None

    def test_error_with_data(self):
        err = JsonRpcError(
            code=-32602, message="Invalid params", data={"field": "limit"}
        )
        assert err.data == {"field": "limit"}


# --- JsonRpcResponse Tests ---


class TestJsonRpcResponse:
    def test_success_response(self):
        resp = JsonRpcResponse(id=1, result={"rows": []})
        assert resp.jsonrpc == "2.0"
        assert resp.id == 1
        assert resp.result == {"rows": []}
        assert resp.error is None

    def test_error_response(self):
        resp = JsonRpcResponse(
            id=1, error=JsonRpcError(code=-32600, message="Auth failed")
        )
        assert resp.result is None
        assert resp.error.code == -32600

    def test_null_id_for_parse_errors(self):
        resp = JsonRpcResponse(
            id=None, error=JsonRpcError(code=-32700, message="Parse error")
        )
        assert resp.id is None


# --- validate_envelope Tests ---


class TestValidateEnvelope:
    def test_valid_envelope_passes(self):
        validate_envelope({"jsonrpc": "2.0", "id": 1, "method": "anything"})

    def test_missing_jsonrpc(self):
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_envelope({"id": 1, "method": "m"})
        assert exc_info.value.code == -32600
        assert "jsonrpc" in exc_info.value.message

    def test_missing_id(self):
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_envelope({"jsonrpc": "2.0", "method": "m"})
        assert exc_info.value.code == -32600
        assert "id" in exc_info.value.message

    def test_missing_method(self):
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_envelope({"jsonrpc": "2.0", "id": 1})
        assert exc_info.value.code == -32600
        assert "method" in exc_info.value.message

    def test_wrong_version(self):
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_envelope({"jsonrpc": "1.0", "id": 1, "method": "m"})
        assert exc_info.value.code == -32600
        assert "version" in exc_info.value.message.lower()
