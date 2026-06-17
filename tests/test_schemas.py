"""Tests for KiroGate JSON-RPC schemas and parameter models."""

import pytest
from pydantic import ValidationError

from kirogate.schemas import (
    DbQueryParams,
    HttpPostParams,
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    ToolCallPayload,
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


# --- DbQueryParams Tests ---


class TestDbQueryParams:
    def test_valid_params(self):
        p = DbQueryParams(op="SELECT", table="users")
        assert p.op == "SELECT"
        assert p.table == "users"
        assert p.limit == 10
        assert p.filter is None

    def test_custom_limit(self):
        p = DbQueryParams(op="SELECT", table="orders", limit=50)
        assert p.limit == 50

    def test_with_filter(self):
        p = DbQueryParams(op="SELECT", table="users", filter={"active": True})
        assert p.filter == {"active": True}

    def test_zero_limit_rejected(self):
        with pytest.raises(ValidationError):
            DbQueryParams(op="SELECT", table="users", limit=0)

    def test_missing_op_rejected(self):
        with pytest.raises(ValidationError):
            DbQueryParams(table="users")

    def test_missing_table_rejected(self):
        with pytest.raises(ValidationError):
            DbQueryParams(op="SELECT")


# --- HttpPostParams Tests ---


class TestHttpPostParams:
    def test_valid_params(self):
        p = HttpPostParams(url="https://api.example.com/data")
        assert p.url == "https://api.example.com/data"
        assert p.body is None
        assert p.headers is None

    def test_with_body_and_headers(self):
        p = HttpPostParams(
            url="https://api.example.com",
            body={"key": "value"},
            headers={"Content-Type": "application/json"},
        )
        assert p.body == {"key": "value"}
        assert p.headers == {"Content-Type": "application/json"}

    def test_missing_url_rejected(self):
        with pytest.raises(ValidationError):
            HttpPostParams()


# --- ToolCallPayload Tests ---


class TestToolCallPayload:
    def test_valid_payload(self):
        p = ToolCallPayload(
            jsonrpc="2.0", id=1, method="db.query", params={"op": "SELECT"}
        )
        assert p.jsonrpc == "2.0"
        assert p.id == 1
        assert p.method == "db.query"

    def test_invalid_jsonrpc_rejected(self):
        with pytest.raises(ValidationError):
            ToolCallPayload(jsonrpc="1.0", id=1, method="test", params={})
