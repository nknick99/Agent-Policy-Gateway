"""Tests for Agent Policy Gateway main FastAPI application and enforcement pipeline."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def policy_file(tmp_path):
    """Create a valid policy.json for testing."""
    policy = {
        "version": 1,
        "default": "deny",
        "caller_auth": {
            "method": "shared_token",
            "token_env": "APG_AGENT_TOKEN",
        },
        "session_limits": {
            "max_calls_per_session": 200,
            "max_records_per_session": 5000,
        },
        "tools": {
            "db.query": {
                "allow": True,
                "operations": ["SELECT"],
                "tables": ["users", "orders"],
                "constraints": {"limit": {"limit": 100}},
                "deny_keywords": ["DROP", "DELETE"],
                "destination_whitelist": [],
                "deny_destinations": [],
                "aws_role": "arn:aws:iam::123456789012:role/TestRole",
                "session_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["rds-data:ExecuteStatement"],
                            "Resource": "*",
                        }
                    ],
                },
            },
            "http.post": {
                "allow": True,
                "operations": ["POST"],
                "tables": [],
                "constraints": None,
                "deny_keywords": [],
                "destination_whitelist": ["api.example.com"],
                "deny_destinations": [],
                "aws_role": "arn:aws:iam::123456789012:role/HttpRole",
                "session_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["execute-api:Invoke"],
                            "Resource": "*",
                        }
                    ],
                },
            },
        },
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    return str(policy_path)


class FakeExecutor:
    """Executor port fake — records calls, returns a fixed result."""

    def __init__(self, result: dict | None = None):
        self.calls: list[tuple[str, dict]] = []
        self.result = result if result is not None else {"status": "executed"}

    async def execute(self, method, params, creds, tool_config):
        self.calls.append((method, params))
        return {**self.result, "method": method}


@pytest.fixture
def client(policy_file, monkeypatch):
    """Create a test client with properly initialized app.

    The pipeline's executor is replaced with a fake so the allow path
    completes without a live target (execution itself is covered by
    executor tests and the end-to-end smoke tests).
    """
    monkeypatch.setenv("APG_AGENT_TOKEN", "test-token-secret")
    monkeypatch.setenv("APG_MODE", "enforce")

    # Patch PolicyEvaluator to use our temp policy file
    with patch(
        "agent_policy_gateway.server.app.PolicyEvaluator",
        lambda: _make_policy_evaluator(policy_file),
    ):
        from agent_policy_gateway.server import app as app_module

        with TestClient(app_module.app) as tc:
            app_module.pipeline.executor = FakeExecutor()
            yield tc


def _make_policy_evaluator(policy_path: str):
    """Create a real PolicyEvaluator with the given policy path."""
    from agent_policy_gateway.core.policy import PolicyEvaluator

    return PolicyEvaluator(policy_path)


def _rpc_payload(
    method: str = "db.query",
    params: dict | None = None,
    request_id: int | str = 1,
) -> dict[str, Any]:
    """Build a valid JSON-RPC 2.0 payload."""
    if params is None:
        params = {"op": "SELECT", "table": "users", "limit": 10}
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }


# --- JSON-RPC 2.0 Protocol Compliance Tests ---


class TestJsonRpcCompliance:
    """Test JSON-RPC 2.0 protocol compliance (Requirements 13.1–13.7)."""

    def test_parse_error_invalid_json(self, client):
        """Requirement 13.5: body not valid JSON → -32700 with null id."""
        response = client.post(
            "/rpc",
            content=b"not valid json {{{",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-token-secret",
            },
        )
        data = response.json()
        assert data["jsonrpc"] == "2.0"
        assert data["id"] is None
        assert data["error"]["code"] == -32700
        assert "result" not in data

    def test_batch_rejection(self, client):
        """Requirement 13.6: JSON array (batch) → -32600."""
        response = client.post(
            "/rpc",
            content=json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "test"}]).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-token-secret",
            },
        )
        data = response.json()
        assert data["jsonrpc"] == "2.0"
        assert data["error"]["code"] == -32600
        assert "batch" in data["error"]["message"].lower()
        assert "result" not in data

    def test_notification_rejection(self, client):
        """Requirement 13.7: missing id (notification) → -32600."""
        response = client.post(
            "/rpc",
            content=json.dumps({"jsonrpc": "2.0", "method": "test"}).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-token-secret",
            },
        )
        data = response.json()
        assert data["jsonrpc"] == "2.0"
        assert data["error"]["code"] == -32600
        assert "notification" in data["error"]["message"].lower()
        assert "result" not in data

    def test_success_response_format(self, client):
        """Requirement 13.2: success has jsonrpc, id, result — no error."""
        response = client.post(
            "/rpc",
            content=json.dumps(_rpc_payload()).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-token-secret",
            },
        )
        data = response.json()
        assert data["jsonrpc"] == "2.0"
        assert data["id"] == 1
        assert "result" in data
        assert "error" not in data

    def test_error_response_format(self, client):
        """Requirement 13.3: error has jsonrpc, id, error with code/message."""
        # Send with wrong token to trigger auth failure
        response = client.post(
            "/rpc",
            content=json.dumps(_rpc_payload()).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer wrong-token",
            },
        )
        data = response.json()
        assert data["jsonrpc"] == "2.0"
        assert data["id"] == 1
        assert "error" in data
        assert "code" in data["error"]
        assert "message" in data["error"]
        assert "result" not in data

    def test_never_both_result_and_error(self, client):
        """Requirement 13.4: response has result XOR error, never both."""
        # Success case
        resp1 = client.post(
            "/rpc",
            content=json.dumps(_rpc_payload()).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-token-secret",
            },
        )
        data1 = resp1.json()
        has_result = "result" in data1
        has_error = "error" in data1
        assert has_result != has_error  # XOR

        # Error case
        resp2 = client.post(
            "/rpc",
            content=b"invalid",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-token-secret",
            },
        )
        data2 = resp2.json()
        has_result = "result" in data2
        has_error = "error" in data2
        assert has_result != has_error  # XOR


# --- Pipeline Order and Fail-Closed Tests ---


class TestPipelineEnforcement:
    """Test pipeline order and fail-closed behavior (Requirements 10.1, 10.4)."""

    def test_auth_failure_blocks_pipeline(self, client):
        """Authentication failure halts pipeline before schema validation."""
        response = client.post(
            "/rpc",
            content=json.dumps(_rpc_payload()).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer invalid-token",
            },
        )
        data = response.json()
        assert data["error"]["code"] == -32600
        assert "authentication" in data["error"]["message"].lower()

    def test_schema_validation_failure(self, client):
        """Schema validation error returns proper error code."""
        # Missing jsonrpc field
        payload = {"id": 1, "method": "db.query", "params": {}}
        response = client.post(
            "/rpc",
            content=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-token-secret",
            },
        )
        data = response.json()
        assert data["error"]["code"] == -32600

    def test_policy_denial_in_enforce_mode(self, client):
        """Unknown tools are denied by policy (default deny), not schema.

        Phase 1 (D11): the gateway fronts arbitrary MCP tools, so there
        is no hardcoded method registry — the policy allowlist decides.
        """
        payload = _rpc_payload(method="admin.delete", params={"target": "all"})
        response = client.post(
            "/rpc",
            content=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-token-secret",
            },
        )
        data = response.json()
        assert data["error"]["code"] == -32600
        assert "policy denied" in data["error"]["message"].lower()
        assert "admin.delete" in data["error"]["message"]

    def test_fail_closed_on_unhandled_exception(self, client):
        """Requirement 10.1: unhandled exception → -32603."""
        # Patch validate_envelope to raise unexpected error
        with patch(
            "agent_policy_gateway.core.pipeline.validate_envelope",
            side_effect=RuntimeError("Unexpected!"),
        ):
            response = client.post(
                "/rpc",
                content=json.dumps(_rpc_payload()).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer test-token-secret",
                },
            )
            data = response.json()
            assert data["error"]["code"] == -32603
            assert "internal error" in data["error"]["message"].lower()


# --- Correlation ID and Audit Tests ---


class TestCorrelationAndAudit:
    """Test correlation ID generation and audit emission."""

    def test_audit_event_emitted_on_success(self, client):
        """Audit logger emit is called for successful requests."""
        with patch("agent_policy_gateway.server.app.audit_logger") as mock_audit:
            mock_audit.generate_correlation_id.return_value = "test-corr-id"
            mock_audit.emit = MagicMock()

            client.post(
                "/rpc",
                content=json.dumps(_rpc_payload()).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer test-token-secret",
                },
            )
            # Audit emit should have been called
            assert mock_audit.emit.called

    def test_audit_event_emitted_on_error(self, client):
        """Audit logger emit is called even for error responses."""
        with patch("agent_policy_gateway.server.app.audit_logger") as mock_audit:
            mock_audit.generate_correlation_id.return_value = "test-corr-id"
            mock_audit.emit = MagicMock()

            client.post(
                "/rpc",
                content=b"bad json",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer test-token-secret",
                },
            )
            assert mock_audit.emit.called


# --- Execution and Credential Broker Tests (Phase 1) ---


class TestExecution:
    """The allow path executes through the injected executor port."""

    def test_executor_receives_allowed_call(self, client):
        from agent_policy_gateway.server import app as app_module

        client.post(
            "/rpc",
            content=json.dumps(_rpc_payload()).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-token-secret",
            },
        )
        executor = app_module.pipeline.executor
        assert executor.calls == [("db.query", {"op": "SELECT", "table": "users", "limit": 10})]

    def test_executor_not_called_on_denial(self, client):
        from agent_policy_gateway.server import app as app_module

        client.post(
            "/rpc",
            content=json.dumps(
                _rpc_payload(params={"op": "DROP", "table": "users"})
            ).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-token-secret",
            },
        )
        assert app_module.pipeline.executor.calls == []

    def test_no_target_fails_closed(self, client):
        """Without any configured target, the allow path returns -32603 —
        never a fabricated success."""
        from agent_policy_gateway.adapters.executors.http_jsonrpc import (
            HttpJsonRpcExecutor,
        )
        from agent_policy_gateway.server import app as app_module

        app_module.pipeline.executor = HttpJsonRpcExecutor(default_target=None)
        response = client.post(
            "/rpc",
            content=json.dumps(_rpc_payload()).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-token-secret",
            },
        )
        data = response.json()
        assert data["error"]["code"] == -32603
        assert "no execution target" in data["error"]["message"].lower()


class TestCredentialBroker:
    """credential_broker: none (default) skips minting; aws_sts mints."""

    def test_null_broker_default(self, client):
        from agent_policy_gateway.adapters.brokers.null_broker import NullBroker
        from agent_policy_gateway.server import app as app_module

        assert isinstance(app_module.pipeline.broker, NullBroker)

    def test_aws_sts_broker_mints(self, policy_file, monkeypatch, tmp_path):
        monkeypatch.setenv("APG_AGENT_TOKEN", "test-token-secret")
        monkeypatch.setenv("APG_MODE", "enforce")
        monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)

        # Same policy but with the STS broker opted in
        policy = json.loads(open(policy_file).read())
        policy["credential_broker"] = "aws_sts"
        sts_policy_path = tmp_path / "sts_policy.json"
        sts_policy_path.write_text(json.dumps(policy))

        with patch(
            "agent_policy_gateway.server.app.PolicyEvaluator",
            lambda: _make_policy_evaluator(str(sts_policy_path)),
        ):
            with patch("agent_policy_gateway.server.app.StsBroker") as mock_broker_cls:
                mock_broker = MagicMock()
                mock_broker.mint_credentials.return_value = MagicMock()
                mock_broker_cls.return_value = mock_broker

                from agent_policy_gateway.server import app as app_module

                with TestClient(app_module.app) as tc:
                    app_module.pipeline.executor = FakeExecutor()
                    response = tc.post(
                        "/rpc",
                        content=json.dumps(_rpc_payload()).encode(),
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": "Bearer test-token-secret",
                        },
                    )
                assert "result" in response.json()
                assert mock_broker.mint_credentials.called
                assert mock_broker.discard.called
