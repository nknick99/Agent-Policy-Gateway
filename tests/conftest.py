"""Shared test fixtures for KiroGate tests."""

import pytest


@pytest.fixture
def sample_policy():
    """Return a minimal valid policy document for testing."""
    return {
        "default": "deny",
        "caller_auth": {
            "type": "bearer_token",
            "env_var": "KIROGATE_AGENT_TOKEN",
        },
        "session_limits": {
            "max_calls_per_session": 100,
            "max_records_per_session": 10000,
        },
        "tools": {
            "db.query": {
                "allow": True,
                "operations": ["SELECT"],
                "tables": ["users", "orders"],
                "constraints": {"max_rows": 1000},
                "deny_keywords": ["DROP", "DELETE", "UPDATE", "INSERT"],
                "aws_role": "arn:aws:iam::123456789012:role/KiroGate-DBQuery",
                "session_policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["rds-data:ExecuteStatement"],"Resource":"*"}]}',
            },
            "http.post": {
                "allow": True,
                "operations": ["POST"],
                "destination_whitelist": ["api.example.com", "hooks.slack.com"],
                "deny_destinations": ["metadata.google.internal"],
                "constraints": {"max_body_bytes": 10240},
                "deny_keywords": ["password", "secret"],
                "aws_role": "arn:aws:iam::123456789012:role/KiroGate-HttpPost",
                "session_policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["execute-api:Invoke"],"Resource":"*"}]}',
            },
        },
    }


@pytest.fixture
def valid_rpc_request():
    """Return a valid JSON-RPC 2.0 request payload."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "db.query",
        "params": {
            "operation": "SELECT",
            "table": "users",
            "query": "SELECT id, name FROM users WHERE active = true",
            "max_rows": 100,
        },
    }


@pytest.fixture
def auth_headers():
    """Return valid authorization headers."""
    return {"Authorization": "Bearer test-token-12345"}
