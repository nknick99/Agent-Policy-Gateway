"""End-to-end integration tests for the `apg proxy` enforcement path.

These are the tests that lock in the Phase 1 exit criterion: every README
claim reproduces through the *real* pipeline. Unlike the unit tests, each case
here stands up a genuine target HTTP server, runs the real `create_proxy_app`
against it, and asserts the full behaviour — auth, policy allow/deny, egress,
forwarding, and the audit trail.

Defects locked in:
    D1  real execution — allowed calls actually reach the target and return
        the target's response (no stubbed payload).
    D2  egress whitelist matches correctly (whitelisted host forwarded,
        non-whitelisted host denied).
    D6  auth is enforced — a request with no/wrong token is rejected 401.
    D11 unknown tools are denied by *policy* (default deny), not by a
        hardcoded schema layer.
"""

from __future__ import annotations

import contextlib
import json
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import uvicorn
from fastapi import FastAPI, Request
from httpx import ASGITransport

from agent_policy_gateway.proxy_app import create_proxy_app

POLICY_PATH = Path(__file__).resolve().parents[2] / "policy.json"
TOKEN = "integration-test-token"


# ─── A real target MCP server (echoes what it receives) ───


def _free_port() -> int:
    with contextlib.closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _make_target_app() -> FastAPI:
    app = FastAPI()

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def echo(request: Request, path: str = ""):
        body = await request.body()
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            payload = {}
        # A field the proxy could never invent — proves the request really
        # traversed the target (rather than being answered by a stub).
        return {"server": "real-target", "echoed": payload}

    return app


class _ThreadedTarget:
    """Runs a uvicorn server in a background thread for the test's lifetime."""

    def __init__(self, app: FastAPI, port: int) -> None:
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("target server failed to start")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


@pytest.fixture()
def target_url() -> str:
    port = _free_port()
    target = _ThreadedTarget(_make_target_app(), port)
    target.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        target.stop()


@pytest_asyncio.fixture()
async def proxy(target_url, tmp_path, monkeypatch):
    """An httpx client wired to the real proxy app + a temp audit file."""
    monkeypatch.setenv("APG_AGENT_TOKEN", TOKEN)
    audit_file = tmp_path / "audit.jsonl"
    app = create_proxy_app(
        target_url=target_url,
        policy_path=str(POLICY_PATH),
        audit_file=str(audit_file),
        mode="enforce",
    )
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
        yield client, audit_file


def _rpc(method: str, params: dict) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}


def _auth() -> dict:
    return {"Authorization": f"Bearer {TOKEN}"}


def _read_audit(audit_file: Path) -> list[dict]:
    if not audit_file.exists():
        return []
    return [json.loads(line) for line in audit_file.read_text().splitlines() if line.strip()]


# ─── D1: real execution — allowed calls reach the target ───


async def test_allowed_call_reaches_real_target(proxy):
    client, audit_file = proxy
    resp = await client.post(
        "/", json=_rpc("db.query", {"op": "select", "query": "SELECT * FROM users"}), headers=_auth()
    )
    assert resp.status_code == 200
    body = resp.json()
    # The response is the target's, not a stub — proves D1 is really wired.
    assert body["server"] == "real-target"
    assert body["echoed"]["method"] == "db.query"

    events = _read_audit(audit_file)
    allow = [e for e in events if e["outcome"] == "ALLOW"]
    assert len(allow) == 1
    assert allow[0]["method"] == "db.query"
    assert allow[0]["target_status"] == 200
    assert "correlation_id" in allow[0]
    assert "latency_ms" in allow[0]


# ─── Policy deny — blocked before the target, with the rule cited ───


async def test_denied_operation_blocked_before_target(proxy):
    client, audit_file = proxy
    resp = await client.post(
        "/", json=_rpc("db.query", {"op": "drop", "query": "DROP TABLE users"}), headers=_auth()
    )
    body = resp.json()
    assert "error" in body
    assert "Policy denied" in body["error"]["message"]
    # Never reached the target.
    assert "server" not in body

    events = _read_audit(audit_file)
    deny = [e for e in events if e["outcome"] == "DENY"]
    assert len(deny) == 1
    assert deny[0]["reason"] is not None
    # Attempt detail captured for learning mode.
    assert deny[0]["op"] == "drop"


# ─── D11: unknown tools denied by policy, not a hardcoded schema ───


async def test_unknown_tool_default_denied(proxy):
    client, _ = proxy
    resp = await client.post(
        "/", json=_rpc("fs.read", {"path": "/etc/passwd"}), headers=_auth()
    )
    body = resp.json()
    assert "error" in body
    assert "Policy denied" in body["error"]["message"]
    assert "not listed in the policy" in body["error"]["message"]


# ─── D6: auth is enforced ───


async def test_missing_token_rejected(proxy):
    client, _ = proxy
    resp = await client.post(
        "/", json=_rpc("db.query", {"op": "select", "query": "SELECT 1"})
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["message"] == "Authentication failed"


async def test_wrong_token_rejected(proxy):
    client, _ = proxy
    resp = await client.post(
        "/",
        json=_rpc("db.query", {"op": "select", "query": "SELECT 1"}),
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


# ─── D2: egress whitelist matches correctly ───


async def test_whitelisted_destination_forwarded(proxy):
    client, _ = proxy
    resp = await client.post(
        "/",
        json=_rpc("http.get", {"op": "GET", "url": "https://api.example.com/data"}),
        headers=_auth(),
    )
    assert resp.status_code == 200
    assert resp.json()["server"] == "real-target"


async def test_non_whitelisted_destination_denied(proxy):
    client, _ = proxy
    resp = await client.post(
        "/",
        json=_rpc("http.get", {"op": "GET", "url": "https://evil.example.net/steal"}),
        headers=_auth(),
    )
    body = resp.json()
    assert "error" in body
    assert "Egress denied" in body["error"]["message"]
    assert "server" not in body
