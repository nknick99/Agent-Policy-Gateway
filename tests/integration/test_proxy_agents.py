"""End-to-end test for per-agent identity through the real proxy.

A policy defines two agents with different tokens and different tool scopes.
The proxy must (a) attribute each request to the right agent, (b) let an agent
call only the tools it is scoped to, and (c) record the agent id in the audit
trail.
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

AGENTS_POLICY = {
    "version": 1,
    "default": "deny",
    "caller_auth": {"method": "shared_token"},
    "session_limits": {},
    "tools": {
        "db.query": {
            "allow": True,
            "operations": ["select"],
            "tables": ["users"],
            "sql": {"dialect": "", "params": ["query", "sql"]},
        },
        "http.get": {
            "allow": True,
            "operations": ["GET"],
            "destination_whitelist": ["https://api.example.com"],
        },
    },
    "agents": {
        "reader": {"token_env": "TOK_READER", "tools": ["db.query"]},
        "fetcher": {"token_env": "TOK_FETCHER", "tools": ["http.get"]},
    },
}


def _free_port() -> int:
    with contextlib.closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _make_target_app() -> FastAPI:
    app = FastAPI()

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def echo(request: Request, path: str = ""):
        return {"server": "real-target"}

    return app


class _ThreadedTarget:
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
def target_url():
    port = _free_port()
    target = _ThreadedTarget(_make_target_app(), port)
    target.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        target.stop()


@pytest_asyncio.fixture()
async def proxy(target_url, tmp_path, monkeypatch):
    monkeypatch.setenv("TOK_READER", "reader-token")
    monkeypatch.setenv("TOK_FETCHER", "fetcher-token")
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(AGENTS_POLICY))
    audit_file = tmp_path / "audit.jsonl"
    app = create_proxy_app(
        target_url=target_url,
        policy_path=str(policy_file),
        audit_file=str(audit_file),
        mode="enforce",
    )
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
        yield client, audit_file


def _rpc(method: str, params: dict) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}


def _read_audit(audit_file: Path) -> list[dict]:
    if not audit_file.exists():
        return []
    return [json.loads(line) for line in audit_file.read_text().splitlines() if line.strip()]


async def test_agent_can_call_its_scoped_tool(proxy):
    client, audit_file = proxy
    resp = await client.post(
        "/",
        json=_rpc("db.query", {"op": "select", "query": "SELECT * FROM users"}),
        headers={"Authorization": "Bearer reader-token"},
    )
    assert resp.status_code == 200
    assert resp.json()["server"] == "real-target"

    allow = [e for e in _read_audit(audit_file) if e["outcome"] == "ALLOW"]
    assert allow and allow[0]["agent_id"] == "reader"


async def test_agent_denied_tool_outside_its_scope(proxy):
    client, audit_file = proxy
    resp = await client.post(
        "/",
        json=_rpc("http.get", {"op": "GET", "url": "https://api.example.com/x"}),
        headers={"Authorization": "Bearer reader-token"},
    )
    body = resp.json()
    assert "error" in body
    assert "not permitted to call 'http.get'" in body["error"]["message"]
    assert "server" not in body

    deny = [e for e in _read_audit(audit_file) if e["outcome"] == "DENY"]
    assert deny and deny[0]["agent_id"] == "reader"


async def test_other_agent_has_its_own_scope(proxy):
    client, _ = proxy
    # fetcher may call http.get ...
    ok = await client.post(
        "/",
        json=_rpc("http.get", {"op": "GET", "url": "https://api.example.com/x"}),
        headers={"Authorization": "Bearer fetcher-token"},
    )
    assert ok.json()["server"] == "real-target"

    # ... but not db.query
    denied = await client.post(
        "/",
        json=_rpc("db.query", {"op": "select", "query": "SELECT * FROM users"}),
        headers={"Authorization": "Bearer fetcher-token"},
    )
    assert "not permitted to call 'db.query'" in denied.json()["error"]["message"]


async def test_unknown_token_rejected(proxy):
    client, _ = proxy
    resp = await client.post(
        "/",
        json=_rpc("db.query", {"op": "select", "query": "SELECT * FROM users"}),
        headers={"Authorization": "Bearer intruder"},
    )
    assert resp.status_code == 401
