"""End-to-end test for `apg wrap` — the stdio transport.

Spawns the real CLI (`apg wrap ... -- python _stdio_echo_server.py`), which in
turn spawns the echo server as its child, and drives the whole pipe over real
stdin/stdout. Proves that allowed tools/call messages reach the child and its
response comes back, that denied ones are answered by an apg error without ever
reaching the child, and that the audit log is written.
"""

from __future__ import annotations

import json
import select
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "policy.json"
ECHO_SERVER = Path(__file__).resolve().parent / "_stdio_echo_server.py"


def _send(proc: subprocess.Popen, obj: dict) -> None:
    assert proc.stdin is not None
    proc.stdin.write((json.dumps(obj) + "\n").encode())
    proc.stdin.flush()


def _recv(proc: subprocess.Popen, timeout: float = 10.0) -> dict:
    assert proc.stdout is not None
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    if not ready:
        raise TimeoutError("no response from `apg wrap` within timeout")
    return json.loads(proc.stdout.readline().decode())


@pytest.fixture()
def wrap_proc(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    stderr_file = (tmp_path / "stderr.log").open("wb")
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agent_policy_gateway.cli",
            "wrap",
            "--policy",
            str(POLICY_PATH),
            "--audit-file",
            str(audit_file),
            "--",
            sys.executable,
            str(ECHO_SERVER),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr_file,
        bufsize=0,
    )
    try:
        yield proc, audit_file
    finally:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        stderr_file.close()


def _read_audit(audit_file: Path) -> list[dict]:
    if not audit_file.exists():
        return []
    return [json.loads(line) for line in audit_file.read_text().splitlines() if line.strip()]


def test_non_tool_traffic_passes_through(wrap_proc):
    proc, _ = wrap_proc
    _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    resp = _recv(proc)
    assert resp["id"] == 1
    assert resp["result"]["server"] == "real-mcp"


def test_allowed_call_reaches_child(wrap_proc):
    proc, audit_file = wrap_proc
    _send(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "db.query", "arguments": {"op": "select", "query": "SELECT 1"}},
        },
    )
    resp = _recv(proc)
    # The echo server answered — proves the call traversed the child.
    assert resp["result"]["echoed"] == "db.query"
    assert resp["result"]["server"] == "real-mcp"

    proc.stdin.close()
    proc.wait(timeout=10)
    events = _read_audit(audit_file)
    allow = [e for e in events if e["outcome"] == "ALLOW"]
    assert allow and allow[0]["transport"] == "stdio"


def test_denied_call_blocked_before_child(wrap_proc):
    proc, audit_file = wrap_proc
    _send(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "db.query", "arguments": {"op": "drop"}},
        },
    )
    resp = _recv(proc)
    # An apg error, not the echo server's result — the child never saw it.
    assert resp["id"] == 3
    assert "error" in resp
    assert "Policy denied" in resp["error"]["message"]
    assert "result" not in resp

    proc.stdin.close()
    proc.wait(timeout=10)
    deny = [e for e in _read_audit(audit_file) if e["outcome"] == "DENY"]
    assert deny and deny[0]["method"] == "db.query"


def test_unknown_tool_denied(wrap_proc):
    proc, _ = wrap_proc
    _send(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "fs.read", "arguments": {"path": "/etc/passwd"}},
        },
    )
    resp = _recv(proc)
    assert "error" in resp
    assert "Policy denied" in resp["error"]["message"]
