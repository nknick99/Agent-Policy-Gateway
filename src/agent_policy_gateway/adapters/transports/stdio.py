"""stdio transport — policy enforcement for subprocess MCP servers.

Most real MCP servers run over stdio: the client spawns the server as a child
process and exchanges newline-delimited JSON-RPC messages over its
stdin/stdout. `apg wrap -- <command>` inserts the gateway into that pipe:

    MCP client  <->  apg wrap (this)  <->  child MCP server (the command)

The wrapper reads each JSON-RPC message the client sends, and for `tools/call`
messages evaluates it against policy through the one shared engine
(:func:`evaluate_call`). Allowed calls (and all non-tool traffic like
`initialize`/`tools/list`) are forwarded verbatim to the child; denied calls
are answered directly with a JSON-RPC error and never reach the child.

There is no network boundary here — the trust boundary is the process spawn,
so unlike the HTTP proxy there is no bearer-token step. Human-facing output
must go to stderr; stdout is reserved for the JSON-RPC channel.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from agent_policy_gateway.adapters.audit import build_audit_sink
from agent_policy_gateway.adapters.audit.jsonl import attempt_summary
from agent_policy_gateway.core.enforcement import evaluate_call
from agent_policy_gateway.core.policy import PolicyEvaluator


@dataclass(frozen=True)
class RouteResult:
    """Decision for a single client→server message.

    Attributes:
        forward: Whether to forward the original message to the child server.
        response: A JSON-RPC error line to send back to the client instead of
            forwarding (only set when ``forward`` is False).
        method: The tool name, if this was a tools/call (for audit); else None.
        outcome: "ALLOW", "DENY", or "PASS_THROUGH".
        reason: Denial reason, if any.
        attempt: op/table/destination summary for learning mode.
    """

    forward: bool
    response: str | None
    method: str | None
    outcome: str
    reason: str | None
    attempt: dict[str, Any] = field(default_factory=dict)


def _error_line(request_id: Any, reason: str) -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32600, "message": f"Policy denied: {reason}"},
        }
    )


def route_message(
    line: bytes, evaluator: PolicyEvaluator, mode: str = "enforce"
) -> RouteResult:
    """Decide what to do with one newline-delimited JSON-RPC message.

    Pure and side-effect-free — this is where all policy logic for the stdio
    transport lives, so it can be exhaustively unit-tested without spawning a
    subprocess. The asyncio plumbing in :func:`run_stdio_proxy` only moves
    bytes around based on what this returns.
    """
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Not JSON we understand — pass it through untouched rather than
        # dropping it (e.g. a blank keepalive line).
        return RouteResult(True, None, None, "PASS_THROUGH", None)

    if not isinstance(payload, dict) or payload.get("method") != "tools/call":
        # initialize / tools/list / notifications / responses — not a tool
        # call, so policy doesn't apply. Forward verbatim.
        return RouteResult(True, None, None, "PASS_THROUGH", None)

    call_params = payload.get("params") or {}
    method_name = call_params.get("name", "")
    arguments = call_params.get("arguments") or {}

    decision = evaluate_call(evaluator, method_name, arguments)
    summary = attempt_summary(arguments)

    if decision.allowed:
        return RouteResult(True, None, method_name, "ALLOW", None, summary)

    if mode == "audit":
        # Audit mode: log the denial but still let it through, so operators can
        # observe real traffic before switching to enforce.
        return RouteResult(True, None, method_name, "DENY", decision.reason, summary)

    return RouteResult(
        forward=False,
        response=_error_line(payload.get("id"), decision.reason or "policy denied"),
        method=method_name,
        outcome="DENY",
        reason=decision.reason,
        attempt=summary,
    )


def _audit_event(result: RouteResult, mode: str, latency_ms: float) -> dict[str, Any]:
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "transport": "stdio",
        "outcome": result.outcome,
        "method": result.method,
        "reason": result.reason,
        "latency_ms": round(latency_ms, 2),
        "mode": mode,
        **result.attempt,
    }


async def _connect_stdin(loop: asyncio.AbstractEventLoop) -> asyncio.StreamReader:
    """Wire the process's real stdin into an asyncio StreamReader."""
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    return reader


async def run_stdio_proxy(
    command: list[str],
    evaluator: PolicyEvaluator,
    audit_file: str = "apg-audit.jsonl",
    mode: str = "enforce",
) -> int:
    """Run the stdio wrapper until the client or child server closes.

    Spawns ``command`` as the child MCP server and pumps three streams
    concurrently: client→server (with policy enforcement), server→client, and
    the child's stderr (surfaced on our stderr so its logs don't corrupt the
    JSON-RPC channel on stdout). Returns the child's exit code.
    """
    loop = asyncio.get_running_loop()
    audit_sink = build_audit_sink(audit_file)
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdin_reader = await _connect_stdin(loop)
    write_lock = asyncio.Lock()

    async def write_client(data: bytes) -> None:
        # A single lock serialises the two producers (denial responses and
        # forwarded server output) so lines never interleave on stdout.
        async with write_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    async def pump_client_to_server() -> None:
        while True:
            line = await stdin_reader.readline()
            if not line:
                break
            start = time.monotonic()
            result = route_message(line, evaluator, mode)
            if result.method is not None:
                audit_sink.write(
                    _audit_event(result, mode, (time.monotonic() - start) * 1000)
                )
            if result.forward:
                if proc.stdin is not None:
                    proc.stdin.write(line)
                    await proc.stdin.drain()
            elif result.response is not None:
                await write_client(result.response.encode() + b"\n")
        if proc.stdin is not None:
            proc.stdin.close()

    async def pump_server_to_client() -> None:
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            await write_client(line)

    async def pump_stderr() -> None:
        assert proc.stderr is not None
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    pumps = [
        asyncio.create_task(pump_client_to_server()),
        asyncio.create_task(pump_server_to_client()),
        asyncio.create_task(pump_stderr()),
    ]
    await proc.wait()
    for task in pumps:
        task.cancel()
    await asyncio.gather(*pumps, return_exceptions=True)
    audit_sink.close()
    return proc.returncode or 0


def wrap(
    command: list[str],
    evaluator: PolicyEvaluator,
    audit_file: str = "apg-audit.jsonl",
    mode: str = "enforce",
) -> int:
    """Synchronous entry point for the CLI: run the stdio proxy to completion."""
    return asyncio.run(run_stdio_proxy(command, evaluator, audit_file, mode))
