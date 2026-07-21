"""Demo executor — the real target the live demo pipeline executes against.

Runs approved db.query calls against the in-memory SQLite demo database.
This is a genuine Executor port implementation: the demo runs the same
EnforcementPipeline the /rpc endpoint uses, and this is where an allowed
request actually executes. http.* scenarios never reach here (they are
denied at egress), so only db.query is handled.
"""

from __future__ import annotations

from typing import Any

from agent_policy_gateway.core.pipeline import ExecutionError
from agent_policy_gateway.live_demo.database import execute_query


class DemoExecutor:
    """Executes approved demo actions; exposes the last raw rows for the UI."""

    def __init__(self) -> None:
        self.last_rows: list[dict] | None = None

    async def execute(
        self,
        method: str,
        params: dict[str, Any],
        creds: Any,
        tool_config: dict[str, Any] | None,
    ) -> Any:
        self.last_rows = None
        if method == "db.query":
            sql = params.get("query") or params.get("sql")
            if not sql:
                raise ExecutionError("no SQL query provided")
            try:
                rows = execute_query(sql)
            except Exception as exc:  # malformed LLM SQL is the target's problem
                raise ExecutionError(f"query execution error: {exc}") from None
            self.last_rows = rows
            return {"rows": rows}

        # No other tool is expected to reach execution in the demo
        raise ExecutionError(f"demo target does not implement '{method}'")
