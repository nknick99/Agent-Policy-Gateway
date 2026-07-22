"""A minimal stdio MCP-style server used as the child in wrap integration tests.

Reads newline-delimited JSON-RPC requests on stdin and replies on stdout with a
result that echoes the request, so tests can prove a message really traversed
the child process (rather than being answered by the wrapper). Exits on EOF.
"""

from __future__ import annotations

import json
import sys


def main() -> None:
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = req.get("method")
        req_id = req.get("id")
        if method == "tools/call":
            name = (req.get("params") or {}).get("name")
            result = {"echoed": name, "server": "real-mcp"}
        else:
            result = {"method": method, "server": "real-mcp"}

        # Notifications have no id and expect no response.
        if req_id is not None:
            sys.stdout.write(
                json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}) + "\n"
            )
            sys.stdout.flush()


if __name__ == "__main__":
    main()
