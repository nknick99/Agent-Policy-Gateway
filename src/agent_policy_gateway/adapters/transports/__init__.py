"""Transport adapters — how the gateway speaks to clients and targets.

- ``http`` (the FastAPI proxy in ``proxy_app``) fronts HTTP MCP servers.
- ``stdio`` wraps a subprocess MCP server (the common case) so that
  ``apg wrap -- npx some-mcp-server`` enforces policy on every tools/call.
"""
