"""Compatibility entry point — the application lives in agent_policy_gateway.server.app.

Kept so `uvicorn agent_policy_gateway.server.app:app` continues to work.
"""

from agent_policy_gateway.server.app import app

__all__ = ["app"]
