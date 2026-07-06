"""Agent Policy Gateway Dashboard API.

REST endpoints that power the Next.js frontend console.
Provides system status, policy info, audit events, and demo scenarios.
"""

from agent_policy_gateway.dashboard_api.router import router as dashboard_router

__all__ = ["dashboard_router"]
