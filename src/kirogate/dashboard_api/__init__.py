"""KiroGate Dashboard API.

REST endpoints that power the Next.js frontend console.
Provides system status, policy info, audit events, and demo scenarios.
"""

from kirogate.dashboard_api.router import router as dashboard_router

__all__ = ["dashboard_router"]
