"""In-memory per-caller session tracking and quota enforcement."""

from __future__ import annotations

import asyncio
import uuid

from agent_policy_gateway.core.models import SessionLimits, SessionState


class SessionManager:
    """Manages in-memory session state per caller for quota enforcement.

    Uses an asyncio.Lock to ensure safe concurrent access in async contexts.
    Sessions persist for the lifetime of the process (no TTL/eviction).
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}
        self._lock = asyncio.Lock()

    async def get_or_create_session(self, caller_id: str) -> SessionState:
        """Retrieve existing session or create a new one for the given caller.

        Args:
            caller_id: Unique identifier for the calling agent.

        Returns:
            The SessionState associated with the caller.
        """
        async with self._lock:
            if caller_id not in self._sessions:
                self._sessions[caller_id] = SessionState(
                    session_id=str(uuid.uuid4()),
                    caller_identity=caller_id,
                )
            return self._sessions[caller_id]

    async def check_quota(self, caller_id: str, limits: SessionLimits) -> bool:
        """Check whether the caller has exceeded session quota limits.

        This should be called *before* credential minting. If True is returned,
        the request must be denied with JSON-RPC error -32600 "quota exceeded".

        Args:
            caller_id: Unique identifier for the calling agent.
            limits: The session limits from the policy document.

        Returns:
            True if the caller has exceeded quota (request should be denied),
            False if the caller is within quota (request may proceed).
        """
        session = await self.get_or_create_session(caller_id)
        return session.exceeds_limits(limits)

    async def record_success(self, caller_id: str, record_count: int = 0) -> None:
        """Record a successful request completion.

        Increments call_count by 1 and adds the returned record count.
        Must only be called after a request completes successfully.
        Do NOT call this for denied requests.

        Args:
            caller_id: Unique identifier for the calling agent.
            record_count: Number of records returned by the successful request.
        """
        session = await self.get_or_create_session(caller_id)
        async with self._lock:
            session.increment_calls()
            if record_count > 0:
                session.add_records(record_count)
