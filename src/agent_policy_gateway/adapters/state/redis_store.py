"""Redis-backed session store — shared quota state across replicas (fixes D7).

The in-memory store keeps counters in a Python dict, so N replicas each track
their own counters and the effective quota becomes N × the configured limit.
Backing the counters with Redis makes the state shared: `record_success` uses
atomic `HINCRBY`, so concurrent increments from any replica are correct.

`redis` is an optional dependency (`pip install "agent-policy-gateway[redis]"`);
it is imported lazily so the default install and the CLI happy path never need
it. A client can be injected (for tests) or built from a URL.

Note on the check-then-act window: `check_quota` reads and `record_success`
increments as separate steps, so two replicas racing at the exact limit can
overshoot by a request or two — acceptable for soft quotas, and vastly better
than the N× multiplication the per-replica dict caused.
"""

from __future__ import annotations

from typing import Any

from agent_policy_gateway.core.models import SessionLimits


class RedisSessionStore:
    """Session/quota counters stored in Redis hashes, one per caller."""

    def __init__(
        self,
        client: Any,
        key_prefix: str = "apg:session:",
        ttl_seconds: int | None = None,
    ) -> None:
        self._redis = client
        self._prefix = key_prefix
        self._ttl = ttl_seconds

    @classmethod
    def from_url(
        cls,
        url: str,
        key_prefix: str = "apg:session:",
        ttl_seconds: int | None = None,
    ) -> RedisSessionStore:
        """Build a store from a redis:// URL (lazy import of redis.asyncio)."""
        import redis.asyncio as redis  # imported lazily; optional dependency

        client = redis.from_url(url, decode_responses=True)
        return cls(client, key_prefix=key_prefix, ttl_seconds=ttl_seconds)

    def _key(self, caller_id: str) -> str:
        return f"{self._prefix}{caller_id}"

    async def check_quota(self, caller_id: str, limits: SessionLimits) -> bool:
        calls, records = await self.get_counts(caller_id)
        return (
            calls >= limits.max_calls_per_session
            or records >= limits.max_records_per_session
        )

    async def record_success(self, caller_id: str, record_count: int = 0) -> None:
        key = self._key(caller_id)
        pipe = self._redis.pipeline()
        pipe.hincrby(key, "calls", 1)
        if record_count > 0:
            pipe.hincrby(key, "records", record_count)
        if self._ttl is not None:
            pipe.expire(key, self._ttl)
        await pipe.execute()

    async def get_counts(self, caller_id: str) -> tuple[int, int]:
        """Return (call_count, record_count) for a caller."""
        calls, records = await self._redis.hmget(self._key(caller_id), "calls", "records")
        return int(calls or 0), int(records or 0)

    async def close(self) -> None:
        aclose = getattr(self._redis, "aclose", None)
        if aclose is not None:
            await aclose()
