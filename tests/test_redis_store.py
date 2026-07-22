"""Tests for the Redis session store and the session-store factory.

Uses fakeredis (an in-process Redis fake) so no real server is required. The
cross-replica test is the point of the whole exercise (D7): two stores pointed
at the same backend share quota state, instead of each counting on its own.
"""

from __future__ import annotations

import pytest
from fakeredis import FakeServer
from fakeredis.aioredis import FakeRedis

from agent_policy_gateway.adapters.state import RedisSessionStore, build_session_store
from agent_policy_gateway.core.models import SessionLimits
from agent_policy_gateway.core.session import SessionManager

LIMITS = SessionLimits(max_calls_per_session=3, max_records_per_session=100)


@pytest.fixture()
def store():
    return RedisSessionStore(FakeRedis(decode_responses=True))


class TestCounters:
    async def test_record_success_increments_calls(self, store):
        await store.record_success("agent-1")
        await store.record_success("agent-1")
        calls, records = await store.get_counts("agent-1")
        assert calls == 2
        assert records == 0

    async def test_record_success_adds_records(self, store):
        await store.record_success("agent-1", record_count=25)
        await store.record_success("agent-1", record_count=10)
        _, records = await store.get_counts("agent-1")
        assert records == 35

    async def test_unknown_caller_has_zero_counts(self, store):
        assert await store.get_counts("nobody") == (0, 0)


class TestQuota:
    async def test_within_quota(self, store):
        await store.record_success("agent-1")
        assert await store.check_quota("agent-1", LIMITS) is False

    async def test_call_count_at_limit_exceeds(self, store):
        for _ in range(3):
            await store.record_success("agent-1")
        assert await store.check_quota("agent-1", LIMITS) is True

    async def test_record_count_at_limit_exceeds(self, store):
        await store.record_success("agent-1", record_count=100)
        assert await store.check_quota("agent-1", LIMITS) is True

    async def test_callers_are_independent(self, store):
        for _ in range(3):
            await store.record_success("agent-1")
        assert await store.check_quota("agent-1", LIMITS) is True
        assert await store.check_quota("agent-2", LIMITS) is False


class TestCrossReplicaSharing:
    async def test_two_replicas_share_quota_state(self):
        # Two stores (two "replicas") pointed at one Redis backend.
        server = FakeServer()
        replica_a = RedisSessionStore(FakeRedis(server=server, decode_responses=True))
        replica_b = RedisSessionStore(FakeRedis(server=server, decode_responses=True))

        # Replica A serves two calls, replica B serves one — three total.
        await replica_a.record_success("agent-1")
        await replica_a.record_success("agent-1")
        await replica_b.record_success("agent-1")

        # Either replica sees the shared total and enforces the limit. With the
        # old in-memory dicts, each replica would still read its own 1-2 calls.
        assert await replica_a.check_quota("agent-1", LIMITS) is True
        assert await replica_b.check_quota("agent-1", LIMITS) is True


class TestTtl:
    async def test_ttl_set_on_write(self):
        client = FakeRedis(decode_responses=True)
        store = RedisSessionStore(client, ttl_seconds=60)
        await store.record_success("agent-1")
        assert 0 < await client.ttl("apg:session:agent-1") <= 60

    async def test_no_ttl_by_default(self, store):
        await store.record_success("agent-1")
        # -1 == key exists with no expiry.
        assert await store._redis.ttl("apg:session:agent-1") == -1


class TestFactory:
    def test_no_env_uses_in_memory(self, monkeypatch):
        monkeypatch.delenv("APG_REDIS_URL", raising=False)
        assert isinstance(build_session_store(), SessionManager)

    def test_redis_url_selects_redis_store(self, monkeypatch):
        # from_url is lazy — no connection is made here.
        monkeypatch.setenv("APG_REDIS_URL", "redis://localhost:6379/0")
        assert isinstance(build_session_store(), RedisSessionStore)
