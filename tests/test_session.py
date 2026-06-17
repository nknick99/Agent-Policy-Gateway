"""Unit tests for session tracking and quota enforcement."""

import pytest

from kirogate.models import SessionLimits
from kirogate.session import SessionManager


@pytest.fixture
def session_manager():
    """Return a fresh SessionManager instance."""
    return SessionManager()


@pytest.fixture
def default_limits():
    """Return default session limits for testing."""
    return SessionLimits(max_calls_per_session=5, max_records_per_session=100)


class TestGetOrCreateSession:
    """Tests for get_or_create_session."""

    async def test_creates_new_session_for_unknown_caller(self, session_manager):
        session = await session_manager.get_or_create_session("agent-1")
        assert session.caller_identity == "agent-1"
        assert session.call_count == 0
        assert session.record_count == 0

    async def test_returns_same_session_for_same_caller(self, session_manager):
        session1 = await session_manager.get_or_create_session("agent-1")
        session2 = await session_manager.get_or_create_session("agent-1")
        assert session1 is session2
        assert session1.session_id == session2.session_id

    async def test_different_callers_get_different_sessions(self, session_manager):
        session1 = await session_manager.get_or_create_session("agent-1")
        session2 = await session_manager.get_or_create_session("agent-2")
        assert session1 is not session2
        assert session1.session_id != session2.session_id
        assert session1.caller_identity == "agent-1"
        assert session2.caller_identity == "agent-2"

    async def test_session_has_valid_uuid(self, session_manager):
        import uuid

        session = await session_manager.get_or_create_session("agent-1")
        # Should not raise
        uuid.UUID(session.session_id)


class TestCheckQuota:
    """Tests for quota enforcement."""

    async def test_new_session_within_quota(self, session_manager, default_limits):
        over_quota = await session_manager.check_quota("agent-1", default_limits)
        assert over_quota is False

    async def test_call_count_at_limit_exceeds_quota(self, session_manager, default_limits):
        session = await session_manager.get_or_create_session("agent-1")
        session.call_count = 5  # Equal to max_calls_per_session
        over_quota = await session_manager.check_quota("agent-1", default_limits)
        assert over_quota is True

    async def test_call_count_above_limit_exceeds_quota(self, session_manager, default_limits):
        session = await session_manager.get_or_create_session("agent-1")
        session.call_count = 10  # Above max_calls_per_session
        over_quota = await session_manager.check_quota("agent-1", default_limits)
        assert over_quota is True

    async def test_record_count_at_limit_exceeds_quota(self, session_manager, default_limits):
        session = await session_manager.get_or_create_session("agent-1")
        session.record_count = 100  # Equal to max_records_per_session
        over_quota = await session_manager.check_quota("agent-1", default_limits)
        assert over_quota is True

    async def test_record_count_above_limit_exceeds_quota(self, session_manager, default_limits):
        session = await session_manager.get_or_create_session("agent-1")
        session.record_count = 150  # Above max_records_per_session
        over_quota = await session_manager.check_quota("agent-1", default_limits)
        assert over_quota is True

    async def test_just_below_limits_is_within_quota(self, session_manager, default_limits):
        session = await session_manager.get_or_create_session("agent-1")
        session.call_count = 4  # One below max
        session.record_count = 99  # One below max
        over_quota = await session_manager.check_quota("agent-1", default_limits)
        assert over_quota is False


class TestRecordSuccess:
    """Tests for recording successful request completion."""

    async def test_increments_call_count(self, session_manager):
        await session_manager.get_or_create_session("agent-1")
        await session_manager.record_success("agent-1", record_count=0)
        session = await session_manager.get_or_create_session("agent-1")
        assert session.call_count == 1

    async def test_adds_record_count(self, session_manager):
        await session_manager.get_or_create_session("agent-1")
        await session_manager.record_success("agent-1", record_count=25)
        session = await session_manager.get_or_create_session("agent-1")
        assert session.call_count == 1
        assert session.record_count == 25

    async def test_multiple_successes_accumulate(self, session_manager):
        await session_manager.get_or_create_session("agent-1")
        await session_manager.record_success("agent-1", record_count=10)
        await session_manager.record_success("agent-1", record_count=20)
        await session_manager.record_success("agent-1", record_count=5)
        session = await session_manager.get_or_create_session("agent-1")
        assert session.call_count == 3
        assert session.record_count == 35

    async def test_counters_monotonically_non_decreasing(self, session_manager):
        """Requirement 7.3: counters never decrease."""
        await session_manager.get_or_create_session("agent-1")
        prev_calls = 0
        prev_records = 0
        for i in range(5):
            await session_manager.record_success("agent-1", record_count=i * 3)
            session = await session_manager.get_or_create_session("agent-1")
            assert session.call_count >= prev_calls
            assert session.record_count >= prev_records
            prev_calls = session.call_count
            prev_records = session.record_count

    async def test_zero_record_count_still_increments_calls(self, session_manager):
        await session_manager.get_or_create_session("agent-1")
        await session_manager.record_success("agent-1", record_count=0)
        session = await session_manager.get_or_create_session("agent-1")
        assert session.call_count == 1
        assert session.record_count == 0


class TestDeniedRequestsNoIncrement:
    """Requirement 7.5: Denied requests do NOT increment counters."""

    async def test_denied_request_does_not_change_counters(self, session_manager, default_limits):
        """When check_quota returns True (deny), counters should not change."""
        session = await session_manager.get_or_create_session("agent-1")
        session.call_count = 5  # At the limit

        # Check quota - should be denied
        over_quota = await session_manager.check_quota("agent-1", default_limits)
        assert over_quota is True

        # Counters remain unchanged (no record_success called)
        assert session.call_count == 5
        assert session.record_count == 0
