"""Agent Policy Gateway data models and shared types."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# --- Enums ---


class Decision(Enum):
    """Policy evaluation decision."""

    ALLOW = "allow"
    DENY = "deny"


class AuditDecision(Enum):
    """Audit log decision outcome."""

    ALLOW = "allow"
    DENY = "deny"


# --- Policy Document Models ---


class CallerAuth(BaseModel):
    """Caller authentication configuration."""

    model_config = ConfigDict(frozen=True)

    method: Literal["shared_token"]
    token_env: str = "APG_AGENT_TOKEN"


class SessionLimits(BaseModel):
    """Per-session aggregate quota limits."""

    model_config = ConfigDict(frozen=True)

    max_calls_per_session: int = Field(ge=1, default=200)
    max_records_per_session: int = Field(ge=1, default=5000)


class Constraints(BaseModel):
    """Parameter constraints for a tool (e.g., max row limit)."""

    model_config = ConfigDict(frozen=True)

    limit: dict[str, int] | None = None


class SqlPolicy(BaseModel):
    """Opt-in SQL parsing for a tool.

    When present, the engine parses the SQL string found under one of `params`
    and enforces the tool's `operations`/`tables` allowlists against the
    *parsed* operation and tables — deterministic, not substring matching.
    """

    model_config = ConfigDict(frozen=True)

    dialect: str = ""  # "" -> sqlglot's default parser
    params: list[str] = ["query", "sql"]  # request keys the SQL string lives under


class ToolConfig(BaseModel):
    """Configuration for a single tool in the policy document."""

    model_config = ConfigDict(frozen=True)

    allow: bool = False
    operations: list[str] = []
    tables: list[str] = []
    constraints: Constraints | None = None
    deny_keywords: list[str] = []
    destination_whitelist: list[str] = []
    deny_destinations: list[str] = []
    aws_role: str = ""
    session_policy: dict = {}
    # Per-tool execution target; falls back to APG_TARGET_URL when empty
    target_url: str = ""
    # Opt-in real SQL parsing; None keeps behavior unchanged (no parsing)
    sql: SqlPolicy | None = None


class PolicyDocument(BaseModel):
    """Top-level immutable policy configuration loaded at startup."""

    model_config = ConfigDict(frozen=True)

    version: int = 1
    default: Literal["deny"] = "deny"
    caller_auth: CallerAuth
    session_limits: SessionLimits
    tools: dict[str, ToolConfig]
    # Per-request credential minting is opt-in; "none" keeps the happy
    # path free of external dependencies
    credential_broker: Literal["none", "aws_sts"] = "none"


# --- Session State ---


@dataclass
class SessionState:
    """In-memory per-caller session tracking for quota enforcement."""

    session_id: str
    caller_identity: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    call_count: int = 0
    record_count: int = 0

    def increment_calls(self) -> None:
        """Increment the call counter by 1."""
        self.call_count += 1

    def add_records(self, count: int) -> None:
        """Add to the cumulative record count."""
        self.record_count += count

    def exceeds_limits(self, limits: SessionLimits) -> bool:
        """Check if current session state exceeds the given limits."""
        return (
            self.call_count >= limits.max_calls_per_session
            or self.record_count >= limits.max_records_per_session
        )
