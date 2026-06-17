"""Operating mode determination and control for KiroGate Proxy.

Supports two modes:
- Enforce (default): deny requests that fail policy evaluation
- Audit: log policy violations but execute request and return result

Mode is determined once at startup from the KIROGATE_MODE environment
variable. There is intentionally NO runtime API to switch modes
(Requirement 12.7).
"""

from __future__ import annotations

import logging
import os
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class OperatingMode(Enum):
    """Proxy operating mode."""

    ENFORCE = "enforce"
    AUDIT = "audit"


def get_operating_mode() -> OperatingMode:
    """Determine operating mode from KIROGATE_MODE environment variable.

    Accepts exactly "enforce" and "audit" (case-insensitive).
    Defaults to ENFORCE on missing or invalid values (Requirement 12.5).
    """
    mode_str = os.environ.get("KIROGATE_MODE", "").strip().lower()
    if mode_str == "audit":
        return OperatingMode.AUDIT
    if mode_str == "enforce":
        return OperatingMode.ENFORCE
    # Missing or invalid → default to Enforce
    if mode_str:
        logger.warning(
            "Invalid KIROGATE_MODE value '%s', defaulting to Enforce mode",
            mode_str,
        )
    return OperatingMode.ENFORCE


class ModeController:
    """Controls request handling based on the operating mode.

    The mode is set once at construction time and cannot be changed.
    This class intentionally exposes NO method to switch modes at
    runtime (Requirement 12.7).
    """

    def __init__(self) -> None:
        self._mode = get_operating_mode()
        logger.info("KiroGate operating in %s mode", self._mode.value.upper())

    @property
    def mode(self) -> OperatingMode:
        """Current operating mode (read-only)."""
        return self._mode

    @property
    def is_audit_mode(self) -> bool:
        """True when operating in Audit mode."""
        return self._mode == OperatingMode.AUDIT

    @property
    def is_enforce_mode(self) -> bool:
        """True when operating in Enforce mode."""
        return self._mode == OperatingMode.ENFORCE

    def should_block_policy_denial(self) -> bool:
        """Whether a policy denial should block the request.

        In Enforce mode: policy denials block the request (Req 12.1).
        In Audit mode: policy denials are logged but request proceeds (Req 12.2).
        """
        return self._mode == OperatingMode.ENFORCE

    def should_block_auth_failure(self) -> bool:
        """Whether an authentication failure should block the request.

        Always True in BOTH modes. Audit mode still enforces
        authentication (Requirement 12.6).
        """
        return True

    def should_block_schema_failure(self) -> bool:
        """Whether a schema validation failure should block the request.

        Always True in BOTH modes. Audit mode still enforces
        schema validation (Requirement 12.6).
        """
        return True

    def build_proposed_policy_entry(
        self, method: str, params: dict[str, Any]
    ) -> dict[str, str]:
        """Build a proposed policy entry for audit logging (Req 12.3).

        In Audit mode, when a request is processed, emit a proposed
        policy entry containing method, operation, and resource that
        would need to be allowlisted.

        Returns an empty dict if not in Audit mode.
        """
        if not self.is_audit_mode:
            return {}
        return {
            "method": method,
            "operation": params.get("op", ""),
            "resource": params.get("table", ""),
        }
