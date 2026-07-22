"""Fixed-order, fail-closed enforcement pipeline (core domain).

    authenticate → envelope validate → policy evaluate → egress control →
    quota check → credential mint → execute → filter response → audit

There is exactly one pipeline. The HTTP endpoint, the live demo, and any
future transport all call EnforcementPipeline.handle() — never a copy of
its logic (ADR-002).

Infrastructure is injected through small ports (Protocols) so the core
never imports adapters:

    Executor         — performs the allowed action against a target
    CredentialBroker — mints/discards per-request credentials
    AuditSink        — receives exactly one AuditEvent per request

Components are public attributes on the pipeline instance; the server
wires real adapters, tests may substitute fakes.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from agent_policy_gateway.core.audit import AuditEvent, redact_params
from agent_policy_gateway.core.egress import EgressController
from agent_policy_gateway.core.filter import filter_response
from agent_policy_gateway.core.mode import ModeController
from agent_policy_gateway.core.models import AuditDecision, Decision
from agent_policy_gateway.core.policy import PolicyEvaluator
from agent_policy_gateway.core.schemas import SchemaValidationError, validate_envelope
from agent_policy_gateway.core.session import SessionStore

logger = logging.getLogger(__name__)


# --- Errors ---


class CredentialMintError(Exception):
    """Raised when credential minting fails.

    Carries a generic user-facing message that does not leak
    broker/cloud details.
    """

    def __init__(self, message: str = "Credential minting failed") -> None:
        super().__init__(message)


class ExecutionError(Exception):
    """Raised when target execution fails. Message must be user-safe."""


# --- Ports ---


class Executor(Protocol):
    """Performs an allowed action against the target system."""

    async def execute(
        self,
        method: str,
        params: dict[str, Any],
        creds: Any,
        tool_config: dict[str, Any] | None,
    ) -> Any: ...


class CredentialBroker(Protocol):
    """Mints and discards per-request credentials."""

    def mint_credentials(
        self, role_arn: str, session_policy: dict, session_name: str
    ) -> Any: ...

    def discard(self, creds: Any) -> None: ...


class AuditSink(Protocol):
    """Receives exactly one AuditEvent per request."""

    def emit(self, event: AuditEvent) -> None: ...


# --- Result ---


@dataclass
class PipelineOutcome:
    """The JSON-RPC response body plus the audit event that describes it."""

    body: dict[str, Any]
    event: AuditEvent


def _error_body(request_id: int | str | None, code: int, message: str) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error body (Requirements 13.3–13.5)."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _success_body(request_id: int | str | None, result: Any) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 success body (Requirements 13.2, 13.4)."""
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def caller_id_from_token(token: str) -> str:
    """Derive a caller ID from the token (SHA-256 hash for session tracking)."""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


class EnforcementPipeline:
    """The one enforcement pipeline. Fail-closed at every step."""

    def __init__(
        self,
        *,
        evaluator: PolicyEvaluator,
        session_manager: SessionStore,
        broker: CredentialBroker,
        audit_sink: AuditSink,
        mode_controller: ModeController,
        executor: Executor,
        authenticate: Callable[[str], bool],
    ) -> None:
        self.evaluator = evaluator
        self.session_manager = session_manager
        self.broker = broker
        self.audit_sink = audit_sink
        self.mode_controller = mode_controller
        self.executor = executor
        self.authenticate = authenticate

    async def handle(self, payload: Any, token: str) -> PipelineOutcome:
        """Run the full pipeline for one parsed JSON-RPC payload.

        Always emits exactly one audit event, including on internal
        errors (Requirement 10.5).
        """
        start_time = time.monotonic()
        event = AuditEvent(correlation_id=str(uuid.uuid4()))
        try:
            body = await self._run(payload, token, event)
        finally:
            event.duration_ms = (time.monotonic() - start_time) * 1000
            self.audit_sink.emit(event)
        return PipelineOutcome(body=body, event=event)

    async def _run(self, payload: Any, token: str, event: AuditEvent) -> dict[str, Any]:
        """Pipeline body. Returns a JSON-RPC response dict; never raises."""
        request_id: int | str | None = None
        creds: Any = None

        try:
            # Requirement 13.6: reject batch (JSON array)
            if isinstance(payload, list):
                event.denial_reason = "Batch requests not supported"
                return _error_body(None, -32600, "Batch requests not supported")

            if not isinstance(payload, dict):
                event.denial_reason = "Invalid request: body is not a JSON object"
                return _error_body(None, -32600, "Invalid request")

            request_id = payload.get("id")

            # Requirement 13.7: reject notifications (missing id)
            if request_id is None:
                event.denial_reason = "Notifications not supported"
                return _error_body(None, -32600, "Notifications not supported")

            # --- Step 1: Authenticate ---
            if not self.authenticate(token):
                event.denial_reason = "Authentication failed"
                return _error_body(request_id, -32600, "Authentication failed")

            caller_id = caller_id_from_token(token)
            event.caller_identity = caller_id

            # --- Step 2: Envelope validation ---
            validate_envelope(payload)

            method = payload["method"]
            params = payload.get("params", {})
            if not isinstance(params, dict):
                event.denial_reason = "Invalid params: must be an object"
                return _error_body(request_id, -32602, "Invalid params: must be an object")
            event.method = method
            event.params_redacted = redact_params(params)

            # --- Step 3: Policy evaluation ---
            # Unknown tools are a policy decision (default deny), not a
            # schema decision — the gateway fronts arbitrary MCP tools.
            policy_result = self.evaluator.evaluate(method, params)

            if policy_result.decision == Decision.DENY:
                if self.mode_controller.should_block_policy_denial():
                    event.denial_reason = f"Policy denied: {policy_result.reason}"
                    event.rule_matched = policy_result.rule_matched
                    return _error_body(
                        request_id, -32600, f"Policy denied: {policy_result.reason}"
                    )
                # Audit mode: log but continue (Requirement 12.2)
                proposed = self.mode_controller.build_proposed_policy_entry(method, params)
                logger.info(
                    "Audit mode: policy denial logged but not enforced. "
                    "Proposed policy entry: %s",
                    proposed,
                )
                event.rule_matched = policy_result.rule_matched

            # --- Step 4: Egress control ---
            tool_config = policy_result.tool_config or {}
            destination = params.get("url") or params.get("destination")
            if destination and policy_result.tool_config is not None:
                egress_result = EgressController(tool_config).check(destination)
                if not egress_result.allowed:
                    event.denial_reason = f"Egress denied: {egress_result.reason}"
                    return _error_body(
                        request_id, -32600, f"Egress denied: {egress_result.reason}"
                    )

            # --- Step 5: Quota check ---
            session_limits = self.evaluator.policy.session_limits
            if await self.session_manager.check_quota(caller_id, session_limits):
                event.denial_reason = "Session quota exceeded"
                return _error_body(request_id, -32600, "Session quota exceeded")

            # --- Step 6: Credential mint ---
            creds = self.broker.mint_credentials(
                role_arn=tool_config.get("aws_role", ""),
                session_policy=tool_config.get("session_policy", {}),
                session_name=f"apg-{event.correlation_id[:8]}",
            )
            # Only record a role when credentials were actually minted
            if creds is not None:
                event.role_assumed = tool_config.get("aws_role", "")

            try:
                # --- Step 7: Execute against the real target ---
                raw_result = await self.executor.execute(method, params, creds, tool_config)

                # --- Step 8: Filter response ---
                filtered_result = filter_response(raw_result)

                # Record success in session tracking
                record_count = 0
                if isinstance(raw_result, dict):
                    rows = raw_result.get("rows", [])
                    record_count = len(rows) if isinstance(rows, list) else 0
                await self.session_manager.record_success(
                    caller_id, record_count=record_count
                )

                event.decision = AuditDecision.ALLOW
                event.rule_matched = policy_result.rule_matched
                event.outcome = "success"

                return _success_body(request_id, filtered_result)
            finally:
                # Requirement 6.6: guaranteed credential discard
                self.broker.discard(creds)
                creds = None

        except SchemaValidationError as exc:
            event.denial_reason = f"Schema validation: {exc.message}"
            return _error_body(request_id, exc.code, exc.message)

        except CredentialMintError:
            event.denial_reason = "Credential minting failed"
            return _error_body(
                request_id, -32603, "Internal error: credential minting failed"
            )

        except ExecutionError as exc:
            event.denial_reason = f"Execution failed: {exc}"
            return _error_body(request_id, -32603, f"Execution failed: {exc}")

        except Exception:
            # Requirement 10.1: fail-closed — unhandled exception → -32603
            logger.exception(
                "Unhandled exception in pipeline (correlation_id=%s)",
                event.correlation_id,
            )
            event.denial_reason = "Unhandled internal error"
            return _error_body(request_id, -32603, "Internal error")
