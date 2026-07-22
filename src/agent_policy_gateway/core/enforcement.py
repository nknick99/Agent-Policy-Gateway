"""Single call-evaluation path shared by every enforcement surface.

The proxy, the CLI demo, `apg policy test`, and `apg policy suggest` all
route through :func:`evaluate_call`. Keeping one function here is what
prevents the divergent-engine class of bug (D4): there is exactly one place
that turns a (method, params) pair into an allow/deny decision, and it
composes the two core primitives — the policy evaluator and the egress
controller — in a fixed order.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_policy_gateway.core.egress import EgressController
from agent_policy_gateway.core.models import Decision
from agent_policy_gateway.core.policy import PolicyEvaluator


@dataclass(frozen=True)
class CallDecision:
    """Immutable result of evaluating one tool call.

    Attributes:
        allowed: True if the call may proceed.
        reason: Human-readable explanation (None when allowed).
        rule: Name of the rule that produced the decision.
    """

    allowed: bool
    reason: str | None
    rule: str


def _destination(params: dict[str, Any]) -> str | None:
    """Extract the outbound destination from a request, if any."""
    dest = params.get("url") or params.get("destination")
    return dest if isinstance(dest, str) and dest else None


def evaluate_call(
    evaluator: PolicyEvaluator, method: str, params: dict[str, Any]
) -> CallDecision:
    """Evaluate a single tool call against policy, then egress control.

    Order matches the proxy hot path:
    1. Policy evaluation (tool/operation/table/constraint/keyword checks).
    2. Egress control for tools that reach out to a destination.

    Halts on the first DENY.
    """
    result = evaluator.evaluate(method, params)
    if result.decision == Decision.DENY:
        return CallDecision(allowed=False, reason=result.reason, rule=result.rule_matched)

    destination = _destination(params)
    if destination and result.tool_config is not None:
        egress = EgressController(result.tool_config).check(destination)
        if not egress.allowed:
            return CallDecision(
                allowed=False,
                reason=f"Egress denied: {egress.reason}",
                rule="egress_denied",
            )

    return CallDecision(allowed=True, reason=None, rule=result.rule_matched)
