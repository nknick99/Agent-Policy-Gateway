"""Deterministic policy evaluation engine for Agent Policy Gateway.

Loads the immutable policy.json at startup and evaluates every incoming
request against it using a fixed evaluation order. No AI reasoning involved —
decisions are purely code-based and deterministic.
"""

from __future__ import annotations

import json
import logging
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agent_policy_gateway.core.models import Decision, PolicyDocument, ToolConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PolicyResult:
    """Immutable result of a policy evaluation.

    Attributes:
        decision: ALLOW or DENY.
        rule_matched: Name of the rule that triggered the decision.
        reason: Human-readable explanation of the decision.
        tool_config: The matched tool configuration dict (only for ALLOW decisions).
    """

    decision: Decision
    rule_matched: str
    reason: str
    tool_config: dict[str, Any] | None = None


class PolicyEvaluator:
    """Deterministic, code-based policy engine.

    Loads the immutable policy.json once at startup and evaluates requests
    against allowlists. Produces deterministic results for identical inputs.
    The internal policy state is frozen and never modified after initialization.
    """

    def __init__(self, policy_path: str = "policy.json") -> None:
        """Load policy from the given path and freeze it.

        Raises SystemExit if:
        - The policy file is missing or unparseable (Requirement 10.2)
        - The default field is not "deny" (Requirement 10.3)
        """
        path = Path(policy_path)

        # Requirement 10.2: Missing policy file → terminate
        if not path.exists():
            print(
                f"FATAL: Policy file not found: {policy_path}",
                file=sys.stderr,
            )
            sys.exit(1)

        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError) as exc:
            # Requirement 10.2: Unparseable policy file → terminate
            print(
                f"FATAL: Failed to parse policy file: {exc}",
                file=sys.stderr,
            )
            sys.exit(1)

        # Validate via Pydantic model
        try:
            policy = PolicyDocument.model_validate(data)
        except ValidationError as exc:
            print(
                f"FATAL: Policy validation failed: {exc}",
                file=sys.stderr,
            )
            sys.exit(1)

        # Requirement 10.3: default must be "deny"
        if policy.default != "deny":
            print(
                f"FATAL: Policy default must be 'deny', got '{policy.default}'",
                file=sys.stderr,
            )
            sys.exit(1)

        # Requirement 11.1: Store as frozen read-only structure
        # Store the validated policy document (Pydantic model is immutable by config)
        self._policy: PolicyDocument = policy

        # Create a frozen mapping of tool names for O(1) lookup
        self._tools_map: types.MappingProxyType[str, ToolConfig] = (
            types.MappingProxyType(policy.tools)
        )

        # Requirement 11.1: Log confirmation that policy is loaded as immutable
        logger.info(
            "Policy loaded as immutable: version=%d, tools=%d, default=%s",
            policy.version,
            len(policy.tools),
            policy.default,
        )

    @property
    def policy(self) -> PolicyDocument:
        """Read-only access to the loaded policy document."""
        return self._policy

    def evaluate(self, method: str, params: dict[str, Any]) -> PolicyResult:
        """Run full policy evaluation in fixed order (Requirement 3.8).

        Evaluation order:
        1. Tool lookup (method in tools map)
        2. Allow flag check
        3. Operation allowlist check (skip if 'op' not in params)
        4. Resource scope check (skip if 'table' not in params)
        5. Parameter constraints check
        6. Deny keywords check (case-insensitive substring in any string param)

        Halts on first DENY without evaluating subsequent checks.
        Produces deterministic results for identical inputs (Requirement 3.9).

        Args:
            method: The tool method being called (e.g., "db.query").
            params: The request parameters dict.

        Returns:
            PolicyResult with ALLOW or DENY decision.
        """
        # Step 1: Tool lookup (Requirement 3.1)
        if method not in self._tools_map:
            return PolicyResult(
                decision=Decision.DENY,
                rule_matched="tool_not_listed",
                reason=f"Method '{method}' is not listed in the policy tools map",
            )

        tool_config = self._tools_map[method]

        # Step 2: Allow flag (Requirement 3.2)
        if not tool_config.allow:
            return PolicyResult(
                decision=Decision.DENY,
                rule_matched="tool_disabled",
                reason=f"Tool '{method}' is disabled (allow=false)",
            )

        # Step 3: Operation check (Requirement 3.3, skip per 3.10)
        if "op" in params:
            op_result = self.check_operation(tool_config, params["op"])
            if op_result is not None:
                return op_result

        # Step 4: Resource scope check (Requirement 3.4, skip per 3.10)
        if "table" in params:
            scope_result = self.check_resource_scope(tool_config, params["table"])
            if scope_result is not None:
                return scope_result

        # Step 5: Constraints check (Requirement 3.5)
        constraints_result = self.check_constraints(tool_config, params)
        if constraints_result is not None:
            return constraints_result

        # Step 6: Deny keywords check (Requirement 3.6)
        keywords_result = self._check_deny_keywords(tool_config, params)
        if keywords_result is not None:
            return keywords_result

        # All checks passed → ALLOW (Requirement 3.7)
        return PolicyResult(
            decision=Decision.ALLOW,
            rule_matched="all_checks_passed",
            reason=f"All policy checks passed for tool '{method}'",
            tool_config=tool_config.model_dump(),
        )

    def check_operation(self, tool_config: ToolConfig, op: str) -> PolicyResult | None:
        """Check if operation is in the tool's operations allowlist.

        Args:
            tool_config: The tool configuration to check against.
            op: The operation string from the request params.

        Returns:
            PolicyResult with DENY if operation not allowed, None if allowed.
        """
        # If operations list is empty, skip this check (no restrictions defined)
        if not tool_config.operations:
            return None

        if op not in tool_config.operations:
            return PolicyResult(
                decision=Decision.DENY,
                rule_matched="operation_not_allowed",
                reason=f"Operation '{op}' is not in the allowed operations list",
            )
        return None

    def check_resource_scope(
        self, tool_config: ToolConfig, resource: str
    ) -> PolicyResult | None:
        """Check if resource is in the tool's tables allowlist.

        Args:
            tool_config: The tool configuration to check against.
            resource: The resource/table name from the request params.

        Returns:
            PolicyResult with DENY if resource out of scope, None if allowed.
        """
        # If tables list is empty, skip this check (no restrictions defined)
        if not tool_config.tables:
            return None

        if resource not in tool_config.tables:
            return PolicyResult(
                decision=Decision.DENY,
                rule_matched="resource_out_of_scope",
                reason=f"Resource '{resource}' is not in the allowed tables list",
            )
        return None

    def check_constraints(
        self, tool_config: ToolConfig, params: dict[str, Any]
    ) -> PolicyResult | None:
        """Check if parameter values satisfy defined constraint bounds.

        Looks at tool_config.constraints.limit — if a param name matches a key
        in constraints and its numeric value exceeds the max, deny it.

        Args:
            tool_config: The tool configuration to check against.
            params: The full request parameters dict.

        Returns:
            PolicyResult with DENY if any constraint violated, None if all pass.
        """
        if tool_config.constraints is None:
            return None
        if tool_config.constraints.limit is None:
            return None

        for param_name, max_value in tool_config.constraints.limit.items():
            if param_name in params:
                param_value = params[param_name]
                # Only check numeric values
                if isinstance(param_value, (int, float)) and param_value > max_value:
                    return PolicyResult(
                        decision=Decision.DENY,
                        rule_matched="constraint_violated",
                        reason=(
                            f"Parameter '{param_name}' value {param_value} "
                            f"exceeds maximum {max_value}"
                        ),
                    )
        return None

    def _check_deny_keywords(
        self, tool_config: ToolConfig, params: dict[str, Any]
    ) -> PolicyResult | None:
        """Check if any deny keyword appears as a case-insensitive substring
        in any top-level string parameter value.

        Args:
            tool_config: The tool configuration to check against.
            params: The full request parameters dict.

        Returns:
            PolicyResult with DENY if a keyword is found, None if clean.
        """
        if not tool_config.deny_keywords:
            return None

        for param_name, param_value in params.items():
            if not isinstance(param_value, str):
                continue
            param_lower = param_value.lower()
            for keyword in tool_config.deny_keywords:
                if keyword.lower() in param_lower:
                    return PolicyResult(
                        decision=Decision.DENY,
                        rule_matched="deny_keyword_found",
                        reason=(
                            f"Deny keyword '{keyword}' found in parameter "
                            f"'{param_name}'"
                        ),
                    )
        return None
