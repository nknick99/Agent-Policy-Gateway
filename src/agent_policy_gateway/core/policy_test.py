"""`apg policy test` — unit tests for your policy.

A policy is a public API; it deserves the same regression safety as code. This
module runs allow/deny assertions (written in YAML) through the *real*
enforcement engine (:func:`evaluate_call`), so a passing suite proves the
shipped policy behaves as the author intends — and a policy edit that silently
opens a hole fails CI.

Test file schema::

    cases:
      - name: allow a normal select
        method: db.query
        params: {op: select, query: "SELECT * FROM users"}
        expect: allow
      - name: block drop
        method: db.query
        params: {op: drop}
        expect: deny
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from agent_policy_gateway.core.enforcement import evaluate_call
from agent_policy_gateway.core.policy import PolicyEvaluator


class PolicyTestError(Exception):
    """Raised when a test file is missing, unparseable, or malformed."""


@dataclass(frozen=True)
class CaseResult:
    """Outcome of a single policy test case."""

    name: str
    expected: str
    actual: str
    passed: bool
    reason: str | None


def load_cases(test_path: str) -> list[dict[str, Any]]:
    """Load and structurally validate a YAML policy-test file."""
    path = Path(test_path)
    if not path.exists():
        raise PolicyTestError(f"Test file not found: {test_path}")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyTestError(f"Failed to parse test file: {exc}") from exc

    if not isinstance(data, dict) or "cases" not in data:
        raise PolicyTestError("Test file must be a mapping with a 'cases' list")
    cases = data["cases"]
    if not isinstance(cases, list) or not cases:
        raise PolicyTestError("'cases' must be a non-empty list")

    for i, case in enumerate(cases):
        if not isinstance(case, dict):
            raise PolicyTestError(f"Case #{i + 1} must be a mapping")
        for required in ("method", "expect"):
            if required not in case:
                raise PolicyTestError(f"Case #{i + 1} is missing required key '{required}'")
        if case["expect"] not in ("allow", "deny"):
            raise PolicyTestError(
                f"Case '{case.get('name', i + 1)}': expect must be 'allow' or 'deny'"
            )
    return cases


def run_cases(
    cases: list[dict[str, Any]], evaluator: PolicyEvaluator
) -> list[CaseResult]:
    """Evaluate each case through the real engine and record pass/fail."""
    results: list[CaseResult] = []
    for i, case in enumerate(cases):
        name = case.get("name") or f"case {i + 1}"
        expected = case["expect"]
        decision = evaluate_call(evaluator, case["method"], case.get("params", {}))
        actual = "allow" if decision.allowed else "deny"
        results.append(
            CaseResult(
                name=name,
                expected=expected,
                actual=actual,
                passed=actual == expected,
                reason=decision.reason,
            )
        )
    return results
