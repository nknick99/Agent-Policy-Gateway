"""Guard tests: shared fixtures must stay in sync with the real models."""

from __future__ import annotations

from agent_policy_gateway.core.models import Decision, PolicyDocument
from agent_policy_gateway.core.policy import PolicyEvaluator


def test_sample_policy_validates(sample_policy):
    """The shared sample_policy fixture must be a valid PolicyDocument."""
    document = PolicyDocument.model_validate(sample_policy)
    assert document.default == "deny"
    assert "db.query" in document.tools


def test_sample_policy_is_evaluable(sample_policy):
    """The fixture must work with the real evaluator end to end."""
    evaluator = PolicyEvaluator.from_document(
        PolicyDocument.model_validate(sample_policy)
    )
    allowed = evaluator.evaluate("db.query", {"op": "select", "table": "users"})
    assert allowed.decision == Decision.ALLOW

    denied = evaluator.evaluate("db.query", {"op": "drop", "table": "users"})
    assert denied.decision == Decision.DENY
