"""Policy-engine tests for opt-in SQL parsing (deterministic enforcement)."""

from __future__ import annotations

from agent_policy_gateway.core.models import Decision, PolicyDocument
from agent_policy_gateway.core.policy import PolicyEvaluator


def _evaluator(**db_query_overrides) -> PolicyEvaluator:
    tool = {
        "allow": True,
        "operations": ["select"],
        "tables": ["users", "orders"],
        "sql": {"dialect": "", "params": ["query", "sql"]},
    }
    tool.update(db_query_overrides)
    document = PolicyDocument.model_validate(
        {
            "version": 1,
            "default": "deny",
            "caller_auth": {"method": "shared_token"},
            "session_limits": {},
            "tools": {"db.query": tool},
        }
    )
    return PolicyEvaluator.from_document(document)


class TestSqlEnforcement:
    def test_allowed_select_passes(self):
        result = _evaluator().evaluate("db.query", {"query": "SELECT * FROM users"})
        assert result.decision == Decision.ALLOW

    def test_drop_derived_from_sql_is_denied(self):
        # No self-declared `op` field — the operation is parsed from the text.
        result = _evaluator().evaluate("db.query", {"query": "DROP TABLE users"})
        assert result.decision == Decision.DENY
        assert result.rule_matched == "operation_not_allowed"
        assert "drop" in result.reason

    def test_table_out_of_scope_denied(self):
        result = _evaluator().evaluate("db.query", {"query": "SELECT * FROM secrets"})
        assert result.decision == Decision.DENY
        assert result.rule_matched == "resource_out_of_scope"
        assert "secrets" in result.reason

    def test_multi_statement_injection_blocked(self):
        # A SELECT that piggybacks a DROP must be denied on the DROP.
        result = _evaluator().evaluate(
            "db.query", {"query": "SELECT * FROM users; DROP TABLE users"}
        )
        assert result.decision == Decision.DENY
        assert result.rule_matched == "operation_not_allowed"

    def test_comment_trick_does_not_bypass_or_falsely_deny(self):
        result = _evaluator().evaluate(
            "db.query", {"query": "SELECT * FROM users WHERE 1=1 -- DROP TABLE users"}
        )
        assert result.decision == Decision.ALLOW

    def test_unparseable_sql_fails_closed(self):
        result = _evaluator().evaluate("db.query", {"query": "!!! not sql ((("})
        assert result.decision == Decision.DENY
        assert result.rule_matched == "sql_unparseable"

    def test_sql_under_alternate_param_key(self):
        result = _evaluator().evaluate("db.query", {"sql": "DROP TABLE users"})
        assert result.decision == Decision.DENY

    def test_no_sql_present_skips_analysis(self):
        # Tool opts into SQL parsing, but this call carries no SQL string.
        result = _evaluator().evaluate("db.query", {"op": "select"})
        assert result.decision == Decision.ALLOW


class TestBackwardCompatibility:
    def test_tool_without_sql_config_unaffected(self):
        # No `sql` key -> parsing off -> self-declared op path as before.
        ev = _evaluator(sql=None)
        # A query string that would parse to DROP is ignored without sql config;
        # only the deny_keywords / explicit op paths apply.
        result = ev.evaluate("db.query", {"op": "select"})
        assert result.decision == Decision.ALLOW
