"""Tests for `apg policy test` — the policy unit-test runner."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_policy_gateway.core.policy import PolicyEvaluator, load_policy_document
from agent_policy_gateway.core.policy_test import (
    PolicyTestError,
    load_cases,
    run_cases,
)

POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.json"


@pytest.fixture()
def evaluator() -> PolicyEvaluator:
    return PolicyEvaluator.from_document(load_policy_document(str(POLICY_PATH)))


class TestLoadCases:
    def test_valid_file(self, tmp_path):
        f = tmp_path / "t.yaml"
        f.write_text(
            "cases:\n"
            "  - name: allow select\n"
            "    method: db.query\n"
            "    params: {op: select}\n"
            "    expect: allow\n"
        )
        cases = load_cases(str(f))
        assert cases[0]["method"] == "db.query"

    def test_missing_file(self, tmp_path):
        with pytest.raises(PolicyTestError, match="not found"):
            load_cases(str(tmp_path / "nope.yaml"))

    def test_missing_cases_key(self, tmp_path):
        f = tmp_path / "t.yaml"
        f.write_text("nope: true\n")
        with pytest.raises(PolicyTestError, match="cases"):
            load_cases(str(f))

    def test_bad_expect_value(self, tmp_path):
        f = tmp_path / "t.yaml"
        f.write_text("cases:\n  - method: db.query\n    expect: maybe\n")
        with pytest.raises(PolicyTestError, match="allow.*deny"):
            load_cases(str(f))

    def test_missing_required_key(self, tmp_path):
        f = tmp_path / "t.yaml"
        f.write_text("cases:\n  - method: db.query\n")
        with pytest.raises(PolicyTestError, match="expect"):
            load_cases(str(f))


class TestRunCases:
    def test_allow_and_deny_pass(self, evaluator):
        cases = [
            {"name": "select ok", "method": "db.query",
             "params": {"op": "select", "query": "SELECT 1"}, "expect": "allow"},
            {"name": "drop blocked", "method": "db.query",
             "params": {"op": "drop"}, "expect": "deny"},
            {"name": "unknown tool", "method": "fs.read",
             "params": {}, "expect": "deny"},
        ]
        results = run_cases(cases, evaluator)
        assert all(r.passed for r in results)

    def test_egress_case(self, evaluator):
        cases = [
            {"name": "whitelisted", "method": "http.get",
             "params": {"op": "GET", "url": "https://api.example.com/x"}, "expect": "allow"},
            {"name": "blocked host", "method": "http.get",
             "params": {"op": "GET", "url": "https://evil.example.net/x"}, "expect": "deny"},
        ]
        results = run_cases(cases, evaluator)
        assert all(r.passed for r in results)

    def test_wrong_expectation_fails(self, evaluator):
        cases = [
            {"name": "drop should be allowed?!", "method": "db.query",
             "params": {"op": "drop"}, "expect": "allow"},
        ]
        results = run_cases(cases, evaluator)
        assert not results[0].passed
        assert results[0].actual == "deny"
        assert results[0].reason is not None
