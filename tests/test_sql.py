"""Tests for the sqlglot-based SQL analyzer."""

from __future__ import annotations

import pytest

from agent_policy_gateway.core.sql import SqlParseError, analyze_sql


class TestOperationExtraction:
    @pytest.mark.parametrize(
        "sql,operation",
        [
            ("SELECT * FROM users", "select"),
            ("select 1", "select"),
            ("sELeCt name FROM users", "select"),
            ("DROP TABLE users", "drop"),
            ("DELETE FROM users WHERE id=1", "delete"),
            ("UPDATE users SET x=1", "update"),
            ("INSERT INTO orders VALUES (1)", "insert"),
            ("TRUNCATE TABLE users", "truncate"),
            ("ALTER TABLE users ADD COLUMN x INT", "alter"),
            ("CREATE TABLE t (id INT)", "create"),
        ],
    )
    def test_operation(self, sql, operation):
        analysis = analyze_sql(sql)
        assert operation in analysis.operations


class TestTableExtraction:
    def test_single_table(self):
        assert analyze_sql("SELECT * FROM users").tables == {"users"}

    def test_join_tables(self):
        analysis = analyze_sql("SELECT * FROM a JOIN b ON a.id = b.id")
        assert analysis.tables == {"a", "b"}

    def test_no_table(self):
        assert analyze_sql("SELECT 1").tables == set()


class TestBypassResistance:
    def test_multi_statement_injection_surfaces_both_ops(self):
        # The classic piggyback: a SELECT with a smuggled DROP.
        analysis = analyze_sql("SELECT * FROM users; DROP TABLE users")
        assert analysis.operations == {"select", "drop"}

    def test_comment_is_not_scanned_as_sql(self):
        # A DROP inside a comment is inert — not a false denial, not a bypass.
        analysis = analyze_sql("SELECT * FROM users WHERE 1=1 -- DROP TABLE users")
        assert analysis.operations == {"select"}
        assert analysis.tables == {"users"}


class TestParseErrors:
    def test_garbage_raises(self):
        with pytest.raises(SqlParseError):
            analyze_sql("this is not ; valid ((( sql")

    def test_empty_raises(self):
        with pytest.raises(SqlParseError):
            analyze_sql("   ")
