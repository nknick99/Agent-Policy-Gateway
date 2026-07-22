"""SQL understanding via a real parser (sqlglot).

Keyword/substring matching on SQL is a speed bump, not a wall: `DR/**/OP`,
comment tricks, casing, and semantically-equivalent rephrasings all slip past
it. This module parses the actual statement(s) and extracts the *structured*
facts policy cares about — the operation(s) performed and the table(s) touched
— so enforcement is deterministic and hard to fool.

Two properties worth calling out:
- **Multi-statement injection is caught.** `SELECT ...; DROP TABLE x` parses to
  two statements; we surface both operations, so a policy that allows only
  `select` still blocks the piggybacked `drop`.
- **Comments are ignored, not scanned.** `... -- DROP` is a comment; it neither
  triggers a false denial nor smuggles a real one.
"""

from __future__ import annotations

from dataclasses import dataclass

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

# sqlglot names a few statements differently from how policy authors write them.
_OPERATION_ALIASES = {"truncatetable": "truncate"}


class SqlParseError(Exception):
    """Raised when SQL cannot be parsed — callers fail closed (deny)."""


@dataclass(frozen=True)
class SqlStatement:
    """One parsed statement: its operation and the tables it references."""

    operation: str
    tables: tuple[str, ...]


@dataclass(frozen=True)
class SqlAnalysis:
    """The structured result of analyzing a (possibly multi-statement) query."""

    statements: tuple[SqlStatement, ...]

    @property
    def operations(self) -> set[str]:
        return {stmt.operation for stmt in self.statements}

    @property
    def tables(self) -> set[str]:
        return {table for stmt in self.statements for table in stmt.tables}


def _operation_of(statement: exp.Expression) -> str:
    """Derive a normalized, lowercase operation verb from a parsed statement."""
    if isinstance(statement, exp.Command):
        # Statements sqlglot doesn't model natively (e.g. some dialect-specific
        # DDL) come back as Command with the leading keyword in `this`.
        op = str(statement.this).lower()
    else:
        op = statement.key
    return _OPERATION_ALIASES.get(op, op)


def analyze_sql(sql: str, dialect: str | None = None) -> SqlAnalysis:
    """Parse SQL and extract the operation(s) and table(s) of each statement.

    Args:
        sql: The raw SQL string.
        dialect: Optional sqlglot dialect (e.g. "postgres", "mysql"); None or
            empty uses sqlglot's default parser.

    Returns:
        A :class:`SqlAnalysis` with one entry per statement.

    Raises:
        SqlParseError: if the SQL is unparseable or yields no statements.
    """
    try:
        parsed = sqlglot.parse(sql, read=dialect or None)
    except SqlglotError as exc:
        raise SqlParseError(str(exc)) from exc

    statements: list[SqlStatement] = []
    for statement in parsed:
        if statement is None:
            continue
        tables = tuple(sorted({table.name for table in statement.find_all(exp.Table)}))
        statements.append(SqlStatement(operation=_operation_of(statement), tables=tables))

    if not statements:
        raise SqlParseError("no SQL statements found")

    return SqlAnalysis(statements=tuple(statements))
