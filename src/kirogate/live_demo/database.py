"""In-memory SQLite database with sample data for live demos.

This simulates a real production database that the AI agent
tries to access through KiroGate's policy gateway.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


_DB_PATH = ":memory:"
_conn: sqlite3.Connection | None = None


def get_connection() -> sqlite3.Connection:
    """Get or create the demo database connection."""
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _seed_data(_conn)
    return _conn


def _seed_data(conn: sqlite3.Connection) -> None:
    """Create tables and insert sample data."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            plan TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            ssn TEXT,
            last_login TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            customer_id INTEGER REFERENCES customers(id),
            product TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY,
            customer_id INTEGER REFERENCES customers(id),
            key_hash TEXT NOT NULL,
            scope TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- Sample customers
        INSERT OR IGNORE INTO customers (id, name, email, plan, active, ssn, last_login)
        VALUES
            (1, 'Alice Johnson', 'alice@acme.com', 'enterprise', 1, '123-45-6789', '2024-06-01'),
            (2, 'Bob Smith', 'bob@startup.io', 'pro', 1, '987-65-4321', '2024-05-28'),
            (3, 'Charlie Lee', 'charlie@bigco.org', 'enterprise', 1, '555-12-3456', '2024-06-10'),
            (4, 'Diana Patel', 'diana@solo.dev', 'free', 0, '111-22-3333', '2023-01-15'),
            (5, 'Eve Martinez', 'eve@agency.co', 'pro', 1, '444-55-6666', '2024-06-12');

        -- Sample orders
        INSERT OR IGNORE INTO orders (id, customer_id, product, amount, status)
        VALUES
            (1, 1, 'KiroGate Enterprise', 2400.00, 'active'),
            (2, 2, 'KiroGate Pro', 49.00, 'active'),
            (3, 3, 'KiroGate Enterprise', 2400.00, 'active'),
            (4, 1, 'Support Add-on', 500.00, 'pending'),
            (5, 5, 'KiroGate Pro', 49.00, 'active');

        -- Sample API keys (hashed, never shown raw)
        INSERT OR IGNORE INTO api_keys (id, customer_id, key_hash, scope)
        VALUES
            (1, 1, 'sha256:a3f8c2...', 'read:customers'),
            (2, 2, 'sha256:b7d1e4...', 'read:orders'),
            (3, 3, 'sha256:c9e2f1...', 'admin:all');
    """)
    conn.commit()


def execute_query(sql: str) -> list[dict]:
    """Execute a SELECT query and return results as list of dicts.

    Only SELECT queries are executed — this is the execution layer
    AFTER KiroGate has already approved the request.
    """
    conn = get_connection()
    cursor = conn.execute(sql)
    columns = [desc[0] for desc in cursor.description] if cursor.description else []
    rows = cursor.fetchall()
    return [dict(zip(columns, row)) for row in rows]


def reset_database() -> None:
    """Reset the database to initial state (for demo resets)."""
    global _conn
    if _conn:
        _conn.close()
        _conn = None
    get_connection()  # Re-creates with seed data
