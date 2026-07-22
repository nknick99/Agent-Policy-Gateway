"""Audit sink adapters (JSONL default, SQLite durable, syslog/HEC for SIEMs)."""

from __future__ import annotations

from urllib.parse import urlparse

from agent_policy_gateway.adapters.audit.jsonl import JsonlAuditSink
from agent_policy_gateway.adapters.audit.splunk_hec import SplunkHecAuditSink
from agent_policy_gateway.adapters.audit.sqlite import SqliteAuditSink
from agent_policy_gateway.adapters.audit.syslog import SyslogAuditSink
from agent_policy_gateway.core.audit_sink import AuditSink

__all__ = [
    "AuditSink",
    "JsonlAuditSink",
    "SplunkHecAuditSink",
    "SqliteAuditSink",
    "SyslogAuditSink",
    "build_audit_sink",
]

_SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3")


def _build_syslog(spec: str) -> SyslogAuditSink:
    # syslog://host:port  or  syslog+tcp://host:port
    parsed = urlparse(spec)
    protocol = "tcp" if parsed.scheme.endswith("+tcp") else "udp"
    return SyslogAuditSink(
        host=parsed.hostname or "localhost",
        port=parsed.port or 514,
        protocol=protocol,
    )


def _build_splunk_hec(spec: str) -> SplunkHecAuditSink:
    # splunk-hec://<token>@host:port   (https; use splunk-hec+http:// for http)
    parsed = urlparse(spec)
    scheme = "http" if parsed.scheme.endswith("+http") else "https"
    port = f":{parsed.port}" if parsed.port else ""
    return SplunkHecAuditSink(
        base_url=f"{scheme}://{parsed.hostname}{port}",
        token=parsed.username or "",
    )


def build_audit_sink(target: str) -> AuditSink:
    """Pick an audit sink from a target string.

    - ``sqlite:///path`` / ``*.db`` / ``*.sqlite`` → durable SQLite sink.
    - ``syslog://host:port`` (or ``syslog+tcp://``) → CEF over syslog to a SIEM.
    - ``splunk-hec://<token>@host:port`` → Splunk HTTP Event Collector.
    - anything else (e.g. ``apg-audit.jsonl``) → append-only JSONL sink.
    """
    spec = target.strip()
    lowered = spec.lower()
    if lowered.startswith("sqlite:///"):
        return SqliteAuditSink(spec[len("sqlite:///") :])
    if lowered.startswith("sqlite://"):
        return SqliteAuditSink(spec[len("sqlite://") :])
    if lowered.startswith("syslog:") or lowered.startswith("syslog+tcp:"):
        return _build_syslog(spec)
    if lowered.startswith("splunk-hec:"):
        return _build_splunk_hec(spec)
    if lowered.endswith(_SQLITE_SUFFIXES):
        return SqliteAuditSink(spec)
    return JsonlAuditSink(spec)
