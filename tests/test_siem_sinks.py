"""Tests for SIEM audit sinks — CEF formatting, syslog, and Splunk HEC."""

from __future__ import annotations

import socket

from agent_policy_gateway.adapters.audit import (
    JsonlAuditSink,
    SplunkHecAuditSink,
    SqliteAuditSink,
    SyslogAuditSink,
    build_audit_sink,
)
from agent_policy_gateway.adapters.audit.cef import to_cef

EVENT = {
    "correlation_id": "abc123",
    "timestamp": "2026-07-21T00:00:00.000Z",
    "outcome": "DENY",
    "method": "db.query",
    "agent_id": "reporting",
    "op": "drop",
    "reason": "operation 'drop' not allowed",
    "latency_ms": 0.4,
}


class TestCef:
    def test_header_and_severity(self):
        cef = to_cef(EVENT)
        assert cef.startswith("CEF:0|AgentPolicyGateway|APG|")
        # DENY → severity 7; the header ends with |7| before the extension.
        assert "|7|" in cef

    def test_extension_fields(self):
        cef = to_cef(EVENT)
        assert "act=DENY" in cef
        assert "suser=reporting" in cef
        assert "cs1=db.query" in cef
        assert "externalId=abc123" in cef

    def test_escaping(self):
        cef = to_cef({"outcome": "DENY", "method": "x", "reason": "a=b|c"})
        # '=' is escaped in extension values.
        assert r"msg=a\=b|c" in cef

    def test_allow_is_low_severity(self):
        assert "|3|" in to_cef({"outcome": "ALLOW", "method": "db.query"})


class TestSyslogSink:
    def test_udp_delivers_cef(self):
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(5.0)
        port = receiver.getsockname()[1]

        sink = SyslogAuditSink(host="127.0.0.1", port=port, protocol="udp")
        try:
            sink.write(EVENT)
            data, _ = receiver.recvfrom(4096)
        finally:
            sink.close()
            receiver.close()

        text = data.decode()
        assert text.startswith("<134>1 ")  # RFC5424 framing, local0.info
        assert "CEF:0|AgentPolicyGateway|APG|" in text
        assert "act=DENY" in text

    def test_read_is_empty(self):
        sink = SyslogAuditSink(host="127.0.0.1", port=1514, protocol="udp")
        try:
            assert sink.read() == []
        finally:
            sink.close()


class TestSplunkHecSink:
    def test_posts_events_off_the_request_path(self):
        calls = []

        def poster(url, headers, payload):
            calls.append((url, headers, payload))

        sink = SplunkHecAuditSink("https://splunk:8088", "TOKEN", poster=poster)
        sink.write(EVENT)
        sink.write({"outcome": "ALLOW", "method": "http.get"})
        sink.flush()
        sink.close()

        assert len(calls) == 2
        url, headers, payload = calls[0]
        assert url == "https://splunk:8088/services/collector/event"
        assert headers["Authorization"] == "Splunk TOKEN"
        assert payload["event"] == EVENT
        assert payload["sourcetype"] == "apg:audit"

    def test_delivery_failure_is_swallowed(self):
        def boom(url, headers, payload):
            raise RuntimeError("network down")

        sink = SplunkHecAuditSink("https://splunk:8088", "TOKEN", poster=boom)
        sink.write(EVENT)  # must not raise
        sink.flush()
        sink.close()


class TestFactory:
    def test_syslog_target(self):
        sink = build_audit_sink("syslog://127.0.0.1:5514")
        try:
            assert isinstance(sink, SyslogAuditSink)
        finally:
            sink.close()

    def test_splunk_hec_target(self):
        sink = build_audit_sink("splunk-hec://mytoken@splunk.example.com:8088")
        try:
            assert isinstance(sink, SplunkHecAuditSink)
            assert sink._endpoint == "https://splunk.example.com:8088/services/collector/event"
            assert sink._headers["Authorization"] == "Splunk mytoken"
        finally:
            sink.close()

    def test_jsonl_and_sqlite_still_selected(self, tmp_path):
        assert isinstance(build_audit_sink(str(tmp_path / "a.jsonl")), JsonlAuditSink)
        s = build_audit_sink(str(tmp_path / "a.db"))
        try:
            assert isinstance(s, SqliteAuditSink)
        finally:
            s.close()
