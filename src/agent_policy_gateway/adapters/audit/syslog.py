"""Syslog audit sink — CEF over UDP/TCP to a SIEM collector.

Emits each audit event as an RFC 5424 syslog line whose message is the CEF
rendering of the event. This is the most widely ingested SIEM path (Splunk,
ArcSight, QRadar, Graylog, rsyslog, …). Write-only: `read` returns nothing —
query the SIEM, not the gateway.
"""

from __future__ import annotations

import socket
import time
from typing import Any

from agent_policy_gateway.adapters.audit.cef import to_cef

# facility local0 (16) * 8 + severity info (6) = 134
_PRI = 134


class SyslogAuditSink:
    """Forward audit events to a syslog collector as CEF."""

    def __init__(
        self,
        host: str,
        port: int = 514,
        protocol: str = "udp",
        app_name: str = "apg",
    ) -> None:
        self._host = host
        self._port = port
        self._protocol = protocol.lower()
        self._app_name = app_name
        self._hostname = socket.gethostname()
        if self._protocol == "tcp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.connect((host, port))
        else:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _frame(self, message: str) -> bytes:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # RFC 5424: <PRI>VER TIMESTAMP HOST APP PROCID MSGID MSG
        line = f"<{_PRI}>1 {timestamp} {self._hostname} {self._app_name} - - - {message}"
        # TCP syslog is newline-framed (RFC 6587 non-transparent framing).
        if self._protocol == "tcp":
            line += "\n"
        return line.encode("utf-8")

    def write(self, event: dict[str, Any]) -> None:
        try:
            data = self._frame(to_cef(event))
            if self._protocol == "tcp":
                self._sock.sendall(data)
            else:
                self._sock.sendto(data, (self._host, self._port))
        except Exception:
            # Audit forwarding must never break the request path.
            pass

    def read(self, limit: int | None = None, outcome: str | None = None) -> list[dict[str, Any]]:
        # Write-only forwarder — tail the SIEM, not the gateway.
        return []

    def close(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass
