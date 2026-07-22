"""Splunk HTTP Event Collector (HEC) audit sink.

POSTs each audit event as JSON to a Splunk HEC endpoint. Because HEC is a
network call, events are handed to a background worker thread and posted off the
request path — `write` never blocks the proxy. Best-effort: delivery failures are
swallowed (audit must not break enforcement); pair with a durable local sink if
guaranteed delivery matters. Write-only: `read` returns nothing.
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from typing import Any

# (endpoint, headers, json_payload) -> None
Poster = Callable[[str, dict[str, str], dict[str, Any]], None]

_STOP = object()


class SplunkHecAuditSink:
    """Forward audit events to Splunk HEC via a background worker."""

    def __init__(
        self,
        base_url: str,
        token: str,
        sourcetype: str = "apg:audit",
        verify: bool = True,
        poster: Poster | None = None,
    ) -> None:
        self._endpoint = base_url.rstrip("/") + "/services/collector/event"
        self._headers = {"Authorization": f"Splunk {token}"}
        self._sourcetype = sourcetype
        self._verify = verify
        self._post = poster or self._default_post
        self._queue: queue.Queue[Any] = queue.Queue()
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()

    def _default_post(
        self, url: str, headers: dict[str, str], payload: dict[str, Any]
    ) -> None:
        import httpx

        httpx.post(url, headers=headers, json=payload, timeout=5.0, verify=self._verify)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP:
                    return
                self._post(
                    self._endpoint,
                    self._headers,
                    {"event": item, "sourcetype": self._sourcetype},
                )
            except Exception:
                pass
            finally:
                self._queue.task_done()

    def write(self, event: dict[str, Any]) -> None:
        self._queue.put(event)

    def read(self, limit: int | None = None, outcome: str | None = None) -> list[dict[str, Any]]:
        return []

    def flush(self, timeout: float | None = None) -> None:
        """Block until queued events have been processed (mainly for tests)."""
        self._queue.join()

    def close(self) -> None:
        self._queue.put(_STOP)
        self._worker.join(timeout=5)
