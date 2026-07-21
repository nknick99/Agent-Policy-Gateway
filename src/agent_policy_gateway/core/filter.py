"""Response filtering module for Agent Policy Gateway Proxy.

Scans execution results for secrets and credentials before returning
them to the AI agent. Detected patterns are replaced with "[REDACTED]".
The original result object is never mutated.
"""

import re
from typing import Any

# Patterns that indicate secrets/credentials in response data.
# These same patterns are reused by the audit logger for redacting params.
SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                        # AWS Access Key
    re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+"),   # JWT tokens
    re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),   # PEM private keys
    re.compile(r"sk-[A-Za-z0-9]{32,}"),                     # API keys (OpenAI-style)
]

_REDACTED = "[REDACTED]"
_MAX_DEPTH = 50


def filter_response(raw_result: Any) -> Any:
    """Scan response for secrets/credentials before returning to agent.

    Replaces detected patterns with [REDACTED].
    Does not mutate the original result.

    Handles top-level string, dict, and list inputs. Other types are
    returned as-is.
    """
    if isinstance(raw_result, str):
        return _filter_string(raw_result)
    elif isinstance(raw_result, dict):
        return {k: _filter_value(v, depth=0) for k, v in raw_result.items()}
    elif isinstance(raw_result, list):
        return [_filter_value(item, depth=0) for item in raw_result]
    return raw_result


def _filter_value(value: Any, depth: int = 0) -> Any:
    """Recursively filter values, redacting secrets.

    Stops recursing beyond _MAX_DEPTH (50 levels) to prevent stack overflow
    on pathological inputs.
    """
    if depth >= _MAX_DEPTH:
        return value
    if isinstance(value, str):
        return _filter_string(value)
    elif isinstance(value, dict):
        return {k: _filter_value(v, depth + 1) for k, v in value.items()}
    elif isinstance(value, list):
        return [_filter_value(item, depth + 1) for item in value]
    return value


def _filter_string(value: str) -> str:
    """Check a string against all secret patterns.

    If any pattern matches, the entire string is replaced with [REDACTED].
    Multiple pattern matches still produce a single [REDACTED] placeholder.
    """
    for pattern in SECRET_PATTERNS:
        if pattern.search(value):
            return _REDACTED
    return value
