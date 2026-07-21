"""Null credential broker — the default.

For deployments where the gateway's own credentials (or none at all)
are used to reach targets. Mints nothing, discards nothing, never
fails. Opt into per-request STS minting with credential_broker:
"aws_sts" in policy.json.
"""

from __future__ import annotations

from typing import Any


class NullBroker:
    """CredentialBroker port implementation that mints no credentials."""

    def mint_credentials(
        self, role_arn: str, session_policy: dict, session_name: str
    ) -> None:
        return None

    def discard(self, creds: Any) -> None:
        return None
