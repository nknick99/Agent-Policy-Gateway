"""Agent Policy Gateway STS credential broker.

Mints just-in-time, downscoped AWS credentials via STS AssumeRole with
inline session policies. Credentials are used once and immediately discarded
by overwriting sensitive fields with zero-value bytes before dereferencing.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mypy_boto3_sts import STSClient

logger = logging.getLogger(__name__)


class CredentialMintError(Exception):
    """Raised when credential minting fails.

    Carries a generic user-facing message that does not leak
    AWS SDK errors, ARNs, or account IDs.
    """

    def __init__(self, message: str = "Credential minting failed") -> None:
        super().__init__(message)


@dataclass
class JitCredentials:
    """Just-in-time AWS credentials returned by STS AssumeRole.

    This is intentionally NOT frozen — fields must be mutable so that
    the discard method can overwrite them with zero-value bytes.
    """

    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: str


class StsBroker:
    """Mints short-lived AWS credentials and provides secure discard.

    Accepts an optional STS client for testability. If not provided,
    a boto3 STS client is created lazily on first use.
    """

    def __init__(self, sts_client: STSClient | None = None) -> None:
        self._sts_client = sts_client

    def _get_client(self) -> STSClient:
        """Lazily create the STS client if not injected."""
        if self._sts_client is None:
            import boto3

            self._sts_client = boto3.client("sts")
        return self._sts_client

    def mint_credentials(
        self,
        role_arn: str,
        session_policy: dict,
        session_name: str,
        duration_seconds: int = 900,
    ) -> JitCredentials:
        """Mint JIT AWS credentials via STS AssumeRole with inline session policy.

        Args:
            role_arn: The ARN of the IAM role to assume.
            session_policy: Inline IAM policy document to downscope permissions.
            session_name: RoleSessionName for CloudTrail tracing. Should contain
                the correlation_id for audit attribution.
            duration_seconds: Credential TTL in seconds. Defaults to 900 (15 min).

        Returns:
            JitCredentials with temporary access key, secret, and session token.

        Raises:
            CredentialMintError: If role_arn or session_policy is missing/empty,
                or if the STS AssumeRole call fails. The error message is generic
                and does not leak AWS SDK details.
        """
        # Fail-closed: reject missing or empty inputs
        if not role_arn or not role_arn.strip():
            raise CredentialMintError("Credential minting failed")

        if not session_policy:
            raise CredentialMintError("Credential minting failed")

        try:
            client = self._get_client()
            response = client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                Policy=json.dumps(session_policy),
                DurationSeconds=duration_seconds,
            )
        except Exception:
            # Catch all STS/boto errors — never leak AWS details
            raise CredentialMintError("Credential minting failed") from None

        credentials = response["Credentials"]
        return JitCredentials(
            access_key_id=credentials["AccessKeyId"],
            secret_access_key=credentials["SecretAccessKey"],
            session_token=credentials["SessionToken"],
            expiration=str(credentials["Expiration"]),
        )

    @staticmethod
    def discard(creds: JitCredentials) -> None:
        """Securely overwrite credential strings with zero-value bytes.

        Overwrites access_key_id, secret_access_key, and session_token with
        '\\x00' bytes of equal length, then allows normal garbage collection.

        This method is designed to be called in a finally block to guarantee
        credential cleanup regardless of success or failure paths.

        Args:
            creds: The JitCredentials instance to discard.
        """
        if creds is None:
            return

        try:
            creds.access_key_id = "\x00" * len(creds.access_key_id)
            creds.secret_access_key = "\x00" * len(creds.secret_access_key)
            creds.session_token = "\x00" * len(creds.session_token)
        except Exception:
            # Requirement 6.6: If overwrite itself raises, log and continue
            # with dereferencing. Never let cleanup failure propagate.
            logger.error("Failed to overwrite credential fields during discard")
