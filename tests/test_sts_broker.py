"""Tests for Agent Policy Gateway STS credential broker."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from agent_policy_gateway.adapters.brokers.aws_sts import (
    CredentialMintError,
    JitCredentials,
    StsBroker,
)

# --- Fixtures ---


@pytest.fixture
def mock_sts_client():
    """Create a mock STS client with a successful AssumeRole response."""
    client = MagicMock()
    client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "FwoGZXIvYXdzEBYaDHqa0AP1",
            "Expiration": datetime(2025, 1, 1, 0, 15, 0, tzinfo=UTC),
        },
        "AssumedRoleUser": {
            "AssumedRoleId": "AROA3XFRBF23:apg-abc123",
            "Arn": "arn:aws:sts::123456789012:assumed-role/TestRole/apg-abc123",
        },
    }
    return client


@pytest.fixture
def broker(mock_sts_client):
    """Create a StsBroker with an injected mock STS client."""
    return StsBroker(sts_client=mock_sts_client)


@pytest.fixture
def valid_role_arn():
    return "arn:aws:iam::123456789012:role/Agent Policy GatewayAgentRole"


@pytest.fixture
def valid_session_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem"],
                "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/orders",
            }
        ],
    }


# --- TestMintCredentials ---


class TestMintCredentials:
    """Tests for StsBroker.mint_credentials."""

    def test_successful_mint_returns_jit_credentials(
        self, broker, mock_sts_client, valid_role_arn, valid_session_policy
    ):
        """Successful AssumeRole returns populated JitCredentials."""
        creds = broker.mint_credentials(
            role_arn=valid_role_arn,
            session_policy=valid_session_policy,
            session_name="apg-abc12345",
        )

        assert isinstance(creds, JitCredentials)
        assert creds.access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert creds.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert creds.session_token == "FwoGZXIvYXdzEBYaDHqa0AP1"
        assert "2025" in creds.expiration

    def test_calls_sts_with_correct_parameters(
        self, broker, mock_sts_client, valid_role_arn, valid_session_policy
    ):
        """AssumeRole is called with role ARN, session policy, name, and duration."""
        broker.mint_credentials(
            role_arn=valid_role_arn,
            session_policy=valid_session_policy,
            session_name="apg-corr1234",
            duration_seconds=900,
        )

        mock_sts_client.assume_role.assert_called_once()
        call_kwargs = mock_sts_client.assume_role.call_args[1]
        assert call_kwargs["RoleArn"] == valid_role_arn
        assert call_kwargs["RoleSessionName"] == "apg-corr1234"
        assert call_kwargs["DurationSeconds"] == 900
        assert '"dynamodb:GetItem"' in call_kwargs["Policy"]

    def test_default_duration_is_900(
        self, broker, mock_sts_client, valid_role_arn, valid_session_policy
    ):
        """Default DurationSeconds is 900 (15 minutes)."""
        broker.mint_credentials(
            role_arn=valid_role_arn,
            session_policy=valid_session_policy,
            session_name="apg-test",
        )

        call_kwargs = mock_sts_client.assume_role.call_args[1]
        assert call_kwargs["DurationSeconds"] == 900

    def test_session_name_contains_correlation_id(
        self, broker, mock_sts_client, valid_role_arn, valid_session_policy
    ):
        """RoleSessionName should contain the correlation_id for CloudTrail tracing."""
        correlation_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        session_name = f"apg-{correlation_id[:8]}"

        broker.mint_credentials(
            role_arn=valid_role_arn,
            session_policy=valid_session_policy,
            session_name=session_name,
        )

        call_kwargs = mock_sts_client.assume_role.call_args[1]
        assert call_kwargs["RoleSessionName"] == "apg-a1b2c3d4"

    def test_empty_role_arn_raises_credential_mint_error(
        self, broker, valid_session_policy
    ):
        """Empty role ARN raises CredentialMintError (fail-closed)."""
        with pytest.raises(CredentialMintError) as exc_info:
            broker.mint_credentials(
                role_arn="",
                session_policy=valid_session_policy,
                session_name="apg-test",
            )
        assert "Credential minting failed" in str(exc_info.value)

    def test_none_role_arn_raises_credential_mint_error(
        self, broker, valid_session_policy
    ):
        """None role ARN raises CredentialMintError (fail-closed)."""
        with pytest.raises(CredentialMintError) as exc_info:
            broker.mint_credentials(
                role_arn=None,
                session_policy=valid_session_policy,
                session_name="apg-test",
            )
        assert "Credential minting failed" in str(exc_info.value)

    def test_whitespace_only_role_arn_raises_credential_mint_error(
        self, broker, valid_session_policy
    ):
        """Whitespace-only role ARN raises CredentialMintError (fail-closed)."""
        with pytest.raises(CredentialMintError) as exc_info:
            broker.mint_credentials(
                role_arn="   ",
                session_policy=valid_session_policy,
                session_name="apg-test",
            )
        assert "Credential minting failed" in str(exc_info.value)

    def test_empty_session_policy_raises_credential_mint_error(
        self, broker, valid_role_arn
    ):
        """Empty session policy raises CredentialMintError (fail-closed)."""
        with pytest.raises(CredentialMintError) as exc_info:
            broker.mint_credentials(
                role_arn=valid_role_arn,
                session_policy={},
                session_name="apg-test",
            )
        assert "Credential minting failed" in str(exc_info.value)

    def test_none_session_policy_raises_credential_mint_error(
        self, broker, valid_role_arn
    ):
        """None session policy raises CredentialMintError (fail-closed)."""
        with pytest.raises(CredentialMintError) as exc_info:
            broker.mint_credentials(
                role_arn=valid_role_arn,
                session_policy=None,
                session_name="apg-test",
            )
        assert "Credential minting failed" in str(exc_info.value)

    def test_sts_failure_raises_credential_mint_error(
        self, broker, mock_sts_client, valid_role_arn, valid_session_policy
    ):
        """STS AssumeRole failure raises CredentialMintError with generic message."""
        from botocore.exceptions import ClientError

        mock_sts_client.assume_role.side_effect = ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "Not authorized"}},
            operation_name="AssumeRole",
        )

        with pytest.raises(CredentialMintError) as exc_info:
            broker.mint_credentials(
                role_arn=valid_role_arn,
                session_policy=valid_session_policy,
                session_name="apg-test",
            )
        # Generic message — no AWS details leaked
        assert str(exc_info.value) == "Credential minting failed"

    def test_sts_error_does_not_leak_aws_details(
        self, broker, mock_sts_client, valid_role_arn, valid_session_policy
    ):
        """Error message must not contain ARNs, account IDs, or SDK error details."""
        from botocore.exceptions import ClientError

        mock_sts_client.assume_role.side_effect = ClientError(
            error_response={
                "Error": {
                    "Code": "MalformedPolicyDocument",
                    "Message": "Policy for arn:aws:iam::123456789012:role/Foo is invalid",
                }
            },
            operation_name="AssumeRole",
        )

        with pytest.raises(CredentialMintError) as exc_info:
            broker.mint_credentials(
                role_arn=valid_role_arn,
                session_policy=valid_session_policy,
                session_name="apg-test",
            )

        error_msg = str(exc_info.value)
        assert "arn:aws" not in error_msg
        assert "123456789012" not in error_msg
        assert "MalformedPolicyDocument" not in error_msg


# --- TestDiscard ---


class TestDiscard:
    """Tests for StsBroker.discard."""

    def test_overwrites_access_key_id_with_zero_bytes(self):
        """access_key_id is overwritten with \\x00 bytes of equal length."""
        creds = JitCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="FwoGZXIvYXdzEBYaDHqa0AP1",
            expiration="2025-01-01T00:15:00+00:00",
        )
        original_len = len(creds.access_key_id)

        StsBroker.discard(creds)

        assert creds.access_key_id == "\x00" * original_len
        assert len(creds.access_key_id) == original_len

    def test_overwrites_secret_access_key_with_zero_bytes(self):
        """secret_access_key is overwritten with \\x00 bytes of equal length."""
        creds = JitCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="FwoGZXIvYXdzEBYaDHqa0AP1",
            expiration="2025-01-01T00:15:00+00:00",
        )
        original_len = len(creds.secret_access_key)

        StsBroker.discard(creds)

        assert creds.secret_access_key == "\x00" * original_len
        assert len(creds.secret_access_key) == original_len

    def test_overwrites_session_token_with_zero_bytes(self):
        """session_token is overwritten with \\x00 bytes of equal length."""
        creds = JitCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="FwoGZXIvYXdzEBYaDHqa0AP1",
            expiration="2025-01-01T00:15:00+00:00",
        )
        original_len = len(creds.session_token)

        StsBroker.discard(creds)

        assert creds.session_token == "\x00" * original_len
        assert len(creds.session_token) == original_len

    def test_discard_none_does_not_raise(self):
        """Passing None to discard should not raise."""
        StsBroker.discard(None)  # Should not raise

    def test_discard_handles_overwrite_failure_gracefully(self):
        """If overwrite raises, log error and continue (requirement 6.6)."""
        creds = JitCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="FwoGZXIvYXdzEBYaDHqa0AP1",
            expiration="2025-01-01T00:15:00+00:00",
        )

        # Make the credential object raise on attribute set
        with patch.object(
            JitCredentials, "__setattr__", side_effect=RuntimeError("memory error")
        ):
            # Should not raise — logs error and continues
            StsBroker.discard(creds)

    def test_discard_in_finally_block_pattern(self):
        """Demonstrate that discard works in a finally block for guaranteed cleanup."""
        creds = JitCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="secret123",
            session_token="token456",
            expiration="2025-01-01T00:15:00+00:00",
        )

        try:
            # Simulate an operation that raises
            raise ValueError("simulated failure")
        except ValueError:
            pass
        finally:
            StsBroker.discard(creds)

        # Credentials should be zeroed even after exception
        assert creds.access_key_id == "\x00" * len("AKIAIOSFODNN7EXAMPLE")
        assert creds.secret_access_key == "\x00" * len("secret123")
        assert creds.session_token == "\x00" * len("token456")


# --- TestLazyClientCreation ---


class TestLazyClientCreation:
    """Tests for lazy boto3 client initialization."""

    def test_client_not_created_at_init(self):
        """STS client should not be created at __init__ time."""
        broker = StsBroker()
        assert broker._sts_client is None

    def test_injected_client_is_used(self, mock_sts_client, valid_role_arn, valid_session_policy):
        """Injected STS client is used instead of creating a new one."""
        broker = StsBroker(sts_client=mock_sts_client)
        broker.mint_credentials(
            role_arn=valid_role_arn,
            session_policy=valid_session_policy,
            session_name="apg-test",
        )
        mock_sts_client.assume_role.assert_called_once()

    @patch("boto3.client")
    def test_lazy_client_created_on_first_use(
        self, mock_boto3_client, valid_role_arn, valid_session_policy
    ):
        """Boto3 client is created lazily on first mint_credentials call."""
        mock_client = MagicMock()
        mock_client.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIATEST",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": datetime(2025, 1, 1, tzinfo=UTC),
            }
        }
        mock_boto3_client.return_value = mock_client

        broker = StsBroker()
        broker.mint_credentials(
            role_arn=valid_role_arn,
            session_policy=valid_session_policy,
            session_name="apg-test",
        )

        mock_boto3_client.assert_called_once_with("sts")


# --- TestCredentialMintError ---


class TestCredentialMintError:
    """Tests for the CredentialMintError exception class."""

    def test_default_message(self):
        """Default error message is generic."""
        err = CredentialMintError()
        assert str(err) == "Credential minting failed"

    def test_custom_message(self):
        """Custom messages can be provided."""
        err = CredentialMintError("Custom error")
        assert str(err) == "Custom error"

    def test_is_exception(self):
        """CredentialMintError inherits from Exception."""
        assert issubclass(CredentialMintError, Exception)
