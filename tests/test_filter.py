"""Unit tests for the response filtering module."""

import copy

import pytest

from agent_policy_gateway.filter import SECRET_PATTERNS, _REDACTED, filter_response


class TestSecretPatterns:
    """Verify each secret pattern detects its target."""

    def test_aws_access_key_detected(self):
        result = filter_response("Here is key AKIAIOSFODNN7EXAMPLE")
        assert result == _REDACTED

    def test_aws_access_key_exact_16_chars(self):
        # AKIA + exactly 16 uppercase alphanumeric
        result = filter_response("AKIA1234567890AB")
        # Only 12 chars after AKIA, should NOT match
        assert result != _REDACTED

        result = filter_response("AKIA1234567890ABCDEF")
        assert result == _REDACTED

    def test_jwt_token_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        result = filter_response(jwt)
        assert result == _REDACTED

    def test_jwt_requires_two_eyj_segments(self):
        # Single eyJ segment without dot-separated second eyJ should not match
        result = filter_response("eyJhbGciOiJIUzI1NiJ9.notajwt")
        assert result != _REDACTED

    def test_pem_private_key_generic(self):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg..."
        result = filter_response(pem)
        assert result == _REDACTED

    def test_pem_rsa_private_key(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ..."
        result = filter_response(pem)
        assert result == _REDACTED

    def test_pem_ec_private_key(self):
        pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBkg..."
        result = filter_response(pem)
        assert result == _REDACTED

    def test_api_key_sk_prefix_detected(self):
        # sk- followed by 32+ alphanumeric chars
        key = "sk-" + "a" * 32
        result = filter_response(key)
        assert result == _REDACTED

    def test_api_key_sk_prefix_too_short(self):
        # sk- followed by only 31 chars should NOT match
        key = "sk-" + "a" * 31
        result = filter_response(key)
        assert result != _REDACTED

    def test_api_key_sk_longer_than_32(self):
        key = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7"
        result = filter_response(key)
        assert result == _REDACTED


class TestRecursiveFiltering:
    """Verify recursive dict/list processing."""

    def test_nested_dict_secret_redacted(self):
        data = {"credentials": {"access_key": "AKIAIOSFODNN7EXAMPLE"}}
        result = filter_response(data)
        assert result["credentials"]["access_key"] == _REDACTED

    def test_nested_list_secret_redacted(self):
        data = [["safe", "AKIAIOSFODNN7EXAMPLE"]]
        result = filter_response(data)
        assert result[0][0] == "safe"
        assert result[0][1] == _REDACTED

    def test_deeply_nested_up_to_50_levels(self):
        # Build 49 levels of nesting (depth 0 to 48)
        data: dict = {"key": "AKIAIOSFODNN7EXAMPLE"}
        for _ in range(49):
            data = {"nested": data}
        result = filter_response(data)
        # Navigate 49 levels down
        node = result
        for _ in range(49):
            node = node["nested"]
        assert node["key"] == _REDACTED

    def test_stops_at_depth_50(self):
        # Build exactly 50 levels of nesting so the innermost is at depth 50
        data: dict = {"key": "AKIAIOSFODNN7EXAMPLE"}
        for _ in range(50):
            data = {"nested": data}
        result = filter_response(data)
        # Navigate 50 levels down - the secret should NOT be redacted
        node = result
        for _ in range(50):
            node = node["nested"]
        assert node["key"] == "AKIAIOSFODNN7EXAMPLE"

    def test_mixed_nesting(self):
        data = {
            "results": [
                {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"},
                {"safe_value": 42},
            ],
            "count": 2,
        }
        result = filter_response(data)
        assert result["results"][0]["token"] == _REDACTED
        assert result["results"][1]["safe_value"] == 42
        assert result["count"] == 2


class TestStructurePreservation:
    """Verify output structure matches input structure."""

    def test_dict_keys_preserved(self):
        data = {"a": "safe", "b": "AKIAIOSFODNN7EXAMPLE", "c": 123}
        result = filter_response(data)
        assert set(result.keys()) == {"a", "b", "c"}
        assert result["a"] == "safe"
        assert result["b"] == _REDACTED
        assert result["c"] == 123

    def test_list_length_preserved(self):
        data = ["safe", "AKIAIOSFODNN7EXAMPLE", 42, None, True]
        result = filter_response(data)
        assert len(result) == 5
        assert result[0] == "safe"
        assert result[1] == _REDACTED
        assert result[2] == 42
        assert result[3] is None
        assert result[4] is True

    def test_non_string_types_unchanged(self):
        data = {"int": 1, "float": 3.14, "bool": True, "none": None}
        result = filter_response(data)
        assert result == data

    def test_original_not_mutated(self):
        data = {"key": "AKIAIOSFODNN7EXAMPLE", "nested": {"inner": "sk-" + "x" * 32}}
        original = copy.deepcopy(data)
        filter_response(data)
        assert data == original


class TestTopLevelString:
    """Verify top-level string input handling (Requirement 8.7)."""

    def test_top_level_string_with_secret(self):
        result = filter_response("AKIAIOSFODNN7EXAMPLE")
        assert result == _REDACTED

    def test_top_level_string_safe(self):
        result = filter_response("hello world")
        assert result == "hello world"

    def test_top_level_string_with_pem(self):
        result = filter_response("-----BEGIN PRIVATE KEY-----\ndata")
        assert result == _REDACTED


class TestMultiplePatterns:
    """Verify multiple patterns produce single [REDACTED] (Requirement 8.8)."""

    def test_string_with_multiple_secrets(self):
        # String containing both AWS key and JWT
        value = "AKIAIOSFODNN7EXAMPLE eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"
        result = filter_response(value)
        assert result == _REDACTED

    def test_redacted_is_single_placeholder(self):
        value = "sk-" + "a" * 32 + " AKIAIOSFODNN7EXAMPLE"
        result = filter_response(value)
        assert result == _REDACTED
        assert result.count("[REDACTED]") == 1


class TestEdgeCases:
    """Miscellaneous edge cases."""

    def test_empty_string(self):
        assert filter_response("") == ""

    def test_empty_dict(self):
        assert filter_response({}) == {}

    def test_empty_list(self):
        assert filter_response([]) == []

    def test_non_container_types_passthrough(self):
        assert filter_response(42) == 42
        assert filter_response(3.14) == 3.14
        assert filter_response(True) is True
        assert filter_response(None) is None
