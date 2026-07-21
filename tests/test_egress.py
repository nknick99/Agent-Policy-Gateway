"""Tests for the egress controller — whitelist matching, deny lists, SSRF guards.

Includes regression tests derived from the shipped policy.json: whitelist
entries written as full URLs must actually match their destinations
(the original implementation compared hostname against the raw entry
string, denying every whitelisted destination).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_policy_gateway.core.egress import EgressController


def make_controller(
    whitelist: list[str] | None = None,
    deny: list[str] | None = None,
) -> EgressController:
    return EgressController(
        {
            "destination_whitelist": whitelist or [],
            "deny_destinations": deny or [],
        }
    )


class TestWhitelistMatching:
    def test_full_url_entry_matches_host(self):
        controller = make_controller(whitelist=["https://api.example.com"])
        result = controller.check("https://api.example.com/v1/data")
        assert result.allowed

    def test_bare_hostname_entry_matches_host(self):
        controller = make_controller(whitelist=["api.example.com"])
        result = controller.check("https://api.example.com/v1/data")
        assert result.allowed

    def test_entry_with_path_matches_host_only(self):
        controller = make_controller(whitelist=["api.example.com/v1"])
        result = controller.check("https://api.example.com/other")
        assert result.allowed

    def test_wildcard_matches_subdomain(self):
        controller = make_controller(whitelist=["*.amazonaws.com"])
        result = controller.check("https://s3.amazonaws.com/bucket")
        assert result.allowed

    def test_wildcard_does_not_match_apex(self):
        controller = make_controller(whitelist=["*.amazonaws.com"])
        result = controller.check("https://amazonaws.com/")
        assert not result.allowed

    def test_wildcard_does_not_match_suffix_trick(self):
        # evilamazonaws.com must not match *.amazonaws.com
        controller = make_controller(whitelist=["*.amazonaws.com"])
        result = controller.check("https://evilamazonaws.com/")
        assert not result.allowed

    def test_non_whitelisted_host_denied(self):
        controller = make_controller(whitelist=["https://api.example.com"])
        result = controller.check("https://evil.attacker.com/steal")
        assert not result.allowed

    def test_similar_prefix_host_denied(self):
        # api.example.com.attacker.com must not match api.example.com
        controller = make_controller(whitelist=["https://api.example.com"])
        result = controller.check("https://api.example.com.attacker.com/")
        assert not result.allowed

    def test_case_insensitive(self):
        controller = make_controller(whitelist=["https://API.Example.COM"])
        result = controller.check("https://api.example.com/")
        assert result.allowed


class TestDenyRules:
    def test_empty_whitelist_denies_everything(self):
        controller = make_controller()
        result = controller.check("https://api.example.com/")
        assert not result.allowed

    def test_metadata_ip_denied_even_if_whitelisted(self):
        controller = make_controller(whitelist=["169.254.169.254"])
        result = controller.check("http://169.254.169.254/latest/meta-data/")
        assert not result.allowed

    def test_link_local_range_denied(self):
        controller = make_controller(whitelist=["*.anything"])
        result = controller.check("http://169.254.1.1/")
        assert not result.allowed

    def test_google_metadata_hostname_denied(self):
        controller = make_controller(whitelist=["metadata.google.internal"])
        result = controller.check("http://metadata.google.internal/computeMetadata/")
        assert not result.allowed

    def test_policy_deny_destinations(self):
        controller = make_controller(
            whitelist=["https://blocked.example.com"],
            deny=["blocked.example.com"],
        )
        result = controller.check("https://blocked.example.com/")
        assert not result.allowed

    def test_unparseable_url_denied(self):
        controller = make_controller(whitelist=["api.example.com"])
        result = controller.check("not a url at all")
        assert not result.allowed


class TestShippedPolicyRegression:
    """Every destination_whitelist entry in the shipped policy.json must
    actually allow its own destination (regression for the full-URL
    whitelist-entry bug)."""

    @pytest.fixture()
    def shipped_policy(self) -> dict:
        policy_path = Path(__file__).parent.parent / "policy.json"
        return json.loads(policy_path.read_text())

    def test_every_whitelist_entry_matches_itself(self, shipped_policy):
        for tool_name, tool_config in shipped_policy["tools"].items():
            whitelist = tool_config.get("destination_whitelist", [])
            controller = EgressController(tool_config)
            for entry in whitelist:
                destination = (
                    entry if "://" in entry else f"https://{entry.lstrip('*.')}"
                )
                result = controller.check(destination)
                assert result.allowed, (
                    f"{tool_name}: whitelisted entry {entry!r} denied its own "
                    f"destination {destination!r}: {result.reason}"
                )
