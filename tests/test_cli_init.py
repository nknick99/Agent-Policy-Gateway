"""`apg init` must generate a policy that actually validates.

Regression guard: the starter policy previously omitted the required
`caller_auth` field, so `apg init && apg policy validate` failed out of the box.
"""

from __future__ import annotations

from argparse import Namespace

from agent_policy_gateway.cli import _run_init
from agent_policy_gateway.core.policy import load_policy_document


def test_init_generates_a_valid_default_deny_policy(tmp_path):
    output = tmp_path / "policy.json"
    _run_init(Namespace(output=str(output)))

    # Loads and validates through the real loader (which also enforces
    # default-deny), the same path `apg policy validate` uses.
    policy = load_policy_document(str(output))
    assert policy.default == "deny"
    assert policy.caller_auth.method == "shared_token"
    # The starter policy demonstrates the recommended SQL parsing.
    assert policy.tools["db.query"].sql is not None
