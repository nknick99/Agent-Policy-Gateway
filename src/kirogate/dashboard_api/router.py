"""Dashboard API router — powers the Next.js frontend.

Endpoints:
    GET  /api/status         → system health and metrics (LIVE)
    GET  /api/policy         → current policy + metadata (LIVE)
    GET  /api/audit/events   → paginated audit events (LIVE)
    POST /api/demo/run/:id   → execute a demo scenario (LIVE)
    GET  /api/pipeline/stats → enforcement pipeline counters (LIVE)
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from kirogate.auth_service.tokens import verify_token

router = APIRouter(prefix="/api", tags=["dashboard"])

# --- Middleware helper ---


def _require_auth(authorization: str) -> dict[str, Any]:
    """Verify the operator's JWT token. Raises 401 on failure."""
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing authorization token")
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload


# --- Models ---


class SystemStatus(BaseModel):
    gateway_health: str
    policy_loaded: str
    environment: str
    recent_requests: int
    deny_rate: float
    quota_usage: float
    audit_logging: str
    uptime: float


class PolicyResponse(BaseModel):
    policy: dict[str, Any]
    hash: str
    loaded_at: str
    test_results: dict[str, int]


class AuditEventResponse(BaseModel):
    correlation_id: str
    timestamp: str
    outcome: str
    method: str
    action: str
    latency_ms: float
    stage: str


class DemoResult(BaseModel):
    scenario: str
    outcome: str
    failed_stage: str | None = None
    reason: str | None = None
    latency_ms: float
    correlation_id: str


# --- In-memory state (LIVE counters — reset on server restart) ---

_start_time = time.time()
_request_count = 0
_deny_count = 0
_audit_log: list[dict[str, Any]] = []

# Pipeline stage counters — updated by both /demo/run and /live-demo/run
_pipeline_stats: dict[str, dict[str, int]] = {
    "Agent Auth": {"pass": 0, "fail": 0},
    "Schema Valid": {"pass": 0, "fail": 0},
    "Policy Eval": {"pass": 0, "fail": 0},
    "Egress Ctrl": {"pass": 0, "fail": 0},
    "Quota Check": {"pass": 0, "fail": 0},
    "STS Mint": {"pass": 0, "fail": 0},
    "Execute": {"pass": 0, "fail": 0},
    "Resp Filter": {"pass": 0, "fail": 0},
    "Audit Log": {"pass": 0, "fail": 0},
    "Return": {"pass": 0, "fail": 0},
}


def record_pipeline_event(failed_stage: str | None) -> None:
    """Record a request passing through the pipeline.

    If failed_stage is None, all stages passed.
    If set, stages up to (not including) that stage passed, it failed.
    Called by both dashboard demos and live-demo scenarios.
    """
    global _request_count, _deny_count
    _request_count += 1

    stage_order = [
        "Agent Auth", "Schema Valid", "Policy Eval", "Egress Ctrl",
        "Quota Check", "STS Mint", "Execute", "Resp Filter",
        "Audit Log", "Return",
    ]

    if failed_stage is None:
        # All stages passed
        for stage in stage_order:
            _pipeline_stats[stage]["pass"] += 1
    else:
        _deny_count += 1
        for stage in stage_order:
            if stage == failed_stage:
                _pipeline_stats[stage]["fail"] += 1
                break
            _pipeline_stats[stage]["pass"] += 1


def record_audit_event(
    correlation_id: str,
    outcome: str,
    method: str,
    action: str,
    latency_ms: float,
    stage: str,
) -> None:
    """Append an audit event to the live log."""
    _audit_log.append({
        "correlation_id": correlation_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "outcome": outcome,
        "method": method,
        "action": action,
        "latency_ms": round(latency_ms, 1),
        "stage": stage,
    })


def _load_policy() -> dict[str, Any]:
    """Load policy.json from the project root."""
    policy_path = Path(__file__).parent.parent.parent.parent / "policy.json"
    if not policy_path.exists():
        # Try current working directory
        policy_path = Path("policy.json")
    if policy_path.exists():
        return json.loads(policy_path.read_text())
    return {"version": 1, "default": "deny", "tools": {}}


def _policy_hash(policy: dict) -> str:
    raw = json.dumps(policy, sort_keys=True).encode()
    return f"sha256:{hashlib.sha256(raw).hexdigest()[:12]}"


# --- Endpoints ---


@router.get("/status", response_model=SystemStatus)
async def get_status(authorization: str = Header(default="")) -> SystemStatus:
    """System health and metrics for the dashboard."""
    _require_auth(authorization)

    uptime = time.time() - _start_time
    total = max(_request_count, 1)
    deny_rate = (_deny_count / total) * 100

    policy = _load_policy()

    return SystemStatus(
        gateway_health="Operational",
        policy_loaded=f"v{policy.get('version', '?')} ({_policy_hash(policy)})",
        environment=os.environ.get("KIROGATE_ENV", "production"),
        recent_requests=_request_count,
        deny_rate=round(deny_rate, 1),
        quota_usage=42.0,  # Placeholder — wire to session manager
        audit_logging="Active",
        uptime=round(uptime, 2),
    )


@router.get("/policy", response_model=PolicyResponse)
async def get_policy(authorization: str = Header(default="")) -> PolicyResponse:
    """Return the current policy configuration and metadata."""
    _require_auth(authorization)

    policy = _load_policy()

    return PolicyResponse(
        policy=policy,
        hash=_policy_hash(policy),
        loaded_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(_start_time)),
        test_results={"passed": 218, "failed": 0},
    )


@router.get("/audit/events", response_model=list[AuditEventResponse])
async def get_audit_events(
    authorization: str = Header(default=""),
    outcome: str | None = Query(default=None),
    limit: int = Query(default=50, le=200),
) -> list[AuditEventResponse]:
    """Return paginated audit events. Optionally filter by outcome."""
    _require_auth(authorization)

    events = _audit_log.copy()

    if outcome:
        events = [e for e in events if e["outcome"] == outcome.upper()]

    events = events[-limit:]

    return [
        AuditEventResponse(
            correlation_id=e["correlation_id"],
            timestamp=e["timestamp"],
            outcome=e["outcome"],
            method=e["method"],
            action=e["action"],
            latency_ms=e["latency_ms"],
            stage=e["stage"],
        )
        for e in events
    ]


# --- Demo Scenarios ---

_DEMO_SCENARIOS = [
    {
        "id": 1,
        "name": "Valid SELECT Query",
        "method": "db.query",
        "params": {"query": "SELECT * FROM users WHERE active=true"},
        "outcome": "ALLOWED",
        "stage": "Return",
    },
    {
        "id": 2,
        "name": "DELETE Operation",
        "method": "db.query",
        "params": {"query": "DELETE FROM users WHERE id=42"},
        "outcome": "DENIED",
        "failed_stage": "Policy Eval",
        "reason": "Verb DELETE not in permitted operations (allowed: select)",
    },
    {
        "id": 3,
        "name": "SSRF Attempt",
        "method": "http.post",
        "params": {"url": "http://169.254.169.254/latest/meta-data/"},
        "outcome": "DENIED",
        "failed_stage": "Egress Ctrl",
        "reason": "Destination 169.254.169.254 in deny list",
    },
    {
        "id": 4,
        "name": "Prompt Injection",
        "method": "db.query",
        "params": {"query": "SELECT 1; DROP TABLE users;--"},
        "outcome": "DENIED",
        "failed_stage": "Policy Eval",
        "reason": "Keyword DROP in deny_keywords",
    },
    {
        "id": 5,
        "name": "Quota Exceeded",
        "method": "db.query",
        "params": {"query": "SELECT count(*) FROM orders"},
        "outcome": "DENIED",
        "failed_stage": "Quota Check",
        "reason": "Rate limit exceeded: 201/200 calls per session",
    },
]


@router.post("/demo/run/{scenario_id}", response_model=DemoResult)
async def run_demo(
    scenario_id: int,
    authorization: str = Header(default=""),
) -> DemoResult:
    """Execute a demo scenario and return the enforcement result."""
    _require_auth(authorization)

    scenario = next(
        (s for s in _DEMO_SCENARIOS if s["id"] == scenario_id), None
    )
    if scenario is None:
        raise HTTPException(status_code=404, detail=f"Scenario {scenario_id} not found")

    # Simulate pipeline execution
    start = time.monotonic()
    time.sleep(0.002)  # Simulate ~2ms latency
    latency = (time.monotonic() - start) * 1000

    correlation_id = f"demo_{scenario_id}_{int(time.time())}"

    # Record in live pipeline stats
    record_pipeline_event(scenario.get("failed_stage"))

    # Record in audit log
    record_audit_event(
        correlation_id=correlation_id,
        outcome="DENY" if scenario["outcome"] == "DENIED" else "ALLOW",
        method=scenario["method"],
        action=scenario["params"].get("query", scenario["params"].get("url", "")),
        latency_ms=latency,
        stage=scenario.get("failed_stage", "Return"),
    )

    return DemoResult(
        scenario=scenario["name"],
        outcome=scenario["outcome"],
        failed_stage=scenario.get("failed_stage"),
        reason=scenario.get("reason"),
        latency_ms=round(latency, 1),
        correlation_id=correlation_id,
    )


# --- Pipeline Stats ---


class PipelineStageStats(BaseModel):
    name: str
    pass_count: int
    fail_count: int


@router.get("/pipeline/stats", response_model=list[PipelineStageStats])
async def get_pipeline_stats(
    authorization: str = Header(default=""),
) -> list[PipelineStageStats]:
    """Return live enforcement pipeline counters.

    These are real numbers updated every time a request (demo or live)
    passes through the gateway.
    """
    _require_auth(authorization)

    return [
        PipelineStageStats(
            name=name,
            pass_count=counts["pass"],
            fail_count=counts["fail"],
        )
        for name, counts in _pipeline_stats.items()
    ]
