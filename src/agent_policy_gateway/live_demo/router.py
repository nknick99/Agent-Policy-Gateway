"""Live Demo API router.

Exposes endpoints for running real AI agent scenarios through Agent Policy Gateway.
"""

from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel

from agent_policy_gateway.auth_service.tokens import verify_token
from agent_policy_gateway.dashboard_api.router import record_audit_event, record_pipeline_event
from agent_policy_gateway.live_demo.database import reset_database
from agent_policy_gateway.live_demo.llm_provider import get_provider
from agent_policy_gateway.live_demo.scenarios import run_scenario

router = APIRouter(prefix="/api/live-demo", tags=["live-demo"])


def _require_auth(authorization: str) -> dict:
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload


class ScenarioInfo(BaseModel):
    id: int
    name: str
    description: str
    category: str
    expected_outcome: str


class PipelineStageResponse(BaseModel):
    name: str
    passed: bool
    detail: str
    duration_ms: float


class ScenarioResultResponse(BaseModel):
    scenario_id: int
    scenario_name: str
    description: str
    agent_intent: str
    agent_action: str
    outcome: str
    denied_at: str | None
    denial_reason: str | None
    pipeline: list[PipelineStageResponse]
    query_result: list[dict] | None
    filtered_result: list[dict] | None
    total_latency_ms: float
    llm_provider: str


SCENARIO_LIST = [
    ScenarioInfo(
        id=1,
        name="Read Customer Data",
        description="AI agent queries active customers from the database. "
        "Agent Policy Gateway allows the SELECT and redacts sensitive fields.",
        category="Database Query",
        expected_outcome="ALLOWED",
    ),
    ScenarioInfo(
        id=2,
        name="Delete Customer Records",
        description="AI agent tries to DELETE old records. "
        "Agent Policy Gateway blocks — only SELECT is permitted.",
        category="Database Mutation",
        expected_outcome="DENIED",
    ),
    ScenarioInfo(
        id=3,
        name="SSRF — Cloud Metadata",
        description="AI agent tries to access AWS metadata endpoint (169.254.169.254) "
        "to steal IAM credentials. Egress control blocks it.",
        category="Network / SSRF",
        expected_outcome="DENIED",
    ),
    ScenarioInfo(
        id=4,
        name="Data Exfiltration",
        description="AI agent tries to send customer PII to an external attacker endpoint. "
        "Egress control blocks unapproved destinations.",
        category="Data Loss Prevention",
        expected_outcome="DENIED",
    ),
]


@router.get("/scenarios", response_model=list[ScenarioInfo])
async def list_scenarios(authorization: str = Header(default="")) -> list[ScenarioInfo]:
    """List available live demo scenarios."""
    _require_auth(authorization)
    return SCENARIO_LIST


@router.post("/run/{scenario_id}", response_model=ScenarioResultResponse)
async def execute_scenario(
    scenario_id: int,
    authorization: str = Header(default=""),
    provider: str = Query(default="auto", description="LLM provider: auto, ollama, openai, mock"),
) -> ScenarioResultResponse:
    """Run a live demo scenario with a real LLM agent.

    The agent generates an intent, Agent Policy Gateway evaluates it through
    the full policy pipeline, and returns the allow/deny decision
    with full evidence.
    """
    _require_auth(authorization)

    if scenario_id not in [1, 2, 3, 4]:
        raise HTTPException(status_code=404, detail="Scenario not found (1-4)")

    llm = get_provider(provider)
    result = await run_scenario(scenario_id, llm)

    # Record into shared dashboard stats (live data!)
    record_pipeline_event(result.denied_at)
    record_audit_event(
        correlation_id=f"live_{scenario_id}_{int(__import__('time').time())}",
        outcome="DENY" if result.outcome == "DENIED" else "ALLOW",
        method=result.scenario_name,
        action=result.agent_action,
        latency_ms=result.total_latency_ms,
        stage=result.denied_at or "Return",
    )

    return ScenarioResultResponse(
        scenario_id=result.scenario_id,
        scenario_name=result.scenario_name,
        description=result.description,
        agent_intent=result.agent_intent,
        agent_action=result.agent_action,
        outcome=result.outcome,
        denied_at=result.denied_at,
        denial_reason=result.denial_reason,
        pipeline=[
            PipelineStageResponse(
                name=s.name,
                passed=s.passed,
                detail=s.detail,
                duration_ms=round(s.duration_ms, 2),
            )
            for s in result.pipeline
        ],
        query_result=result.query_result,
        filtered_result=result.filtered_result,
        total_latency_ms=round(result.total_latency_ms, 2),
        llm_provider=result.llm_provider,
    )


@router.post("/reset")
async def reset_demo(authorization: str = Header(default="")) -> dict:
    """Reset the demo database to initial state."""
    _require_auth(authorization)
    reset_database()
    return {"status": "ok", "message": "Database reset to initial state"}
