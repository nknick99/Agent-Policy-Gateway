"""Agent Service — standalone microservice.

Handles LLM provider abstraction and live demo scenarios.
This service is pluggable — swap the LLM provider without
affecting the rest of the system.

Endpoints:
    GET  /api/live-demo/scenarios    → list demo scenarios
    POST /api/live-demo/run/:id      → run a scenario
    POST /api/live-demo/reset        → reset demo database
    GET  /health                     → readiness probe
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agent_policy_gateway.live_demo.router import router as live_demo_router

app = FastAPI(title="Agent Policy Gateway Agent Service", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(live_demo_router)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "agent",
        "llm_provider": os.environ.get("LLM_PROVIDER", "auto"),
    }
