"""KiroGate Interactive Prototype — Visual Pipeline Demo.

A polished web application that visually demonstrates the KiroGate
enforcement pipeline with animated flow diagrams, real-time request
testing, and step-by-step pipeline visualization.

Run with:
    $env:KIROGATE_AGENT_TOKEN = "demo-token-12345"
    python -m uvicorn kirogate.prototype:app --host 127.0.0.1 --port 9090 --app-dir src

Then open http://127.0.0.1:9090 in your browser.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from kirogate.audit import AuditEvent, AuditLogger, redact_params
from kirogate.auth import authenticate_caller, validate_startup
from kirogate.egress import EgressController
from kirogate.filter import filter_response
from kirogate.mode import ModeController
from kirogate.models import AuditDecision, Decision
from kirogate.policy import PolicyEvaluator
from kirogate.schemas import (
    SchemaValidationError,
    validate_envelope,
    validate_params,
)
from kirogate.session import SessionManager
from kirogate.sts_broker import CredentialMintError, StsBroker

logger = logging.getLogger(__name__)

# Module-level singletons
audit_logger: AuditLogger
policy_evaluator: PolicyEvaluator
session_manager: SessionManager
sts_broker: StsBroker
mode_controller: ModeController

# Store pipeline traces for the UI
_recent_traces: list[dict] = []
_MAX_TRACES = 30


@asynccontextmanager
async def lifespan(app: FastAPI):
    global audit_logger, policy_evaluator, session_manager, sts_broker, mode_controller
    validate_startup()
    policy_evaluator = PolicyEvaluator()
    audit_logger = AuditLogger()
    session_manager = SessionManager()
    sts_broker = StsBroker()
    mode_controller = ModeController()
    yield


app = FastAPI(title="KiroGate Prototype", lifespan=lifespan)
