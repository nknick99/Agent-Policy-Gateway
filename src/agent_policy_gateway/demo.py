"""Agent Policy Gateway Demo Web UI.

A simple HTML dashboard that lets you interact with the Agent Policy Gateway proxy
visually — send requests, see pipeline decisions, and explore the policy.

Run with:
    python -m uvicorn agent_policy_gateway.demo:app --host 127.0.0.1 --port 8080 --app-dir src

Requires APG_AGENT_TOKEN to be set in environment.
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

from agent_policy_gateway.audit import AuditEvent, AuditLogger, redact_params
from agent_policy_gateway.auth import authenticate_caller, validate_startup
from agent_policy_gateway.egress import EgressController
from agent_policy_gateway.filter import filter_response
from agent_policy_gateway.mode import ModeController
from agent_policy_gateway.models import AuditDecision, Decision
from agent_policy_gateway.policy import PolicyEvaluator
from agent_policy_gateway.schemas import (
    SchemaValidationError,
    validate_envelope,
    validate_params,
)
from agent_policy_gateway.session import SessionManager
from agent_policy_gateway.sts_broker import CredentialMintError, StsBroker

logger = logging.getLogger(__name__)

# Module-level singletons
audit_logger: AuditLogger
policy_evaluator: PolicyEvaluator
session_manager: SessionManager
sts_broker: StsBroker
mode_controller: ModeController

# Store recent audit events for the demo UI
_recent_events: list[dict] = []
_MAX_EVENTS = 50


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


app = FastAPI(title="Agent Policy Gateway Demo", lifespan=lifespan)


# --- Demo HTML UI ---

DEMO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Agent Policy Gateway — Policy Gateway Demo</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1419; color: #e7e9ea; min-height: 100vh; }
.container { max-width: 1200px; margin: 0 auto; padding: 24px; }
h1 { font-size: 28px; margin-bottom: 8px; color: #fff; }
.subtitle { color: #71767b; margin-bottom: 24px; font-size: 14px; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
@media (max-width: 800px) { .grid { grid-template-columns: 1fr; } }
.card { background: #16202a; border: 1px solid #2f3336; border-radius: 12px; padding: 20px; }
.card h2 { font-size: 16px; color: #1d9bf0; margin-bottom: 12px; }
.card h3 { font-size: 14px; color: #71767b; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
label { display: block; font-size: 13px; color: #71767b; margin-bottom: 4px; margin-top: 12px; }
input, select, textarea { width: 100%; padding: 10px 12px; background: #0f1419; border: 1px solid #2f3336; border-radius: 8px; color: #e7e9ea; font-family: 'JetBrains Mono', monospace; font-size: 13px; }
textarea { resize: vertical; min-height: 120px; }
select { cursor: pointer; }
button { margin-top: 16px; padding: 10px 20px; background: #1d9bf0; color: #fff; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; width: 100%; }
button:hover { background: #1a8cd8; }
button:active { transform: scale(0.98); }
.response-box { margin-top: 16px; padding: 12px; background: #0f1419; border: 1px solid #2f3336; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; min-height: 60px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; margin-right: 6px; }
.badge-allow { background: #0d4429; color: #3fb950; }
.badge-deny { background: #4a1c1c; color: #f85149; }
.badge-error { background: #3d2e00; color: #d29922; }
.pipeline-step { display: flex; align-items: center; padding: 6px 0; border-bottom: 1px solid #2f3336; font-size: 13px; }
.pipeline-step:last-child { border-bottom: none; }
.step-num { width: 24px; height: 24px; border-radius: 50%; background: #2f3336; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 600; margin-right: 10px; flex-shrink: 0; }
.step-active { background: #1d9bf0; }
.step-pass { background: #0d4429; color: #3fb950; }
.step-fail { background: #4a1c1c; color: #f85149; }
.presets { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
.preset-btn { padding: 4px 10px; background: #2f3336; border: none; border-radius: 6px; color: #e7e9ea; font-size: 12px; cursor: pointer; }
.preset-btn:hover { background: #3f4346; }
.preset-btn.active { background: #1d9bf0; }
.event-row { padding: 8px 0; border-bottom: 1px solid #2f3336; font-size: 12px; }
.event-row:last-child { border-bottom: none; }
.mode-indicator { padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }
.mode-enforce { background: #4a1c1c; color: #f85149; }
.mode-audit { background: #3d2e00; color: #d29922; }
.header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; }
.stats { display: flex; gap: 16px; margin-top: 16px; }
.stat { text-align: center; }
.stat-value { font-size: 24px; font-weight: 700; color: #fff; }
.stat-label { font-size: 11px; color: #71767b; text-transform: uppercase; }
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>🛡️ Agent Policy Gateway Policy Gateway</h1>
            <div class="subtitle">Deterministic enforcement pipeline for AI agent tool calls</div>
        </div>
        <div>
            <span class="mode-indicator" id="modeIndicator">ENFORCE</span>
        </div>
    </div>

    <div class="grid">
        <!-- Left: Request Builder -->
        <div>
            <div class="card">
                <h2>Request Builder</h2>
                <h3>Presets</h3>
                <div class="presets">
                    <button class="preset-btn active" onclick="loadPreset('valid')">✓ Valid Query</button>
                    <button class="preset-btn" onclick="loadPreset('denied_op')">✗ Denied Operation</button>
                    <button class="preset-btn" onclick="loadPreset('unknown_tool')">✗ Unknown Tool</button>
                    <button class="preset-btn" onclick="loadPreset('deny_keyword')">✗ Deny Keyword</button>
                    <button class="preset-btn" onclick="loadPreset('bad_auth')">✗ Bad Auth</button>
                    <button class="preset-btn" onclick="loadPreset('egress_ssrf')">✗ SSRF Attempt</button>
                    <button class="preset-btn" onclick="loadPreset('invalid_json')">✗ Invalid JSON</button>
                    <button class="preset-btn" onclick="loadPreset('constraint')">✗ Constraint Violation</button>
                </div>

                <label for="token">Bearer Token</label>
                <input type="text" id="token" value="" placeholder="Enter APG_AGENT_TOKEN value">

                <label for="payload">JSON-RPC 2.0 Payload</label>
                <textarea id="payload"></textarea>

                <button onclick="sendRequest()">Send Request →</button>
            </div>

            <div class="card" style="margin-top: 20px;">
                <h2>Pipeline Trace</h2>
                <div id="pipelineTrace">
                    <div class="pipeline-step"><span class="step-num">1</span> Authenticate caller</div>
                    <div class="pipeline-step"><span class="step-num">2</span> Schema validation</div>
                    <div class="pipeline-step"><span class="step-num">3</span> Policy evaluation</div>
                    <div class="pipeline-step"><span class="step-num">4</span> Egress control</div>
                    <div class="pipeline-step"><span class="step-num">5</span> Quota check</div>
                    <div class="pipeline-step"><span class="step-num">6</span> Credential mint</div>
                    <div class="pipeline-step"><span class="step-num">7</span> Execute action</div>
                    <div class="pipeline-step"><span class="step-num">8</span> Filter response</div>
                    <div class="pipeline-step"><span class="step-num">9</span> Audit</div>
                </div>
            </div>
        </div>

        <!-- Right: Response & Audit -->
        <div>
            <div class="card">
                <h2>Response</h2>
                <div id="responseBadge"></div>
                <div class="response-box" id="responseBox">Send a request to see the response here...</div>
                <div class="stats">
                    <div class="stat"><div class="stat-value" id="statAllowed">0</div><div class="stat-label">Allowed</div></div>
                    <div class="stat"><div class="stat-value" id="statDenied">0</div><div class="stat-label">Denied</div></div>
                    <div class="stat"><div class="stat-value" id="statLatency">-</div><div class="stat-label">Latency (ms)</div></div>
                </div>
            </div>

            <div class="card" style="margin-top: 20px;">
                <h2>Audit Log <span style="color:#71767b;font-size:12px;">(last 10 events)</span></h2>
                <div id="auditLog" style="max-height: 300px; overflow-y: auto;">
                    <div style="color:#71767b; font-size:13px;">No events yet...</div>
                </div>
            </div>

            <div class="card" style="margin-top: 20px;">
                <h2>Policy Summary</h2>
                <div id="policySummary" style="font-size: 13px; color: #71767b;">Loading...</div>
            </div>
        </div>
    </div>
</div>

<script>
const PRESETS = {
    valid: {
        token: '',
        payload: JSON.stringify({jsonrpc: "2.0", id: 1, method: "db.query", params: {op: "select", table: "users", limit: 10}}, null, 2)
    },
    denied_op: {
        token: '',
        payload: JSON.stringify({jsonrpc: "2.0", id: 2, method: "db.query", params: {op: "delete", table: "users"}}, null, 2)
    },
    unknown_tool: {
        token: '',
        payload: JSON.stringify({jsonrpc: "2.0", id: 3, method: "admin.destroy", params: {target: "everything"}}, null, 2)
    },
    deny_keyword: {
        token: '',
        payload: JSON.stringify({jsonrpc: "2.0", id: 4, method: "db.query", params: {op: "select", table: "users", query: "DROP TABLE users"}}, null, 2)
    },
    bad_auth: {
        token: 'wrong-token-xxx',
        payload: JSON.stringify({jsonrpc: "2.0", id: 5, method: "db.query", params: {op: "select", table: "users"}}, null, 2)
    },
    egress_ssrf: {
        token: '',
        payload: JSON.stringify({jsonrpc: "2.0", id: 6, method: "http.post", params: {op: "POST", url: "http://169.254.169.254/latest/meta-data/"}}, null, 2)
    },
    invalid_json: {
        token: '',
        payload: 'not valid json {{{'
    },
    constraint: {
        token: '',
        payload: JSON.stringify({jsonrpc: "2.0", id: 7, method: "db.query", params: {op: "select", table: "users", limit: 5, max: 999}}, null, 2)
    }
};

let allowedCount = 0;
let deniedCount = 0;

function loadPreset(name) {
    document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    const preset = PRESETS[name];
    if (preset.token) document.getElementById('token').value = preset.token;
    document.getElementById('payload').value = preset.payload;
}

// Load default preset
loadPreset('valid');

async function sendRequest() {
    const token = document.getElementById('token').value;
    const payload = document.getElementById('payload').value;

    const start = performance.now();

    try {
        const headers = {'Content-Type': 'application/json'};
        if (token) headers['Authorization'] = 'Bearer ' + token;

        const resp = await fetch('/rpc', {
            method: 'POST',
            headers: headers,
            body: payload
        });

        const elapsed = Math.round(performance.now() - start);
        const data = await resp.json();

        document.getElementById('statLatency').textContent = elapsed;

        if (data.error) {
            deniedCount++;
            document.getElementById('statDenied').textContent = deniedCount;
            document.getElementById('responseBadge').innerHTML = '<span class="badge badge-deny">DENIED</span> Code: ' + data.error.code;
            document.getElementById('responseBox').textContent = JSON.stringify(data, null, 2);
            updatePipeline(data.error.code, data.error.message);
        } else {
            allowedCount++;
            document.getElementById('statAllowed').textContent = allowedCount;
            document.getElementById('responseBadge').innerHTML = '<span class="badge badge-allow">ALLOWED</span>';
            document.getElementById('responseBox').textContent = JSON.stringify(data, null, 2);
            updatePipeline('allow', '');
        }
    } catch (e) {
        document.getElementById('responseBadge').innerHTML = '<span class="badge badge-error">ERROR</span>';
        document.getElementById('responseBox').textContent = 'Network error: ' + e.message;
    }

    // Refresh audit log
    fetchAuditLog();
}

function updatePipeline(code, message) {
    const steps = document.querySelectorAll('#pipelineTrace .pipeline-step');
    let failStep = -1;

    if (code === 'allow') {
        failStep = 99; // all pass
    } else if (code === -32700) {
        failStep = 0; // parse error before auth
    } else if (message && message.toLowerCase().includes('authentication')) {
        failStep = 0;
    } else if (code === -32600 && message && message.includes('Missing required field')) {
        failStep = 1;
    } else if (code === -32601) {
        failStep = 1;
    } else if (code === -32602) {
        failStep = 1;
    } else if (message && message.includes('Policy denied')) {
        failStep = 2;
    } else if (message && message.includes('Egress denied')) {
        failStep = 3;
    } else if (message && message.includes('quota')) {
        failStep = 4;
    } else if (code === -32603) {
        failStep = 5;
    } else {
        failStep = 2;
    }

    steps.forEach((step, i) => {
        const num = step.querySelector('.step-num');
        num.className = 'step-num';
        if (i < failStep) {
            num.classList.add('step-pass');
            num.textContent = '✓';
        } else if (i === failStep) {
            num.classList.add('step-fail');
            num.textContent = '✗';
        } else {
            num.textContent = i + 1;
        }
    });

    if (code === 'allow') {
        steps.forEach((step, i) => {
            const num = step.querySelector('.step-num');
            num.className = 'step-num step-pass';
            num.textContent = '✓';
        });
    }
}

async function fetchAuditLog() {
    try {
        const resp = await fetch('/demo/audit-log');
        const events = await resp.json();
        const container = document.getElementById('auditLog');
        if (events.length === 0) {
            container.innerHTML = '<div style="color:#71767b; font-size:13px;">No events yet...</div>';
            return;
        }
        container.innerHTML = events.slice(0, 10).map(e => `
            <div class="event-row">
                <span class="badge ${e.decision === 'allow' ? 'badge-allow' : 'badge-deny'}">${e.decision}</span>
                <strong>${e.method || '(unknown)'}</strong>
                <span style="color:#71767b;"> — ${e.rule_matched || e.denial_reason || ''}</span>
                <br><span style="color:#71767b;font-size:11px;">${e.correlation_id} · ${Math.round(e.duration_ms)}ms</span>
            </div>
        `).join('');
    } catch(e) {}
}

async function fetchPolicy() {
    try {
        const resp = await fetch('/demo/policy-summary');
        const data = await resp.json();
        const container = document.getElementById('policySummary');
        container.innerHTML = `
            <div><strong>Default:</strong> ${data.default}</div>
            <div><strong>Mode:</strong> ${data.mode}</div>
            <div><strong>Tools:</strong></div>
            ${data.tools.map(t => `<div style="margin-left:12px;margin-top:4px;">
                <strong>${t.name}</strong> ${t.allow ? '✓' : '✗'}
                ${t.operations.length ? ' — ops: ' + t.operations.join(', ') : ''}
                ${t.tables.length ? ' — tables: ' + t.tables.join(', ') : ''}
            </div>`).join('')}
            <div style="margin-top:8px;"><strong>Session Limits:</strong> ${data.session_limits.max_calls} calls, ${data.session_limits.max_records} records</div>
        `;
        document.getElementById('modeIndicator').textContent = data.mode.toUpperCase();
        document.getElementById('modeIndicator').className = 'mode-indicator mode-' + data.mode;
    } catch(e) {}
}

fetchPolicy();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def demo_ui():
    """Serve the demo web UI."""
    return HTMLResponse(content=DEMO_HTML)


@app.get("/demo/policy-summary")
async def policy_summary():
    """Return policy summary for the demo UI."""
    policy = policy_evaluator.policy
    tools = []
    for name, config in policy.tools.items():
        tools.append({
            "name": name,
            "allow": config.allow,
            "operations": list(config.operations),
            "tables": list(config.tables),
        })
    return {
        "default": policy.default,
        "mode": mode_controller.mode.value,
        "tools": tools,
        "session_limits": {
            "max_calls": policy.session_limits.max_calls_per_session,
            "max_records": policy.session_limits.max_records_per_session,
        },
    }


@app.get("/demo/audit-log")
async def get_audit_log():
    """Return recent audit events for the demo UI."""
    return list(reversed(_recent_events[-_MAX_EVENTS:]))


# --- Helper Functions ---

def _error_response(request_id: int | str | None, code: int, message: str) -> JSONResponse:
    content: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }
    return JSONResponse(content=content, status_code=200)


def _success_response(request_id: int | str | None, result: Any) -> JSONResponse:
    content: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }
    return JSONResponse(content=content, status_code=200)


def _caller_id_from_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:16]


async def _execute_action(method: str, params: dict[str, Any], creds: Any) -> dict[str, Any]:
    """Simulated action execution for the demo."""
    if method == "db.query":
        return {
            "status": "executed",
            "method": method,
            "rows": [
                {"id": 1, "name": "Alice", "email": "alice@example.com"},
                {"id": 2, "name": "Bob", "email": "bob@example.com"},
            ],
            "row_count": 2,
        }
    return {"status": "executed", "method": method}


def _record_audit_event(event: AuditEvent):
    """Store audit event for the demo UI display."""
    _recent_events.append({
        "correlation_id": event.correlation_id,
        "method": event.method,
        "decision": event.decision.value,
        "rule_matched": event.rule_matched,
        "denial_reason": event.denial_reason,
        "duration_ms": event.duration_ms,
        "caller_identity": event.caller_identity,
    })


# --- Main RPC Endpoint (with demo-friendly STS bypass) ---

@app.post("/rpc")
async def handle_rpc(request: Request) -> JSONResponse:
    """POST /rpc — Full enforcement pipeline (demo mode skips real STS)."""
    start_time = time.monotonic()
    correlation_id = audit_logger.generate_correlation_id()
    audit_event = AuditEvent(correlation_id=correlation_id)
    request_id: int | str | None = None

    try:
        raw_body = await request.body()

        try:
            payload = json.loads(raw_body)
        except (json.JSONDecodeError, ValueError):
            audit_event.decision = AuditDecision.DENY
            audit_event.denial_reason = "Parse error: body is not valid JSON"
            return _error_response(None, -32700, "Parse error")

        if isinstance(payload, list):
            audit_event.decision = AuditDecision.DENY
            audit_event.denial_reason = "Batch requests not supported"
            return _error_response(None, -32600, "Batch requests not supported")

        if not isinstance(payload, dict):
            audit_event.decision = AuditDecision.DENY
            return _error_response(None, -32600, "Invalid request")

        request_id = payload.get("id")
        if request_id is None:
            audit_event.decision = AuditDecision.DENY
            audit_event.denial_reason = "Notifications not supported"
            return _error_response(None, -32600, "Notifications not supported")

        # Step 1: Authenticate
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()

        if not authenticate_caller(token):
            audit_event.decision = AuditDecision.DENY
            audit_event.denial_reason = "Authentication failed"
            return _error_response(request_id, -32600, "Authentication failed")

        caller_id = _caller_id_from_token(token)
        audit_event.caller_identity = caller_id

        # Step 2: Schema validation
        validate_envelope(payload)
        method = payload["method"]
        params = payload.get("params", {})
        audit_event.method = method
        audit_event.params_redacted = redact_params(params)

        # Step 3: Schema validation (params)
        validate_params(method, params)

        # Step 4: Policy evaluation
        policy_result = policy_evaluator.evaluate(method, params)

        if policy_result.decision == Decision.DENY:
            if mode_controller.should_block_policy_denial():
                audit_event.decision = AuditDecision.DENY
                audit_event.denial_reason = f"Policy denied: {policy_result.reason}"
                audit_event.rule_matched = policy_result.rule_matched
                return _error_response(request_id, -32600, f"Policy denied: {policy_result.reason}")
            else:
                audit_event.rule_matched = policy_result.rule_matched

        # Step 5: Egress control
        if policy_result.tool_config and ("url" in params or "destination" in params):
            egress = EgressController(policy_result.tool_config)
            dest = params.get("url") or params.get("destination")
            egress_result = egress.check(dest)
            if not egress_result.allowed:
                audit_event.decision = AuditDecision.DENY
                audit_event.denial_reason = f"Egress denied: {egress_result.reason}"
                return _error_response(request_id, -32600, f"Egress denied: {egress_result.reason}")

        # Step 6: Quota check
        session_limits = policy_evaluator.policy.session_limits
        if await session_manager.check_quota(caller_id, session_limits):
            audit_event.decision = AuditDecision.DENY
            audit_event.denial_reason = "Session quota exceeded"
            return _error_response(request_id, -32600, "Session quota exceeded")

        # Steps 7-8: Execute action (demo mode — skip real STS)
        raw_result = await _execute_action(method, params, None)
        filtered_result = filter_response(raw_result)

        record_count = 0
        if isinstance(raw_result, dict):
            record_count = len(raw_result.get("rows", []))
        await session_manager.record_success(caller_id, record_count=record_count)

        audit_event.decision = AuditDecision.ALLOW
        audit_event.rule_matched = policy_result.rule_matched
        audit_event.outcome = "success"
        audit_event.role_assumed = (policy_result.tool_config or {}).get("aws_role", "")

        return _success_response(request_id, filtered_result)

    except SchemaValidationError as exc:
        audit_event.decision = AuditDecision.DENY
        audit_event.denial_reason = f"Schema validation: {exc.message}"
        return _error_response(request_id, exc.code, exc.message)

    except Exception:
        logger.exception("Unhandled exception in pipeline")
        audit_event.decision = AuditDecision.DENY
        audit_event.denial_reason = "Unhandled internal error"
        return _error_response(request_id, -32603, "Internal error")

    finally:
        elapsed_ms = (time.monotonic() - start_time) * 1000
        audit_event.duration_ms = elapsed_ms
        audit_logger.emit(audit_event)
        _record_audit_event(audit_event)
