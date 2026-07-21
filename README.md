# Agent Policy Gateway

Deterministic policy enforcement gateway that sits between AI agents and target systems (databases, APIs, cloud services). Every action an agent attempts is evaluated against an immutable JSON allowlist — permitted or denied in under 1ms. No LLM in the enforcement path.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      AI Agents (Any LLM)                         │
│   GPT-4 · Claude · Ollama · Gemini · Custom                     │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                ┌──────────▼──────────┐
                │   Agent Policy      │
                │   Gateway           │  ← Deterministic policy enforcement
                │                     │
                │  Auth → Schema →    │
                │  Policy → Egress →  │     policy.json (immutable)
                │  Quota → Mint(opt)→ │
                │  Execute → Filter → │
                │  Audit              │
                └──────────┬──────────┘
                           │
                ┌──────────▼──────────┐
                │   Target Systems    │
                │  DB · APIs · Cloud  │
                └─────────────────────┘
```

### Enforcement Pipeline

Every request passes through a fixed-order pipeline. If any stage fails, the request is denied and the pipeline halts.

```
authenticate → schema validate → policy evaluate → egress control →
quota check → credential mint → execute action → filter response → audit
```

1. **Authentication** — Bearer token verified via HMAC constant-time comparison
2. **Schema validation** — JSON-RPC 2.0 envelope structure check (tools themselves are validated by policy, not a fixed registry)
3. **Policy evaluation** — tool allowed? operation permitted? keywords blocked?
4. **Egress control** — destination in allowlist? not in deny list?
5. **Quota check** — within per-session rate limits?
6. **Credential mint** — optional: `credential_broker: none` (default) or `aws_sts` for short-lived per-action AWS credentials (15min TTL)
7. **Execute** — action forwarded to the real target (per-tool `target_url` or `APG_TARGET_URL`); fails closed if no target is configured
8. **Response filter** — redact secrets/PII (SSN, AWS keys, JWTs, private keys)
9. **Credential discard** — memory zeroed immediately (when a broker minted credentials)
10. **Audit** — append-only structured log with correlation ID

The pipeline is a single implementation (`core/pipeline.py`) with injected
ports for execution, credential brokering, and audit. The `/rpc` endpoint,
the CLI proxy, and the live demo all run through it — there is no second
enforcement engine (see `docs/adr/002-deterministic-policy-scope.md`).

### Zero Trust Principles

- **Default deny** — nothing is allowed unless explicitly in the policy; unknown tools are denied by policy, not by a hardcoded method list
- **Least privilege** — with `aws_sts`, credentials are scoped to exactly one action
- **No standing access** — minted credentials live for milliseconds, not minutes
- **Assume breach** — agents hold zero secrets; compromised agent = zero escalation
- **Full audit** — every decision logged with correlation IDs

---

## Services

A modular monolith (see `docs/adr/001-modular-monolith.md`): one backend
process serves the gateway, auth, and demo APIs.

| Service | Port | Responsibility |
|---------|------|----------------|
| **Frontend** (Next.js) | 3000 | Dashboard UI — login, pipeline visualization, demos |
| **Backend** (FastAPI) | 8000 | Policy enforcement, STS mint, egress control, audit, JWT auth, demo scenarios |
| **PostgreSQL** | 5432 | Audit logs, user accounts |
| **Floci** (AWS emulator) | 4566 | STS credential minting (dev); real AWS in prod |

```
┌────────────────────────────────────────────┐
│               Docker Compose                │
│                                             │
│  ┌──────────┐        ┌──────────────────┐  │
│  │ Frontend │───────▶│     Backend      │  │
│  │  :3000   │        │      :8000       │  │
│  └──────────┘        └───┬──────────┬───┘  │
│                          │          │      │
│                  ┌───────▼────┐ ┌───▼───┐  │
│                  │ PostgreSQL │ │ Floci │  │
│                  │   :5432    │ │ :4566 │  │
│                  └────────────┘ └───────┘  │
└────────────────────────────────────────────┘
```

---

## Quick Start

### Docker (one command)

```bash
docker compose up --build
```

Open http://localhost:3000 — login with `admin@apg.dev` / `apg-demo` / workspace `apg`.

### Without Docker

```bash
# Backend
export APG_AGENT_TOKEN="test-token"
python -m uvicorn agent_policy_gateway.main:app --port 8000 --reload

# Frontend
cd frontend && npm install && npm run dev
```

### CLI (standalone proxy)

```bash
pip install -e .
apg proxy --target http://localhost:9000 --policy policy.json --token my-secret
```

Point your MCP client at the gateway instead of the target server. Every
request must carry `Authorization: Bearer my-secret`; allowed calls are
forwarded to the target, denied calls are blocked before it. No database,
no AWS, no frontend required.

Validate a policy before shipping it:

```bash
apg policy validate policy.json
```

---

## Policy

The policy is a JSON allowlist loaded at startup. Maps directly to MCP `tools/call` requests:

```json
{
  "version": 1,
  "default": "deny",
  "credential_broker": "none",
  "tools": {
    "db.query": {
      "allow": true,
      "operations": ["select"],
      "tables": ["customers", "orders"],
      "deny_keywords": ["DROP", "DELETE", "UPDATE", "INSERT"],
      "target_url": "http://localhost:9000/rpc"
    },
    "http.post": {
      "allow": true,
      "destination_whitelist": ["https://api.example.com"],
      "deny_destinations": ["169.254.169.254"]
    }
  }
}
```

- `credential_broker`: `none` (default, zero external deps) or `aws_sts` to mint
  per-request scoped credentials. With `aws_sts`, add `aws_role` and
  `session_policy` per tool.
- `target_url`: per-tool execution target; falls back to the `APG_TARGET_URL`
  environment variable. If neither is set, an allowed request fails closed
  rather than returning fabricated data.

---

## Operating Modes

| Mode | Behavior |
|------|----------|
| **Enforce** (default) | Denied requests are blocked. No execution. |
| **Audit** | Denied requests are logged but still executed. Use for gradual rollout. |

Set via `APG_MODE=enforce` or `APG_MODE=audit`.

---

## Performance

The **enforcement decision** (auth + policy + egress) is in-process and
sub-millisecond:

| Operation | Latency |
|---|---|
| Token verification (HMAC-SHA256) | ~0.02ms |
| Policy evaluation (ALLOW) | ~0.01ms |
| Policy evaluation (DENY) | ~0.003ms |

End-to-end request latency is dominated by the two things the decision does
*not* control: the network hop to the target (the Execute step) and, if
`credential_broker: aws_sts` is enabled, the STS `AssumeRole` call
(typically 50–200ms). Benchmark your own target; the enforcement overhead
APG adds on top is the numbers above.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `APG_AGENT_TOKEN` | Bearer token for agent authentication |
| `APG_TARGET_URL` | Default execution target for allowed requests (per-tool `target_url` overrides) |
| `APG_MODE` | `enforce` or `audit` |
| `AWS_ENDPOINT_URL` | STS endpoint (e.g. Floci/LocalStack); unset → real AWS. Only used with `credential_broker: aws_sts` |
| `APG_JWT_SECRET` | Secret for signing operator JWTs |
| `APG_OPERATOR_EMAIL` | Operator login email |
| `APG_OPERATOR_PASSWORD` | Operator login password |
| `APG_OPERATOR_WORKSPACE` | Workspace identifier |
| `LLM_PROVIDER` | `mock`, `ollama`, `openai`, `anthropic`, `microservice` |
| `DATABASE_URL` | PostgreSQL connection string |

---

## Deploy to Kubernetes

> **Note:** the `k8s/` manifests still describe the pre-consolidation
> multi-service layout and assume in-memory session state. They are
> quarantined pending the Phase 3 update (single backend image +
> Redis-backed sessions so multi-replica is correct). See `k8s/README.md`.
> For now, use `docker compose up --build`.

Once updated, with `credential_broker: aws_sts`, remove `AWS_ENDPOINT_URL`
from the backend env to use real AWS STS instead of a local emulator.

---

## Project Structure

```
Agent-Policy-Gateway/
├── Makefile                        # dev / test / lint / check / run
├── docker-compose.yml              # docker compose up --build
├── policy.json                     # immutable policy (source of truth)
├── pyproject.toml                  # Python package config
│
├── services/                       # Docker build contexts
│   ├── backend/Dockerfile          # single backend image (main:app)
│   ├── frontend/Dockerfile
│   └── postgres/init.sql
│
├── k8s/                            # Kubernetes manifests (stale — see k8s/README.md)
│
├── docs/adr/                       # Architecture decision records
│
├── frontend/                       # Next.js 14 dashboard
│   └── src/
│       ├── app/                    # Pages (login, dashboard, demos, audit)
│       ├── components/             # Sidebar, shared UI
│       └── lib/                    # API client, auth helpers
│
├── src/agent_policy_gateway/       # Python source (modular monolith, ADR-001)
│   ├── core/                       # pure domain — no infrastructure imports
│   │   ├── policy.py               # deterministic policy evaluator (the one engine)
│   │   ├── egress.py               # egress control
│   │   ├── filter.py               # response PII redaction
│   │   ├── session.py              # quota management
│   │   ├── mode.py                 # enforce/audit mode control
│   │   ├── models.py               # frozen Pydantic policy models
│   │   └── schemas.py              # JSON-RPC envelope validation
│   ├── adapters/                   # replaceable infrastructure
│   │   ├── brokers/aws_sts.py      # STS credential minting
│   │   ├── identity/shared_token.py# agent caller auth
│   │   └── audit/stdout.py         # structured audit sink
│   ├── server/app.py               # FastAPI wiring (all routers + /rpc)
│   ├── main.py                     # uvicorn entry point shim
│   ├── cli.py                      # apg CLI (proxy / demo / init / policy validate)
│   ├── proxy_app.py                # standalone transparent proxy
│   ├── auth_service/               # operator JWT + pluggable providers
│   ├── dashboard_api/              # REST API for frontend
│   └── live_demo/                  # LLM providers + demo scenarios
│
└── tests/                          # pytest test suite
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Gateway | Python 3.13 + FastAPI |
| Frontend | Next.js 14 + Tailwind CSS |
| Database | PostgreSQL 16 |
| Credential Minting | Optional: AWS STS (per-request, downscoped) or none |
| Local AWS | Floci (dev); real AWS (prod) |
| LLM Integration | Ollama / OpenAI / Anthropic (pluggable) |
| Orchestration | Docker Compose |
| Tests | pytest (236) · ruff · mypy · CI on 3.11–3.13 |

---

## License

MIT
