# Threat Model (STRIDE)

**Subject:** the Agent Policy Gateway itself — the component that sits between AI
agents and the systems they act on. This document applies STRIDE to the gateway,
states the mitigations that are actually implemented (with pointers), and is
explicit about residual risk and deployment assumptions. It is a living document;
see the [compliance mapping](./compliance-mapping.md) for how these controls map
to frameworks.

---

## 1. System & trust boundaries

```
                         ┌────────────────────────── Agent Policy Gateway ──────────────────────────┐
   ┌────────┐   B1 tls   │  auth → policy → egress → (quota) → (mint) → execute → filter → audit     │  B2 tls   ┌──────────┐
   │ AI     │──────────► │  identity   engine    egress-ctl   session    STS      forward   redact   │──────────►│ target   │
   │ agent  │  bearer    │  (per-agent token / OIDC-later)                                            │  (token   │ MCP/API  │
   └────────┘            └───────────┬───────────────────────────────────────────────┬──────────────┘  stripped)└──────────┘
                                     │ B4 policy.json (git, read-only at load)         │ B5 audit sink (append-only: JSONL/SQLite/SIEM)
   ┌────────┐   B3 tls   ┌───────────┴───────────┐                                     │
   │operator│──────────► │ dashboard / auth API  │                                     ▼
   └────────┘  JWT       │ (argon2 + PyJWT)      │                              B6 credential broker (STS, opt-in)
                         └───────────────────────┘
```

**Trust boundaries**

| # | Boundary | Notes |
|---|----------|-------|
| B1 | Agent → Gateway | Untrusted caller. Per-agent bearer token; TLS expected in front. |
| B2 | Gateway → Target | Gateway is the *only* sanctioned path to the target (critical assumption A1). |
| B3 | Operator → Dashboard/API | Human operators; JWT session, argon2 password. |
| B4 | Policy file → Gateway | Config as code; trusted, loaded read-only, fail-closed. |
| B5 | Gateway → Audit sink | Append-only; ideally shipped off-box. |
| B6 | Gateway → Credential broker | Opt-in STS; short-lived downscoped credentials. |
| B7 | Client → `apg wrap` (stdio) | Local process spawn; trust boundary is the OS, not a token. |

**Assets:** the target systems (databases/APIs) and their data; the policy; the
audit trail; operator and agent credentials; minted cloud credentials.

---

## 2. STRIDE analysis

### S — Spoofing (identity)

| Threat | Mitigation (implemented) | Residual |
|--------|--------------------------|----------|
| An unauthorized caller impersonates an agent | Per-agent bearer tokens, constant-time comparison; unknown token → 401 (`adapters/identity/`, `proxy_app.py`) | Bearer tokens are secrets — theft/replay is possible without TLS + rotation (assumption A2). |
| One agent impersonates another | Each agent has its own token → its own `agent_id` and tool scope; audit attributes every call | Shared or leaked tokens defeat this — rotate per agent. |
| Operator impersonation | argon2-verified password + signed JWT session; **no default credentials** (`auth_service/`) | Phishing/credential theft — out of scope; use SSO (OIDC adapter planned). |
| Gateway connects to a spoofed target | Target URL is operator-controlled config | TLS/cert validation to the target is a deployment concern (A2). |

### T — Tampering (integrity)

| Threat | Mitigation | Residual |
|--------|------------|----------|
| Policy is altered to weaken enforcement | Policy is code in git (reviewed diffs); loaded read-only and frozen at startup; `default: deny` enforced; invalid policy aborts startup (`core/policy.py`) | Whoever can write the policy file or its env controls enforcement — protect the deploy (A3). |
| Request/response tampered in transit | Expect TLS termination in front (A2) | Not enforced by APG itself. |
| Audit records altered/deleted | Append-only sinks; **no update/delete code path** (`adapters/audit/`) | Filesystem/DB access outside APG can still alter logs → ship off-box to a SIEM (roadmap). |
| **Agent bypasses the gateway and calls the target directly** | — | **Primary assumption A1:** the network must make the gateway the only path to the target. If not, policy is moot. Enforce with network policy / firewall / private networking. |

### R — Repudiation

| Threat | Mitigation | Residual |
|--------|------------|----------|
| A caller denies performing an action | One structured audit event per request: correlation id, `agent_id`, tool, decision, rule matched, latency (`core/audit_sink.py`) | Audit writes are **best-effort** (I/O errors are swallowed so audit never breaks the request path) — a full disk could drop a line. Use a durable sink and monitor it. |

### I — Information disclosure

| Threat | Mitigation | Residual |
|--------|------------|----------|
| Agent exfiltrates data to an attacker destination | Default-deny egress with allowlists; SSRF guards deny link-local / cloud-metadata (`core/egress.py`) | Only structured destinations are checked; a permitted destination can still receive data. |
| Secrets leak in responses or logs | Response redaction of secret patterns; audit logs a compact attempt summary (op/table/destination), not full payloads (`core/audit.py`, `adapters/audit/jsonl.py`) | Regex redaction is a speed bump, **not full DLP** (see ADR-002) — pair with a content/DLP scanner. |
| Credentials at rest | Passwords argon2-hashed; tokens in env, not in the policy; STS = no standing secrets in the agent (`auth_service/`, `adapters/brokers/`) | At-rest encryption of the audit DB is a deployment concern. |

### D — Denial of service / availability

| Threat | Mitigation | Residual |
|--------|------------|----------|
| A caller exhausts a backend via volume | Per-session quotas, shared across replicas via Redis so limits count once (`adapters/state/`) | Quota is check-then-act, so replicas racing at the exact limit can overshoot slightly (soft limit). No general rate-limiter beyond quotas — front with a gateway/WAF. |
| Slow/hung target ties up the gateway | httpx client timeout on the forward call | Tune per deployment. |
| Malicious input burns CPU (SQL parse) | Parsing is bounded; unparseable SQL fails closed (`core/sql.py`) | — |
| Audit sink failure stalls requests | Audit writes never raise into the request path (availability chosen over audit completeness — a deliberate trade-off) | Monitor sink health. |

### E — Elevation of privilege

| Threat | Mitigation | Residual |
|--------|------------|----------|
| Agent performs an action it isn't allowed to | Default-deny engine; per-tool operation/table/egress allowlists; per-agent tool scope; structured SQL (multi-statement injection is caught) (`core/policy.py`, `core/sql.py`, `core/identity.py`) | Correct policy authoring is the operator's responsibility; `apg policy test` guards it in CI. |
| Prompt injection coerces a disallowed action | The enforcement point is **deterministic** — a JSON allowlist cannot be sweet-talked; the model being fooled does not change the decision | Injection can still influence *allowed* actions within policy. |
| Compromised agent uses standing cloud credentials | Opt-in STS mints short-lived, downscoped credentials per action; agent holds none | Only when the STS broker is configured; otherwise execution credentials are the operator's responsibility. |
| Operator privilege escalation | Single operator role, JWT-scoped | No fine-grained operator RBAC yet (roadmap). |

---

## 3. Assumptions (must hold for the model to be valid)

- **A1 — Sole path:** the network is configured so the gateway is the only route
  to the protected target. Direct agent→target access bypasses all enforcement.
- **A2 — Transport security:** TLS terminates in front of the gateway; bearer
  tokens and JWTs are transported and stored securely, and rotated.
- **A3 — Config integrity:** the policy file and secret env vars are protected by
  the deployment; write access to them equals control of enforcement.
- **A4 — Durable audit:** audit sinks live on durable, monitored storage and are
  shipped off-box where tamper-evidence is required.

---

## 4. Residual risks & non-goals

Explicitly **out of scope** (see [ADR-002](./adr/002-deterministic-policy-scope.md)):
content classification / DLP beyond patterns, prompt-injection *detection*, model
assurance/red-teaming, fine-grained operator RBAC, and general rate limiting.
APG is the deterministic **action-enforcement** layer; pair it with content-centric
tooling and standard network/transport controls for defense in depth.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
