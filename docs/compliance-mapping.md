# Compliance Control Mapping

**Scope:** how Agent Policy Gateway (APG) controls map to common AI‑governance
and security frameworks. APG is the *action‑enforcement layer* for AI agents —
it deterministically controls which tool calls an agent may perform, records an
auditable trail of every decision, and keeps agents from holding standing
secrets. This document maps those controls to control families so they can be
cited in a security review, a risk assessment, or an audit.

> **This is a control‑mapping aid, not a certification or legal advice.** APG is
> a component; meeting a regulation or passing an audit is the responsibility of
> the organization deploying it, in the context of their full system. The
> mappings below describe how APG *supports* each control, and are honest about
> where APG does not apply (see [Scope boundaries](#scope-boundaries)).

---

## 1. Control inventory

Every mapping below traces to a control that is actually implemented and tested
in this repository.

| # | Control | What it does | Where |
|---|---------|--------------|-------|
| C1 | **Default‑deny action policy** | No tool call is allowed unless the policy explicitly permits it. `default: deny` is enforced at load time (a non‑deny default is rejected). | `policy.json`, `core/policy.py` |
| C2 | **Deterministic policy engine** | Same input → same decision, no model in the enforcement path. Every denial cites the exact rule matched. | `core/policy.py`, `core/enforcement.py` |
| C3 | **Operation & resource allowlists** | Per‑tool allowlists for operations and resources (e.g. SQL operations, tables). | `core/policy.py`, `policy.json` |
| C4 | **Structured SQL enforcement** | SQL is parsed (not string‑matched); operation/table are enforced against the parsed statement. Multi‑statement injection is caught; unparseable SQL fails closed. | `core/sql.py` |
| C5 | **Egress control** | Destination allowlists with SSRF guards (link‑local / cloud‑metadata denial); default‑deny for destinations. | `core/egress.py` |
| C6 | **Per‑agent identity & least privilege** | Each agent authenticates with its own token and is scoped to a subset of tools; per‑request credential minting (opt‑in STS) issues short‑lived, downscoped credentials so agents hold no standing secrets. | `core/identity.py`, `adapters/identity/`, `adapters/brokers/aws_sts.py` |
| C7 | **Durable, append‑only audit trail** | One event per request with correlation id, resolved `agent_id`, decision, rule matched, latency, and attempt detail. JSONL or SQLite; no update/delete path. Queryable via `apg audit tail`. | `core/audit_sink.py`, `adapters/audit/` |
| C8 | **Policy‑as‑code & change control** | The policy is a versioned JSON file reviewed in pull requests; `apg policy validate` and `apg policy test` (allow/deny assertions) gate changes in CI. | `policy.json`, `policy.test.yaml`, `cli.py` |
| C9 | **Enforce / audit modes & learning** | Run in `audit` mode to observe without blocking, then `apg policy suggest` proposes allowlist entries from real traffic; switch to `enforce` to block. | `adapters/transports/`, `core/learning.py` |
| C10 | **Authentication hygiene** | Operator auth via PyJWT (HS256, validated expiry) and argon2 password hashing; constant‑time token comparison; no built‑in default credentials. | `auth_service/tokens.py`, `auth_service/provider.py`, `adapters/identity/shared_token.py` |
| C11 | **Fail‑closed & shared quotas** | Missing/invalid policy at startup aborts; unparseable input is denied; session/quota counters can be shared across replicas (Redis) so limits are enforced once, not per‑replica. | `core/policy.py`, `adapters/state/` |

---

## 2. NIST AI Risk Management Framework (AI RMF 1.0)

APG primarily supports the **MANAGE** and **MEASURE** functions — the runtime
controls and monitoring around a deployed agent.

| AI RMF function / category | How APG supports it | Controls |
|---|---|---|
| **GOVERN 1.2 / 4.1** — policies, accountability, documented risk practices | Agent permissions are policy‑as‑code: versioned, peer‑reviewed, and testable, giving a documented, auditable record of what agents are allowed to do. | C1, C8 |
| **MEASURE 2.7** — security and resilience | Deterministic enforcement can't be prompt‑injected; egress/SSRF guards, structured SQL parsing, and fail‑closed defaults harden the action surface. | C2, C4, C5, C11 |
| **MEASURE 2.8** — transparency & accountability mechanisms | Every action decision is logged with the rule matched and the agent identity, providing an accountability record per request. | C7 |
| **MANAGE 2.2 / 2.3** — mechanisms to sustain value, override, and treat risk | Default‑deny with human‑authored allowlists; enforce/audit modes provide a controlled rollout and an override point. | C1, C9 |
| **MANAGE 4.1** — post‑deployment monitoring | Durable audit + `apg audit tail` + learning mode turn observed traffic into monitoring and policy refinement. | C7, C9 |

---

## 3. NIST SP 800‑53 Rev. 5 (control families)

800‑53 gives the most concrete, testable mapping (and underpins SOC 2 and
FedRAMP).

| 800‑53 control | Title | How APG supports it | Controls |
|---|---|---|---|
| **AC‑3** | Access Enforcement | The policy engine enforces default‑deny on every tool call. | C1, C2, C3 |
| **AC‑4** | Information Flow Enforcement | Egress allowlists constrain where actions may send data; SSRF/metadata destinations are denied. | C5 |
| **AC‑6** | Least Privilege | Per‑agent tool scope + per‑tool operation limits + short‑lived downscoped credentials. | C6 |
| **IA‑2 / IA‑5** | Identification & Authentication / Authenticator Management | Per‑agent bearer identities; argon2‑hashed operator passwords; PyJWT sessions; constant‑time comparison; no default credentials. | C6, C10 |
| **AU‑2 / AU‑3 / AU‑12** | Event Logging / Content of Records / Audit Generation | One structured event per request (who, what tool, decision, rule, latency, correlation id). | C7 |
| **AU‑9** | Protection of Audit Information | Append‑only sinks; no update/delete API surface. | C7 |
| **SI‑10** | Information Input Validation | Structured SQL parsing and schema validation; unparseable input fails closed. | C4 |
| **CM‑3 / CM‑5** | Change Control / Access Restrictions for Change | Policy‑as‑code reviewed in PRs; `apg policy validate` + `apg policy test` gate changes in CI. | C8 |
| **SC‑5 / SC‑7** | Denial‑of‑Service / Boundary Protection | Shared session quotas (correct across replicas); the gateway is a policy boundary in front of the target. | C5, C11 |

---

## 4. EU AI Act (Regulation (EU) 2024/1689)

For deployers of high‑risk AI systems, APG provides technical controls that
support several obligations. Whether a given agent is "high‑risk" is a
determination for the deployer.

| Article | Requirement | How APG supports it | Controls |
|---|---|---|---|
| **Art. 12** — Record‑keeping (logging) | Automatic recording of events over the system's lifetime, enabling traceability. | Durable, append‑only audit trail with correlation ids and per‑agent attribution; retained in JSONL or SQLite. | C7 |
| **Art. 14** — Human oversight | Humans can understand, oversee, and intervene in the system's operation. | Agent permissions are human‑authored and code‑reviewed; every denial is explainable (exact rule cited); audit mode + learning mode support supervised rollout; enforce mode is the intervention/override boundary. | C1, C8, C9 |
| **Art. 15** — Accuracy, robustness & cybersecurity | Resilience against errors and against attempts to manipulate the system. | Deterministic enforcement is not manipulable by prompt injection; SQL parsing resists injection/obfuscation; egress guards; fail‑closed behavior. | C2, C4, C5, C11 |
| **Art. 19 / 26** — Deployer log‑keeping & oversight duties | Keep automatically generated logs; assign human oversight. | Audit sinks provide the logs to retain; policy‑as‑code + reviewers provide the oversight assignment. | C7, C8 |

---

## 5. SOC 2 — Trust Services Criteria (Common Criteria)

| Criterion | Focus | How APG supports it | Controls |
|---|---|---|---|
| **CC6.1** | Logical access — identification & authentication | Per‑agent identities; hardened operator auth (argon2, PyJWT); no default credentials. | C6, C10 |
| **CC6.3** | Least‑privilege / role‑based access | Per‑agent tool scope and per‑tool operation/resource allowlists. | C3, C6 |
| **CC6.6 / CC6.7** | Boundary protection / restricting data movement | Egress allowlists and SSRF guards constrain where actions can reach. | C5 |
| **CC7.2 / CC7.3** | Monitoring & evaluating security events | Structured per‑request audit; `apg audit tail --outcome DENY` surfaces blocked attempts. | C7, C9 |
| **CC7.4 / CC7.5** | Incident response evidence | Correlation‑id‑tagged, append‑only audit records support investigation. | C7 |
| **CC8.1** | Change management | Policy‑as‑code with validation and allow/deny tests in CI; changes reviewed as diffs. | C8 |

---

## 6. Producing evidence

For each control, the evidence an assessor typically asks for:

- **Policy in force / change history** — `policy.json` in version control with its
  git history; PR reviews of policy diffs; `apg policy validate` output.
- **Control effectiveness tests** — `policy.test.yaml` run by `apg policy test`
  in CI (allow/deny assertions, incl. injection/SSRF cases), plus the
  repository's automated test suite.
- **Operational logs** — the audit trail (`apg-audit.jsonl` or the SQLite store);
  `apg audit tail --outcome DENY` for a denials report; each record carries a
  correlation id, agent id, rule matched, and latency.
- **Least‑privilege configuration** — the `agents` map (per‑agent tool scope) and
  per‑tool `operations`/`tables`/`destination_whitelist`; STS `session_policy`
  for downscoped credentials when enabled.
- **Authentication hardening** — argon2 `APG_OPERATOR_PASSWORD_HASH`
  (via `apg hash-password`), PyJWT settings, and the absence of default
  credentials in images.

---

## Scope boundaries

APG is deliberately an **action‑layer, deterministic** control. It is *not* a
substitute for these, and does not claim their controls (see
[ADR‑002](./adr/002-deterministic-policy-scope.md)):

- **Content classification / DLP** — toxicity, PII detection beyond simple
  patterns, data‑classification. Pair APG with a content‑safety/DLP service.
- **Prompt‑injection *detection*** — APG makes injection *ineffective at the
  action layer* (the policy can't be talked out of a decision), but it does not
  score or flag prompts as malicious.
- **Model assurance** — model scanning, red‑teaming, evaluation, and bias/fairness
  testing are out of scope.

The honest positioning: APG guarantees *what an agent is allowed to do*, and
proves it with an audit trail — a deterministic complement to probabilistic,
content‑centric AI‑security tools.
