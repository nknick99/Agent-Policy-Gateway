# ADR-002: Deterministic enforcement — and what this product will not do

**Status:** Accepted — 2026-07-20

## Context

AI agent security products split into two families:

1. **Probabilistic content security** — ML classifiers that score
   prompts and responses for prompt injection, toxicity, sensitive
   data (e.g., Palo Alto Prisma AIRS).
2. **Deterministic action control** — rule-based allow/deny decisions
   over the *actions* an agent attempts (which tool, which operation,
   which table, which destination).

Trying to do both with one team produces a worse version of each.
The enforcement point for actions with side effects must not be
something an attacker can argue with: a policy engine that can be
prompt-injected is part of the attack surface, not a control. This is
the same reason IAM policies, firewall rules, and seccomp profiles
are deterministic.

## Decision

Agent Policy Gateway is a **deterministic action firewall for the
MCP/tool-call layer**. Every enforcement decision is produced by
code-based evaluation of an immutable, version-controlled JSON policy:
same input, same decision, exact rule cited, testable in CI.

There is exactly **one policy engine** (`core/policy.py` +
`core/egress.py`). Every surface — gateway `/rpc`, standalone CLI
proxy, demos — routes through it. Parallel "simplified" evaluators
are forbidden; they diverge silently and demo something other than
the product (this happened; see git history for the deleted
duplicates in proxy_app and live_demo/scenarios).

## Explicit non-goals

- **No prompt-injection classification.** We assume the model *will*
  be fooled; the policy holds anyway. That's the pitch, not a gap.
- **No ML/LLM in the enforcement path.** Latency and determinism
  guarantees both die there.
- **No toxicity/content moderation.** Point users at content-safety
  APIs; integrate, don't rebuild.
- **No model artifact scanning / red teaming.** Different product.

## Known limitations (owned honestly)

- Substring deny-keywords over free text are a speed bump, not a
  wall (`DR/**/OP`-style bypasses). Robust enforcement lives in the
  structured checks (operation, table, destination). Phase 2 replaces
  string verb-sniffing with real SQL parsing (sqlglot).
- Default-deny pushes authoring cost onto operators. Mitigation is
  learning mode: audit-mode traffic generates proposed policy entries.

## Consequences

- Marketing claims must match the mechanism: we guarantee *action*
  containment, never *content* safety.
- Complementary positioning vs. AIRS-class products (content firewall
  + action firewall), not head-to-head.
- Any feature request that requires probabilistic judgment inside the
  enforcement path is rejected or redesigned as an advisory
  (non-blocking) signal.
