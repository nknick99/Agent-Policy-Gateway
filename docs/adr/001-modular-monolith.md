# ADR-001: Modular monolith, not microservices

**Status:** Accepted — 2026-07-20

## Context

The project previously shipped as four separately deployed services
(frontend, auth, gateway, agent) with individual Dockerfiles, ports,
health checks, and Kubernetes deployments. The services shared one
Python package and barely communicated with each other; the split
added orchestration cost without buying isolation, independent
scaling, or independent releases. Meanwhile the actual seams that
matter — policy evaluation vs. infrastructure — were not enforced
anywhere in the code layout.

## Decision

One deployable Python service, with module boundaries enforced by
package layout instead of network boundaries:

```
src/agent_policy_gateway/
├── core/        # pure domain: policy engine, models, schemas,
│                # session, mode, filter, egress. No infrastructure
│                # imports (no boto3, no structlog, no FastAPI).
├── adapters/    # replaceable infrastructure behind small surfaces:
│   ├── brokers/    # credential minting (aws_sts today)
│   ├── identity/   # caller authentication (shared_token today)
│   └── audit/      # audit sinks (structlog stdout today)
├── server/      # FastAPI wiring only
├── proxy_app.py # standalone CLI proxy (uses core, no server deps)
└── cli.py       # apg entry point
```

The Next.js frontend remains a separate app (different runtime,
different deploy cadence — a real boundary).

## Consequences

- `docker compose up` runs one backend container instead of three.
- Adding a capability (new audit sink, new credential broker, stdio
  transport) means adding an adapter module, not a service.
- The rule for future contributors: **core never imports adapters or
  server.** Violations are architecture regressions even if tests pass.
- We split a service out only when something forces it: independent
  scaling under measured load, a different security boundary, or a
  different language/runtime. Résumé-driven architecture is explicitly
  rejected.
- The k8s manifests describing the old split are stale and quarantined
  behind k8s/README.md until the Phase 3 update (Redis-backed state
  makes multi-replica correct first).
