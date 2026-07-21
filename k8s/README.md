# Kubernetes manifests — status

**These manifests are stale and pending the Phase 3 update.** They still
describe the old four-service split (gateway/auth/frontend), and the
gateway's session/quota state is currently in-memory, so running more
than one replica silently breaks quota enforcement.

Do not deploy these until:

1. The deployments are updated to the single `backend` image
   (`services/backend/Dockerfile`, entry `agent_policy_gateway.main:app`).
2. Session/quota state is backed by Redis (Phase 3), making multi-replica
   deployment correct.

For now, use `docker compose up --build` (see repo README).
