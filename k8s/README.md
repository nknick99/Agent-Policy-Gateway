# Kubernetes manifests

These manifests deploy the **modular monolith** (one `backend` image serving the
gateway + auth + agent APIs), an optional Next.js `frontend`, and a `redis` used
for shared session/quota state. Because quota counters live in Redis
(`APG_REDIS_URL`), running multiple `backend` replicas is **correct** — the
per-replica in-memory state bug (D7) is gone.

## Contents

| File | What |
|------|------|
| `namespace.yaml` | The `agent-policy-gateway` namespace |
| `secrets.yaml` | `apg-secrets` — agent token, JWT secret, argon2 operator hash, DB URL (**replace all values**) |
| `redis.yaml` | Redis Deployment + Service (shared session/quota state) |
| `backend-deployment.yaml` | The monolith Deployment + Service + HPA (2–20 replicas) |
| `frontend-deployment.yaml` | Dashboard Deployment + Service |
| `ingress.yaml` | nginx Ingress: `/api` → backend, `/` → frontend (TLS via cert-manager) |

## Deploy

```bash
# 1. Build & push the backend image referenced by backend-deployment.yaml
#    (image: apg/backend:latest — from services/backend/Dockerfile)
# 2. Set real secrets first:
apg hash-password                 # -> paste into APG_OPERATOR_PASSWORD_HASH
$EDITOR k8s/secrets.yaml          # replace every CHANGE-ME value

kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/backend-deployment.yaml
kubectl apply -f k8s/frontend-deployment.yaml   # optional dashboard
kubectl apply -f k8s/ingress.yaml               # edit the host first
```

## Notes

- **Redis** here is a single, non-persistent replica — session/quota is soft
  state. For production prefer a managed Redis or a StatefulSet with persistence.
- **Postgres** is referenced via `DATABASE_URL` (managed DB expected); it is not
  provisioned by these manifests.
- **STS**: the credential broker defaults to `none`. For `aws_sts`, add the AWS
  env/IRSA to `backend-deployment.yaml`.
- For a zero-infrastructure local run, use `docker compose up --build` instead.
