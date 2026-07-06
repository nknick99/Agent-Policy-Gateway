# Agent Policy Gateway Frontend

Next.js dashboard for the Agent Policy Gateway deterministic AI policy enforcement proxy.

## Architecture

```
┌────────────────────┐         ┌──────────────────────┐
│  Next.js Frontend  │ ──/api──▶  Backend (Python/Go) │
│  (this directory)  │         │  FastAPI or net/http  │
└────────────────────┘         └──────────────────────┘
```

The frontend talks to the backend exclusively through `/api/*` routes.
A Next.js rewrite proxies these to the `BACKEND_URL` environment variable.

**To switch from Python to Go**: just change `BACKEND_URL` and reimplement the same endpoints.

## Getting Started

```bash
cd frontend
npm install
cp .env.example .env.local   # edit BACKEND_URL if needed
npm run dev                   # http://localhost:3000
```

## Pages

| Route | Screen |
|-------|--------|
| `/` | Login |
| `/dashboard` | Home — system status, pipeline, quick actions |
| `/dashboard/request-flow` | 12-stage pipeline visualizer |
| `/dashboard/policy` | Immutable policy.json viewer |
| `/dashboard/demos` | 5 deterministic demo scenarios |
| `/dashboard/audit` | Audit log & credential lifecycle |

## Backend Contract (API endpoints)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Authenticate operator |
| `/api/status` | GET | System health & metrics |
| `/api/policy` | GET | Current policy + metadata |
| `/api/audit/events` | GET | Paginated audit events |
| `/api/demo/run/:id` | POST | Execute demo scenario |

Implement these in Python (FastAPI) today, swap to Go (net/http, chi, etc.) later.

## Tech Stack

- **Next.js 14** — App Router
- **TypeScript** — strict mode
- **Tailwind CSS** — dark theme with custom Agent Policy Gateway palette
- **Lucide React** — icons
