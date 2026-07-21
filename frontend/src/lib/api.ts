/**
 * API client for Agent Policy Gateway backend.
 *
 * All backend calls go through this module. When you switch from
 * Python/FastAPI to Go, just update BACKEND_URL — no frontend changes.
 *
 * In dev mode, Next.js rewrites /api/* to the backend.
 * In production, configure the reverse proxy accordingly.
 */

import { getToken } from "./auth";

const BASE = "/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = getToken();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      ...headers,
      ...options?.headers,
    },
  });

  if (res.status === 401 && path !== "/auth/login") {
    // Token expired or invalid — redirect to login (but not during login itself)
    if (typeof window !== "undefined") {
      window.location.href = "/";
    }
    throw new Error("Unauthorized");
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => res.statusText);
    throw new Error(`API error ${res.status}: ${detail}`);
  }

  return res.json();
}

// --- Auth ---

export interface LoginPayload {
  workspace: string;
  email: string;
  password: string;
}

export interface LoginUser {
  user_id: string;
  email: string;
  workspace: string;
  role: string;
}

export interface LoginResponse {
  token: string;
  expires_in: number;
  user: LoginUser;
}

export function login(payload: LoginPayload): Promise<LoginResponse> {
  return request("/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

// --- Status ---

export interface SystemStatus {
  gateway_health: string;
  policy_loaded: string;
  environment: string;
  recent_requests: number;
  deny_rate: number;
  quota_usage: number;
  audit_logging: string;
  uptime: number;
}

export function getSystemStatus(): Promise<SystemStatus> {
  return request("/status");
}

// --- Policy ---

export interface PolicyResponse {
  policy: Record<string, unknown>;
  hash: string;
  loaded_at: string;
}

export function getPolicy(): Promise<PolicyResponse> {
  return request("/policy");
}

// --- Audit ---

export interface AuditEvent {
  correlation_id: string;
  timestamp: string;
  outcome: "ALLOW" | "DENY";
  method: string;
  action: string;
  latency_ms: number;
  stage: string;
}

export function getAuditEvents(params?: {
  outcome?: string;
  limit?: number;
}): Promise<AuditEvent[]> {
  const query = new URLSearchParams();
  if (params?.outcome) query.set("outcome", params.outcome);
  if (params?.limit) query.set("limit", String(params.limit));
  const qs = query.toString();
  return request(`/audit/events${qs ? `?${qs}` : ""}`);
}

// --- Demo ---

export interface DemoResult {
  scenario: string;
  outcome: "ALLOWED" | "DENIED";
  failed_stage: string | null;
  reason: string | null;
  latency_ms: number;
  correlation_id: string;
}

export function runDemo(scenarioId: number): Promise<DemoResult> {
  return request(`/demo/run/${scenarioId}`, { method: "POST" });
}
