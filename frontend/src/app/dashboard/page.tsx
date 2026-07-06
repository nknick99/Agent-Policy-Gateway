"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Activity,
  Clock,
  GitBranch,
  FileJson,
  Play,
  ScrollText,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { getSystemStatus, getAuditEvents, type SystemStatus, type AuditEvent } from "@/lib/api";

interface PipelineStage {
  name: string;
  pass_count: number;
  fail_count: number;
}

const quickActions = [
  { label: "Request Flow Visualizer", href: "/dashboard/request-flow", icon: GitBranch },
  { label: "Inspect Policy Rules", href: "/dashboard/policy", icon: FileJson },
  { label: "Run Live Demo Scenarios", href: "/dashboard/live-demo", icon: Play },
  { label: "Review Audit Trail", href: "/dashboard/audit", icon: ScrollText },
];

const principles = [
  { title: "Deterministic Enforcement", icon: ShieldCheck },
  { title: "Zero-Credential Agents", icon: Zap },
  { title: "Per-Request Short-Lived Tokens", icon: Clock },
  { title: "Immutable Policy", icon: FileJson },
  { title: "Append-Only Audit Trail", icon: ScrollText },
  { title: "Fail-Closed", icon: Activity },
];

export default function DashboardHome() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [pipelineStats, setPipelineStats] = useState<PipelineStage[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [s, events, pipeline] = await Promise.all([
          getSystemStatus(),
          getAuditEvents({ limit: 5 }),
          fetch("/api/pipeline/stats", {
            headers: { Authorization: `Bearer ${localStorage.getItem("apg_token") || ""}` },
          }).then((r) => (r.ok ? r.json() : [])),
        ]);
        setStatus(s);
        setAuditEvents(events);
        setPipelineStats(pipeline);
      } catch (err) {
        console.error("Failed to load dashboard data:", err);
      } finally {
        setLoading(false);
      }
    }
    load();
    // Auto-refresh every 5 seconds
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  const statusItems = status
    ? [
        { label: "Gateway Health", value: status.gateway_health, status: "success" },
        { label: "Policy Loaded", value: status.policy_loaded, status: "success" },
        { label: "Environment", value: status.environment, status: "info" },
        { label: "Recent Requests", value: String(status.recent_requests), status: "info" },
        { label: "Deny Rate", value: `${status.deny_rate}%`, status: status.deny_rate > 5 ? "warning" : "info" },
        { label: "Quota Usage", value: `${status.quota_usage}%`, status: "info" },
        { label: "Audit Logging", value: status.audit_logging, status: "success" },
        { label: "Uptime", value: `${Math.floor(status.uptime)}s`, status: "success" },
      ]
    : [];

  return (
    <div className="space-y-6 max-w-7xl">
      <div>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="text-kiro-muted text-sm mt-1">
          Agent Policy Gateway Policy Enforcement Console
        </p>
      </div>

      {/* System Status */}
      <section className="card">
        <h2 className="text-sm font-medium mb-3 flex items-center gap-2">
          <Activity className="w-4 h-4 text-kiro-accent" />
          System Status
          {loading && <span className="text-xs text-kiro-muted">(loading...)</span>}
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {statusItems.map((item) => (
            <div key={item.label} className="rounded-md bg-kiro-bg p-3">
              <p className="text-xs text-kiro-muted">{item.label}</p>
              <p className="text-sm font-medium mt-0.5">{item.value}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Quick Actions */}
      <section className="card">
        <h2 className="text-sm font-medium mb-3">Quick Actions</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {quickActions.map((action) => {
            const Icon = action.icon;
            return (
              <Link
                key={action.href}
                href={action.href}
                className="flex flex-col items-center gap-2 rounded-md border border-kiro-border p-4 hover:border-kiro-accent/50 hover:bg-kiro-accent/5 transition-colors text-center"
              >
                <Icon className="w-5 h-5 text-kiro-accent" />
                <span className="text-xs">{action.label}</span>
              </Link>
            );
          })}
        </div>
      </section>

      {/* Enforcement Pipeline — LIVE DATA */}
      <section className="card">
        <h2 className="text-sm font-medium mb-3">
          Enforcement Pipeline
          <span className="ml-2 text-[10px] text-emerald-400 font-normal">● LIVE</span>
        </h2>
        {pipelineStats.length === 0 ? (
          <p className="text-xs text-kiro-muted">
            No requests yet. Run a demo scenario to see live pipeline stats.
          </p>
        ) : (
          <div className="flex gap-1 overflow-x-auto pb-2">
            {pipelineStats.map((stage) => (
              <div
                key={stage.name}
                className="flex-shrink-0 rounded-md border border-kiro-border bg-kiro-bg p-2 text-center min-w-[90px]"
              >
                <p className="text-[10px] text-kiro-muted whitespace-nowrap">
                  {stage.name}
                </p>
                <p className="text-xs text-emerald-400 font-mono mt-1">
                  {stage.pass_count}
                </p>
                {stage.fail_count > 0 && (
                  <p className="text-[10px] text-red-400 font-mono">
                    -{stage.fail_count}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Core Principles */}
      <section className="card">
        <h2 className="text-sm font-medium mb-3">Core Principles</h2>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {principles.map((p) => {
            const Icon = p.icon;
            return (
              <div
                key={p.title}
                className="flex items-center gap-2 rounded-md bg-kiro-bg p-3"
              >
                <Icon className="w-4 h-4 text-kiro-accent flex-shrink-0" />
                <span className="text-xs">{p.title}</span>
              </div>
            );
          })}
        </div>
      </section>

      {/* Latest Audit Events (from real API) */}
      <section className="card">
        <div className="flex justify-between items-center mb-3">
          <h2 className="text-sm font-medium">Latest Audit Events</h2>
          <Link
            href="/dashboard/audit"
            className="text-xs text-kiro-accent hover:underline"
          >
            Full Log →
          </Link>
        </div>
        {auditEvents.length === 0 && !loading ? (
          <p className="text-xs text-kiro-muted">
            No audit events yet. Run a demo scenario to generate events.
          </p>
        ) : (
          <div className="space-y-2 font-mono text-xs">
            {auditEvents.map((event) => (
              <div
                key={event.correlation_id}
                className="flex gap-3 items-center rounded-md bg-kiro-bg px-3 py-2"
              >
                <span className="text-kiro-muted">
                  {new Date(event.timestamp).toLocaleTimeString()}
                </span>
                <span className="text-kiro-accent">{event.correlation_id}</span>
                <span
                  className={
                    event.outcome === "ALLOW"
                      ? "text-emerald-400"
                      : "text-red-400"
                  }
                >
                  {event.outcome}
                </span>
                <span className="text-kiro-muted truncate flex-1">
                  {event.action}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
