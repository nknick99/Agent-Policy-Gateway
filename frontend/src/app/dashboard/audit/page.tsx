"use client";

import { useState } from "react";
import { Search, Download, Clock } from "lucide-react";

type Tab = "ALL" | "ALLOW" | "DENY" | "WARNING";

const auditEvents = [
  {
    id: "req_7f3a9c2e",
    timestamp: "2024-01-15T14:32:01.003Z",
    outcome: "ALLOW" as const,
    method: "sql_read",
    action: 'SELECT * FROM users WHERE active=true',
    latency: "12ms",
    stage: "Return",
  },
  {
    id: "req_a1b4d8f0",
    timestamp: "2024-01-15T14:31:58.891Z",
    outcome: "DENY" as const,
    method: "sql_read",
    action: "DELETE FROM users WHERE id=42",
    latency: "3ms",
    stage: "Policy Eval",
  },
  {
    id: "req_c9e2f1a7",
    timestamp: "2024-01-15T14:31:55.442Z",
    outcome: "DENY" as const,
    method: "http_get",
    action: "http://169.254.169.254/latest/meta-data/",
    latency: "2ms",
    stage: "Egress Ctrl",
  },
  {
    id: "req_d4f7e3b2",
    timestamp: "2024-01-15T14:31:52.117Z",
    outcome: "ALLOW" as const,
    method: "sql_read",
    action: "SELECT count(*) FROM orders WHERE status='pending'",
    latency: "14ms",
    stage: "Return",
  },
  {
    id: "req_e8a1c5d9",
    timestamp: "2024-01-15T14:31:49.003Z",
    outcome: "DENY" as const,
    method: "sql_read",
    action: "SELECT 1; DROP TABLE users;--",
    latency: "2ms",
    stage: "Policy Eval",
  },
];

const credentialLifecycle = [
  { time: "T+0ms", event: "Request received — zero credentials held" },
  { time: "T+8ms", event: "All checks passed — STS credentials minted" },
  { time: "T+9ms", event: "Action executed against target service" },
  { time: "T+11ms", event: "Credentials disposed (zeroed from memory)" },
  { time: "T+12ms", event: "Audit logged — request complete" },
];

const compliance = [
  "Every request tagged with unique correlation ID",
  "Append-only audit log — no deletions, no edits",
  "Zero credential exposure to AI agents",
  "SOC2 / ISO 27001 compatible logging format",
];

export default function AuditPage() {
  const [activeTab, setActiveTab] = useState<Tab>("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  const filteredEvents = auditEvents.filter((e) => {
    if (activeTab !== "ALL" && e.outcome !== activeTab) return false;
    if (searchQuery && !e.id.includes(searchQuery)) return false;
    return true;
  });

  return (
    <div className="space-y-6 max-w-7xl">
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-2xl font-semibold">
            Audit &amp; Credential Lifecycle
          </h1>
          <p className="text-kiro-muted text-sm mt-1">
            Full traceability — append-only structured logs
          </p>
        </div>
        <button className="flex items-center gap-1.5 rounded-md border border-kiro-border px-3 py-1.5 text-xs hover:bg-kiro-surface transition-colors">
          <Download className="w-3.5 h-3.5" />
          Export Logs
        </button>
      </div>

      {/* Filters */}
      <div className="card flex flex-wrap gap-3 items-center">
        <div className="flex gap-1">
          {(["ALL", "ALLOW", "DENY", "WARNING"] as Tab[]).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1 rounded-md text-xs transition-colors ${
                activeTab === tab
                  ? "bg-kiro-accent text-white"
                  : "text-kiro-muted hover:text-kiro-text"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-kiro-muted" />
          <input
            type="text"
            placeholder="Search correlation ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 rounded-md border border-kiro-border bg-kiro-bg text-xs placeholder:text-kiro-muted focus:outline-none focus:ring-1 focus:ring-kiro-accent"
          />
        </div>
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Audit events */}
        <div className="lg:col-span-2 space-y-2">
          {filteredEvents.map((event) => (
            <div key={event.id} className="card font-mono text-xs">
              <div className="flex gap-3 items-start flex-wrap">
                <span className="text-kiro-muted">
                  {new Date(event.timestamp).toLocaleTimeString()}
                </span>
                <span className="text-kiro-accent">{event.id}</span>
                <span
                  className={
                    event.outcome === "ALLOW"
                      ? "text-emerald-400"
                      : "text-red-400"
                  }
                >
                  {event.outcome}
                </span>
                <span className="text-kiro-muted">{event.method}</span>
                <span className="text-kiro-text/70 truncate flex-1">
                  {event.action}
                </span>
              </div>
              <div className="flex gap-4 mt-2 text-kiro-muted">
                <span>stage: {event.stage}</span>
                <span>latency: {event.latency}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Right panel */}
        <div className="space-y-4">
          {/* Credential lifecycle */}
          <div className="card">
            <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
              <Clock className="w-4 h-4 text-kiro-accent" />
              Credential Lifecycle
            </h3>
            <div className="space-y-2">
              {credentialLifecycle.map((step) => (
                <div key={step.time} className="flex gap-2 text-xs">
                  <span className="text-kiro-accent font-mono w-14 shrink-0">
                    {step.time}
                  </span>
                  <span className="text-kiro-muted">{step.event}</span>
                </div>
              ))}
            </div>
            <div className="mt-3 rounded-md bg-kiro-bg p-2">
              <div className="flex justify-between text-[10px] text-kiro-muted">
                <span>Max TTL: 15min</span>
                <span>Actual: 3ms</span>
              </div>
              <div className="mt-1 h-1.5 rounded-full bg-kiro-border overflow-hidden">
                <div className="h-full w-[0.03%] bg-emerald-400 rounded-full min-w-[4px]" />
              </div>
            </div>
          </div>

          {/* Compliance */}
          <div className="card">
            <h3 className="text-sm font-medium mb-3">Compliance</h3>
            <div className="space-y-2">
              {compliance.map((item) => (
                <div key={item} className="flex gap-2 text-xs">
                  <span className="text-emerald-400">✓</span>
                  <span className="text-kiro-muted">{item}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
