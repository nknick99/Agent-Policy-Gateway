"use client";

import { useState } from "react";
import { CheckCircle2, XCircle } from "lucide-react";

interface Scenario {
  id: number;
  name: string;
  outcome: "ALLOWED" | "DENIED";
  request: string;
  failStage?: string;
  reason?: string;
}

const scenarios: Scenario[] = [
  {
    id: 1,
    name: "Valid SELECT Query",
    outcome: "ALLOWED",
    request: `{"jsonrpc":"2.0","method":"sql_read","params":{"query":"SELECT * FROM users WHERE active=true"},"id":1}`,
  },
  {
    id: 2,
    name: "DELETE Operation",
    outcome: "DENIED",
    request: `{"jsonrpc":"2.0","method":"sql_read","params":{"query":"DELETE FROM users WHERE id=42"},"id":2}`,
    failStage: "Policy Eval",
    reason: "Verb DELETE not in permitted_sql_verbs",
  },
  {
    id: 3,
    name: "SSRF Attempt",
    outcome: "DENIED",
    request: `{"jsonrpc":"2.0","method":"http_get","params":{"url":"http://169.254.169.254/latest/meta-data/"},"id":3}`,
    failStage: "Egress Ctrl",
    reason: "Destination in egress_deny list",
  },
  {
    id: 4,
    name: "Prompt Injection",
    outcome: "DENIED",
    request: `{"jsonrpc":"2.0","method":"sql_read","params":{"query":"SELECT 1; DROP TABLE users;--"},"id":4}`,
    failStage: "Policy Eval",
    reason: "Keyword DROP in deny_keywords",
  },
  {
    id: 5,
    name: "Quota Exceeded",
    outcome: "DENIED",
    request: `{"jsonrpc":"2.0","method":"sql_read","params":{"query":"SELECT count(*) FROM orders"},"id":5}`,
    failStage: "Quota Check",
    reason: "Rate limit exceeded: 61/60 req/min",
  },
];

const pipelineStages = [
  "Auth",
  "Schema",
  "Policy",
  "Egress",
  "Quota",
  "JIT Mint",
  "Execute",
];

export default function DemosPage() {
  const [selected, setSelected] = useState<Scenario>(scenarios[0]);

  const allowed = scenarios.filter((s) => s.outcome === "ALLOWED").length;
  const denied = scenarios.filter((s) => s.outcome === "DENIED").length;

  return (
    <div className="space-y-6 max-w-7xl">
      <div>
        <h1 className="text-2xl font-semibold">Demo Scenarios</h1>
        <p className="text-kiro-muted text-sm mt-1">
          Deterministic test cases demonstrating policy enforcement
        </p>
      </div>

      {/* Summary cards */}
      <div className="flex gap-3">
        <div className="card flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span className="text-sm font-medium">{allowed} Allowed</span>
        </div>
        <div className="card flex items-center gap-2">
          <XCircle className="w-4 h-4 text-red-400" />
          <span className="text-sm font-medium">{denied} Denied</span>
        </div>
      </div>

      {/* Scenario list */}
      <div className="grid lg:grid-cols-3 gap-6">
        <div className="space-y-2">
          {scenarios.map((s) => (
            <button
              key={s.id}
              onClick={() => setSelected(s)}
              className={`w-full text-left rounded-md border p-3 transition-colors ${
                selected.id === s.id
                  ? "border-kiro-accent bg-kiro-accent/5"
                  : "border-kiro-border hover:border-kiro-accent/30"
              }`}
            >
              <div className="flex justify-between items-center">
                <span className="text-sm">{s.name}</span>
                <span
                  className={`badge ${
                    s.outcome === "ALLOWED" ? "badge-success" : "badge-danger"
                  }`}
                >
                  {s.outcome}
                </span>
              </div>
            </button>
          ))}
        </div>

        {/* Detail panel */}
        <div className="lg:col-span-2 space-y-4">
          <div className="card">
            <h3 className="text-sm font-medium mb-2">
              Scenario {selected.id}: {selected.name}
            </h3>

            {/* Request body */}
            <div className="mb-4">
              <p className="text-[10px] text-kiro-muted uppercase tracking-wider mb-1">
                JSON-RPC Request
              </p>
              <pre className="rounded-md bg-kiro-bg p-3 text-xs font-mono overflow-x-auto">
                {selected.request}
              </pre>
            </div>

            {/* Pipeline visualization */}
            <div className="mb-4">
              <p className="text-[10px] text-kiro-muted uppercase tracking-wider mb-2">
                Validation Pipeline
              </p>
              <div className="flex flex-wrap gap-2">
                {pipelineStages.map((stage) => {
                  const stageMap: Record<string, string> = {
                    Auth: "Auth",
                    Schema: "Schema Valid",
                    Policy: "Policy Eval",
                    Egress: "Egress Ctrl",
                    Quota: "Quota Check",
                    "JIT Mint": "STS Mint",
                    Execute: "Execute",
                  };
                  const failMatch =
                    selected.failStage &&
                    stageMap[stage] === selected.failStage;
                  const passedFail =
                    selected.failStage &&
                    pipelineStages.indexOf(stage) >
                      pipelineStages.findIndex(
                        (s) => stageMap[s] === selected.failStage
                      );

                  return (
                    <div
                      key={stage}
                      className={`flex items-center gap-1 rounded-md border px-2.5 py-1.5 text-xs ${
                        failMatch
                          ? "border-red-500/40 bg-red-500/10 text-red-400"
                          : passedFail
                          ? "border-kiro-border bg-kiro-bg text-kiro-muted"
                          : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                      }`}
                    >
                      {failMatch ? (
                        <XCircle className="w-3 h-3" />
                      ) : passedFail ? null : (
                        <CheckCircle2 className="w-3 h-3" />
                      )}
                      {stage}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Reason / Result */}
            {selected.outcome === "DENIED" ? (
              <div className="rounded-md bg-red-500/5 border border-red-500/20 p-3">
                <p className="text-xs text-red-400 font-medium">
                  Denied at: {selected.failStage}
                </p>
                <p className="text-xs text-kiro-muted mt-1">
                  {selected.reason}
                </p>
              </div>
            ) : (
              <div className="rounded-md bg-emerald-500/5 border border-emerald-500/20 p-3">
                <p className="text-xs text-emerald-400 font-medium">
                  Request allowed — result filtered and returned
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
