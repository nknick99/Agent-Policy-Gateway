"use client";

import { useState } from "react";
import {
  Bot,
  CheckCircle2,
  XCircle,
  Play,
  Database,
  Globe,
  ShieldAlert,
  ArrowRight,
} from "lucide-react";
import { getToken } from "@/lib/auth";

interface PipelineStage {
  name: string;
  passed: boolean;
  detail: string;
  duration_ms: number;
}

interface ScenarioResult {
  scenario_id: number;
  scenario_name: string;
  description: string;
  agent_intent: string;
  agent_action: string;
  outcome: string;
  denied_at: string | null;
  denial_reason: string | null;
  pipeline: PipelineStage[];
  query_result: Record<string, unknown>[] | null;
  filtered_result: Record<string, unknown>[] | null;
  total_latency_ms: number;
  llm_provider: string;
}

const scenarios = [
  {
    id: 1,
    name: "Read Customer Data",
    icon: Database,
    description: "Agent queries active customers. KiroGate allows SELECT and redacts SSN.",
    category: "Database Query",
    expected: "ALLOWED",
  },
  {
    id: 2,
    name: "Delete Records",
    icon: ShieldAlert,
    description: "Agent tries DELETE. KiroGate blocks — only SELECT permitted.",
    category: "Database Mutation",
    expected: "DENIED",
  },
  {
    id: 3,
    name: "SSRF — Cloud Metadata",
    icon: Globe,
    description: "Agent tries to access AWS metadata endpoint. Egress blocks it.",
    category: "Network / SSRF",
    expected: "DENIED",
  },
  {
    id: 4,
    name: "Data Exfiltration",
    icon: ShieldAlert,
    description: "Agent tries to send PII to attacker endpoint. Egress blocks it.",
    category: "Data Loss Prevention",
    expected: "DENIED",
  },
];

export default function LiveDemoPage() {
  const [running, setRunning] = useState<number | null>(null);
  const [results, setResults] = useState<Map<number, ScenarioResult>>(new Map());

  async function runScenario(id: number) {
    setRunning(id);
    try {
      const token = getToken();
      const resp = await fetch(`/api/live-demo/run/${id}?provider=mock`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      if (!resp.ok) throw new Error("Failed");
      const data: ScenarioResult = await resp.json();
      setResults((prev) => new Map(prev).set(id, data));
    } catch (err) {
      console.error(err);
    } finally {
      setRunning(null);
    }
  }

  async function runAll() {
    for (const s of scenarios) {
      await runScenario(s.id);
    }
  }

  const selectedResult = [...results.values()].find(
    (r) => r.scenario_id === (running || [...results.keys()].pop())
  );

  return (
    <div className="space-y-6 max-w-7xl">
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <Bot className="w-6 h-6 text-kiro-accent" />
            Live Agent Demo
          </h1>
          <p className="text-kiro-muted text-sm mt-1">
            Real AI agent actions enforced through KiroGate policy gateway
          </p>
        </div>
        <button
          onClick={runAll}
          disabled={running !== null}
          className="flex items-center gap-1.5 rounded-md bg-kiro-accent px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 disabled:opacity-50 transition-colors"
        >
          <Play className="w-4 h-4" />
          Run All Scenarios
        </button>
      </div>

      {/* How it works */}
      <div className="card">
        <h2 className="text-sm font-medium mb-2">How This Works</h2>
        <div className="flex items-center gap-2 text-xs text-kiro-muted flex-wrap">
          <span className="badge badge-info">AI Agent</span>
          <ArrowRight className="w-3 h-3" />
          <span>generates intent</span>
          <ArrowRight className="w-3 h-3" />
          <span className="badge badge-warning">KiroGate Policy</span>
          <ArrowRight className="w-3 h-3" />
          <span>evaluates pipeline</span>
          <ArrowRight className="w-3 h-3" />
          <span className="badge badge-success">Allow</span>
          <span>/</span>
          <span className="badge badge-danger">Deny</span>
        </div>
        <p className="text-xs text-kiro-muted mt-2">
          The LLM provider is swappable — Ollama (local), OpenAI, Anthropic, or mock for demos.
          KiroGate doesn&apos;t care what generates the intent; it enforces policy deterministically.
        </p>
      </div>

      {/* Scenario cards */}
      <div className="grid md:grid-cols-2 gap-4">
        {scenarios.map((s) => {
          const Icon = s.icon;
          const result = results.get(s.id);
          const isRunning = running === s.id;

          return (
            <div key={s.id} className="card relative">
              <div className="flex justify-between items-start mb-3">
                <div className="flex items-center gap-2">
                  <Icon className="w-4 h-4 text-kiro-accent" />
                  <h3 className="text-sm font-medium">{s.name}</h3>
                </div>
                <span
                  className={`badge ${
                    s.expected === "ALLOWED" ? "badge-success" : "badge-danger"
                  }`}
                >
                  expects: {s.expected}
                </span>
              </div>
              <p className="text-xs text-kiro-muted mb-3">{s.description}</p>
              <div className="flex justify-between items-center">
                <span className="text-[10px] text-kiro-muted uppercase tracking-wider">
                  {s.category}
                </span>
                <button
                  onClick={() => runScenario(s.id)}
                  disabled={isRunning}
                  className="flex items-center gap-1 rounded-md border border-kiro-border px-2.5 py-1 text-xs hover:border-kiro-accent hover:text-kiro-accent disabled:opacity-50 transition-colors"
                >
                  {isRunning ? (
                    "Running..."
                  ) : (
                    <>
                      <Play className="w-3 h-3" /> Run
                    </>
                  )}
                </button>
              </div>

              {/* Result overlay */}
              {result && (
                <div
                  className={`mt-3 rounded-md border p-3 ${
                    result.outcome === "ALLOWED"
                      ? "border-emerald-500/30 bg-emerald-500/5"
                      : "border-red-500/30 bg-red-500/5"
                  }`}
                >
                  <div className="flex justify-between items-center mb-2">
                    <span
                      className={`text-xs font-medium ${
                        result.outcome === "ALLOWED"
                          ? "text-emerald-400"
                          : "text-red-400"
                      }`}
                    >
                      {result.outcome === "ALLOWED" ? "✓ ALLOWED" : "✗ DENIED"}
                    </span>
                    <span className="text-[10px] text-kiro-muted">
                      {result.total_latency_ms.toFixed(1)}ms
                    </span>
                  </div>
                  <p className="text-[11px] text-kiro-muted font-mono">
                    {result.agent_action}
                  </p>
                  {result.denied_at && (
                    <p className="text-[11px] text-red-400 mt-1">
                      Blocked at: {result.denied_at} — {result.denial_reason}
                    </p>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Detailed result panel */}
      {results.size > 0 && (
        <div className="space-y-4">
          <h2 className="text-sm font-medium">Detailed Results</h2>

          {[...results.values()].map((result) => (
            <div key={result.scenario_id} className="card">
              <div className="flex justify-between items-center mb-3">
                <h3 className="text-sm font-medium">
                  {result.scenario_id}. {result.scenario_name}
                </h3>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-kiro-muted">
                    via {result.llm_provider}
                  </span>
                  <span
                    className={`badge ${
                      result.outcome === "ALLOWED"
                        ? "badge-success"
                        : "badge-danger"
                    }`}
                  >
                    {result.outcome}
                  </span>
                </div>
              </div>

              <p className="text-xs text-kiro-muted mb-3">{result.description}</p>

              {/* Pipeline visualization */}
              <div className="flex flex-wrap gap-1.5 mb-3">
                {result.pipeline.map((stage) => (
                  <div
                    key={stage.name}
                    className={`flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] ${
                      stage.passed
                        ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-400"
                        : stage.detail.includes("Skipped") || stage.detail === "Not executed"
                        ? "border-kiro-border bg-kiro-bg text-kiro-muted"
                        : "border-red-500/30 bg-red-500/5 text-red-400"
                    }`}
                    title={stage.detail}
                  >
                    {stage.passed ? (
                      <CheckCircle2 className="w-3 h-3" />
                    ) : stage.detail.includes("Skipped") || stage.detail === "Not executed" ? null : (
                      <XCircle className="w-3 h-3" />
                    )}
                    {stage.name}
                  </div>
                ))}
              </div>

              {/* Query results (for scenario 1) */}
              {result.filtered_result && result.filtered_result.length > 0 && (
                <div className="grid md:grid-cols-2 gap-3">
                  <div>
                    <p className="text-[10px] text-kiro-muted uppercase tracking-wider mb-1">
                      Raw DB Result
                    </p>
                    <pre className="rounded-md bg-kiro-bg p-2 text-[10px] font-mono overflow-x-auto max-h-40">
                      {JSON.stringify(result.query_result, null, 2)}
                    </pre>
                  </div>
                  <div>
                    <p className="text-[10px] text-kiro-muted uppercase tracking-wider mb-1">
                      Filtered (SSN Redacted)
                    </p>
                    <pre className="rounded-md bg-kiro-bg p-2 text-[10px] font-mono overflow-x-auto max-h-40">
                      {JSON.stringify(result.filtered_result, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
