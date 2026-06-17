"use client";

import { useState } from "react";
import { CheckCircle2, XCircle, AlertTriangle } from "lucide-react";

const requests = [
  { id: "req_7f3a9c2e", outcome: "PASS" as const },
  { id: "req_a1b4d8f0", outcome: "DENY" as const },
  { id: "req_c9e2f1a7", outcome: "DENY" as const },
  { id: "req_d4f7e3b2", outcome: "PASS" as const },
  { id: "req_e8a1c5d9", outcome: "DENY" as const },
];

const stages = [
  "Agent Auth",
  "Bearer Token",
  "Schema Valid",
  "Policy Eval",
  "Egress Ctrl",
  "Quota Check",
  "STS Mint",
  "Execute",
  "Resp Filter",
  "Cred Dispose",
  "Audit Log",
  "Return",
];

const denialCodes = [
  { code: "-32600", description: "Invalid Request — schema validation failed" },
  { code: "-32602", description: "Policy Denied — action not in allowlist" },
  { code: "-32603", description: "Egress Blocked — destination not approved" },
];

export default function RequestFlowPage() {
  const [selectedReq, setSelectedReq] = useState(requests[0]);

  // For the selected request, simulate which stages pass
  const failStage =
    selectedReq.outcome === "DENY"
      ? selectedReq.id === "req_a1b4d8f0"
        ? 3 // Policy Eval
        : selectedReq.id === "req_c9e2f1a7"
        ? 4 // Egress Ctrl
        : 5 // Quota Check
      : -1;

  return (
    <div className="space-y-6 max-w-7xl">
      <div>
        <h1 className="text-2xl font-semibold">Request Flow Visualizer</h1>
        <p className="text-kiro-muted text-sm mt-1">
          Trace requests through the 12-stage enforcement pipeline
        </p>
      </div>

      {/* Fail-closed banner */}
      <div className="rounded-md bg-red-500/10 border border-red-500/20 px-4 py-2 flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-red-400" />
        <span className="text-sm text-red-400 font-medium">
          FAIL-CLOSED — Any stage failure stops the entire request
        </span>
      </div>

      <div className="flex gap-6">
        {/* Request list */}
        <div className="w-56 shrink-0">
          <h3 className="text-xs font-medium text-kiro-muted mb-2 uppercase tracking-wider">
            Recent Requests
          </h3>
          <div className="space-y-1">
            {requests.map((req) => (
              <button
                key={req.id}
                onClick={() => setSelectedReq(req)}
                className={`w-full flex items-center justify-between rounded-md px-3 py-2 text-sm transition-colors ${
                  selectedReq.id === req.id
                    ? "bg-kiro-accent/10 text-kiro-accent"
                    : "hover:bg-kiro-bg text-kiro-muted"
                }`}
              >
                <span className="font-mono text-xs">{req.id}</span>
                <span
                  className={`badge ${
                    req.outcome === "PASS" ? "badge-success" : "badge-danger"
                  }`}
                >
                  {req.outcome}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Pipeline visualization */}
        <div className="flex-1 space-y-6">
          <div className="card">
            <h3 className="text-sm font-medium mb-4">
              Pipeline — {selectedReq.id}
            </h3>
            <div className="flex flex-wrap gap-2">
              {stages.map((stage, i) => {
                const passed =
                  failStage === -1 || i < failStage;
                const failed = i === failStage;
                return (
                  <div
                    key={stage}
                    className={`flex items-center gap-1.5 rounded-md border px-3 py-2 text-xs ${
                      failed
                        ? "border-red-500/40 bg-red-500/10 text-red-400"
                        : passed
                        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                        : "border-kiro-border bg-kiro-bg text-kiro-muted"
                    }`}
                  >
                    {failed ? (
                      <XCircle className="w-3.5 h-3.5" />
                    ) : passed ? (
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    ) : null}
                    {stage}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Denial Codes Reference */}
          <div className="card">
            <h3 className="text-sm font-medium mb-3">
              Denial Codes Reference
            </h3>
            <div className="space-y-2">
              {denialCodes.map((dc) => (
                <div
                  key={dc.code}
                  className="flex gap-3 items-center text-xs"
                >
                  <code className="text-red-400 font-mono">{dc.code}</code>
                  <span className="text-kiro-muted">{dc.description}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Evidence panel */}
          <div className="card">
            <h3 className="text-sm font-medium mb-3">Evidence Panel</h3>
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-md bg-kiro-bg p-3">
                <p className="text-[10px] text-kiro-muted uppercase tracking-wider mb-1">
                  Matched Policy Rule
                </p>
                <p className="text-xs font-mono">
                  {selectedReq.outcome === "PASS"
                    ? "allowed_tools[0]: sql_read"
                    : "deny (default)"}
                </p>
              </div>
              <div className="rounded-md bg-kiro-bg p-3">
                <p className="text-[10px] text-kiro-muted uppercase tracking-wider mb-1">
                  JIT Credential
                </p>
                <p className="text-xs font-mono">
                  {selectedReq.outcome === "PASS"
                    ? "TTL: 15min / Actual: 3ms"
                    : "Not minted (denied)"}
                </p>
              </div>
              <div className="rounded-md bg-kiro-bg p-3">
                <p className="text-[10px] text-kiro-muted uppercase tracking-wider mb-1">
                  Decision
                </p>
                <p
                  className={`text-xs font-medium ${
                    selectedReq.outcome === "PASS"
                      ? "text-emerald-400"
                      : "text-red-400"
                  }`}
                >
                  {selectedReq.outcome === "PASS" ? "ALLOWED" : "DENIED"}
                </p>
              </div>
              <div className="rounded-md bg-kiro-bg p-3">
                <p className="text-[10px] text-kiro-muted uppercase tracking-wider mb-1">
                  Latency
                </p>
                <p className="text-xs font-mono">12ms total</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
