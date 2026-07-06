import { CheckCircle2, FileJson } from "lucide-react";

const policyJson = `{
  "version": "1.0",
  "allowed_tools": ["sql_read", "http_get"],
  "permitted_sql_verbs": ["SELECT"],
  "deny_keywords": ["DROP", "DELETE", "TRUNCATE", "ALTER"],
  "approved_services": ["s3", "dynamodb", "rds"],
  "allowed_destinations": [
    "*.amazonaws.com",
    "api.internal.acme.dev"
  ],
  "egress_deny": [
    "169.254.169.254",
    "metadata.google.internal"
  ],
  "role_mappings": {
    "sql_read": "arn:aws:iam::123456789:role/apg-sql-ro",
    "http_get": "arn:aws:iam::123456789:role/apg-http-ro"
  },
  "quotas": {
    "requests_per_minute": 60,
    "max_concurrent": 10
  },
  "response_redaction": ["password", "secret", "token", "ssn"]
}`;

const interpretation = [
  {
    category: "Query Access",
    detail: "SELECT only — no DDL, no DML mutations",
  },
  {
    category: "Outbound Destinations",
    detail: "*.amazonaws.com, api.internal.acme.dev",
  },
  {
    category: "Destructive Actions",
    detail: "DROP, DELETE, TRUNCATE, ALTER → always denied",
  },
  {
    category: "Credential Minting",
    detail: "IAM roles mapped per tool, scoped to read-only",
  },
  {
    category: "Quotas & Limits",
    detail: "60 req/min, max 10 concurrent",
  },
];

const ruleClassifications = [
  { label: "allowed", type: "success" },
  { label: "denied", type: "danger" },
  { label: "quota", type: "warning" },
  { label: "info", type: "info" },
];

export default function PolicyPage() {
  return (
    <div className="space-y-6 max-w-7xl">
      <div>
        <h1 className="text-2xl font-semibold">Policy Management</h1>
        <p className="text-kiro-muted text-sm mt-1">
          Immutable policy loaded at startup — deterministic enforcement
        </p>
      </div>

      {/* Policy metadata bar */}
      <div className="card flex flex-wrap gap-4 items-center">
        <div className="flex items-center gap-2">
          <FileJson className="w-4 h-4 text-kiro-accent" />
          <span className="text-xs font-mono">sha256:a3f8c…</span>
        </div>
        <div className="text-xs text-kiro-muted">
          Loaded: 2024-01-15T08:00:00Z
        </div>
        <div className="badge badge-success">startup: OK</div>
        <div className="flex items-center gap-1">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-xs text-emerald-400">218 passed, 0 failed</span>
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Policy JSON viewer */}
        <div className="card">
          <h2 className="text-sm font-medium mb-3">policy.json</h2>
          <pre className="rounded-md bg-kiro-bg p-4 text-xs font-mono overflow-x-auto leading-relaxed text-kiro-text/80">
            {policyJson}
          </pre>
        </div>

        {/* Right panel */}
        <div className="space-y-6">
          {/* Effective Policy Interpretation */}
          <div className="card">
            <h2 className="text-sm font-medium mb-3">
              Effective Policy Interpretation
            </h2>
            <div className="space-y-3">
              {interpretation.map((item) => (
                <div key={item.category}>
                  <p className="text-xs font-medium">{item.category}</p>
                  <p className="text-xs text-kiro-muted">{item.detail}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Rule Classification */}
          <div className="card">
            <h2 className="text-sm font-medium mb-3">Rule Classification</h2>
            <div className="flex flex-wrap gap-2">
              {ruleClassifications.map((r) => (
                <span key={r.label} className={`badge badge-${r.type}`}>
                  {r.label}
                </span>
              ))}
            </div>
          </div>

          {/* Deterministic vs Probabilistic */}
          <div className="card">
            <h2 className="text-sm font-medium mb-3">
              Deterministic vs Probabilistic
            </h2>
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-md bg-kiro-bg p-3">
                <p className="text-[10px] text-kiro-muted uppercase tracking-wider mb-1">
                  AI Guardrails
                </p>
                <p className="text-xs text-red-400">
                  Probabilistic — can be bypassed with prompt injection
                </p>
              </div>
              <div className="rounded-md bg-kiro-bg p-3">
                <p className="text-[10px] text-kiro-muted uppercase tracking-wider mb-1">
                  Agent Policy Gateway
                </p>
                <p className="text-xs text-emerald-400">
                  Code-based — allowlist checked before execution
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
