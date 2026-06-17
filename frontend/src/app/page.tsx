"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, KeyRound, FileText, Lock } from "lucide-react";
import { login } from "@/lib/api";
import { setAuth } from "@/lib/auth";

export default function LoginPage() {
  const router = useRouter();
  const [workspace, setWorkspace] = useState("kirogate");
  const [email, setEmail] = useState("admin@kirogate.dev");
  const [password, setPassword] = useState("kirogate-demo");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleLogin(e: React.FormEvent | React.MouseEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await login({ workspace, email, password });
      setAuth(res.token, res.user);
      router.push("/dashboard");
    } catch (err: any) {
      setError(err?.message || "Invalid credentials. Please try again.");
      console.error("Login error:", err);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen">
      {/* Left branding panel */}
      <div className="hidden lg:flex lg:w-1/2 flex-col justify-center px-16 bg-gradient-to-br from-kiro-surface to-kiro-bg border-r border-kiro-border">
        <div className="max-w-md">
          <h1 className="text-3xl font-bold mb-2">KiroGate</h1>
          <p className="text-kiro-muted mb-10">
            Deterministic AI Policy Enforcement
          </p>

          <div className="space-y-6">
            <Feature
              icon={<Shield className="w-5 h-5 text-kiro-accent" />}
              title="Default-Deny"
              description="Every request is denied unless explicitly allowed by policy"
            />
            <Feature
              icon={<KeyRound className="w-5 h-5 text-emerald-400" />}
              title="Zero Credentials"
              description="AI agents never hold long-lived secrets"
            />
            <Feature
              icon={<FileText className="w-5 h-5 text-amber-400" />}
              title="Full Auditability"
              description="Append-only structured logs with correlation IDs"
            />
            <Feature
              icon={<Lock className="w-5 h-5 text-purple-400" />}
              title="Trust Guarantees"
              description="Code-based enforcement, not probabilistic AI guardrails"
            />
          </div>
        </div>
      </div>

      {/* Right login form */}
      <div className="flex-1 flex items-center justify-center px-8">
        <div className="w-full max-w-sm">
          <h2 className="text-2xl font-semibold mb-1">Operator Access</h2>
          <p className="text-kiro-muted text-sm mb-8">
            Sign in to the KiroGate console
          </p>

          {error && (
            <div className="mb-4 rounded-md bg-red-500/10 border border-red-500/20 px-3 py-2 text-sm text-red-400">
              {error}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1.5">
                Workspace
              </label>
              <input
                type="text"
                value={workspace}
                onChange={(e) => setWorkspace(e.target.value)}
                placeholder="acme-corp"
                className="w-full rounded-md border border-kiro-border bg-kiro-bg px-3 py-2 text-sm placeholder:text-kiro-muted focus:outline-none focus:ring-2 focus:ring-kiro-accent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1.5">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="operator@acme.dev"
                className="w-full rounded-md border border-kiro-border bg-kiro-bg px-3 py-2 text-sm placeholder:text-kiro-muted focus:outline-none focus:ring-2 focus:ring-kiro-accent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1.5">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full rounded-md border border-kiro-border bg-kiro-bg px-3 py-2 text-sm placeholder:text-kiro-muted focus:outline-none focus:ring-2 focus:ring-kiro-accent"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-md bg-kiro-accent px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-600 transition-colors mt-6 disabled:opacity-50"
            >
              {loading ? "Authenticating..." : "Secure Access"}
            </button>

            <button
              type="button"
              onClick={handleLogin}
              className="w-full rounded-md border border-kiro-border px-4 py-2.5 text-sm font-medium hover:bg-kiro-surface transition-colors"
            >
              Continue with SSO
            </button>
          </form>

          <div className="mt-8 flex gap-2">
            <span className="badge badge-info">env:production</span>
            <span className="badge badge-info">region:us-east-1</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function Feature({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <div className="flex gap-3">
      <div className="mt-0.5">{icon}</div>
      <div>
        <p className="font-medium text-sm">{title}</p>
        <p className="text-kiro-muted text-sm">{description}</p>
      </div>
    </div>
  );
}
