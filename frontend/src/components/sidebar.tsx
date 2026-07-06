"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Home,
  GitBranch,
  FileJson,
  Play,
  ScrollText,
  LogOut,
  Shield,
  Bot,
} from "lucide-react";
import { clsx } from "clsx";

const navItems = [
  { href: "/dashboard", label: "Home", icon: Home },
  { href: "/dashboard/live-demo", label: "Live Agent Demo", icon: Bot },
  { href: "/dashboard/request-flow", label: "Request Flow", icon: GitBranch },
  { href: "/dashboard/policy", label: "Policy Management", icon: FileJson },
  { href: "/dashboard/demos", label: "Demo Scenarios", icon: Play },
  { href: "/dashboard/audit", label: "Audit & Credentials", icon: ScrollText },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-60 border-r border-kiro-border bg-kiro-surface flex flex-col">
      <div className="p-4 border-b border-kiro-border">
        <Link href="/dashboard" className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-kiro-accent" />
          <span className="font-semibold">Agent Policy Gateway</span>
        </Link>
      </div>

      <nav className="flex-1 p-3 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={clsx(
                "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
                active
                  ? "bg-kiro-accent/10 text-kiro-accent"
                  : "text-kiro-muted hover:text-kiro-text hover:bg-kiro-bg"
              )}
            >
              <Icon className="w-4 h-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="p-3 border-t border-kiro-border">
        <Link
          href="/"
          className="flex items-center gap-2.5 rounded-md px-3 py-2 text-sm text-kiro-muted hover:text-red-400 transition-colors"
        >
          <LogOut className="w-4 h-4" />
          Sign Out
        </Link>
      </div>
    </aside>
  );
}
