"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut, useSession } from "next-auth/react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api/client";
import type { AppIdentity } from "@/lib/api/types";
import { defaultWorkspacePath } from "@/lib/navigation";

const workspaceNav = [
  { href: "/reviews", label: "My review queue", icon: "▤", roles: ["reviewer"] },
  { href: "/campaigns", label: "Campaigns", icon: "◫", roles: ["campaign_admin"] },
  { href: "/remediation", label: "Remediation approvals", icon: "✓", roles: ["remediation_approver"] },
  { href: "/audit", label: "Audit and exports", icon: "≡", roles: ["auditor", "campaign_admin"] },
  { href: "/operations", label: "Operations", icon: "⌁", roles: ["remediation_operator"] },
];

export function WorkspaceShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { data: session } = useSession();
  const identityQuery = useQuery({ queryKey: ["me"], queryFn: () => apiFetch<AppIdentity>("me") });
  const identity = identityQuery.data;
  const roles = identity?.roles ?? [];
  const visibleNav = workspaceNav.filter((item) => item.roles.some((role) => roles.includes(role)));
  const requiredRole = pathname.startsWith("/campaigns") ? "campaign_admin"
    : pathname.startsWith("/remediation") ? "remediation_approver"
      : pathname.startsWith("/audit") ? (roles.includes("auditor") || roles.includes("campaign_admin") ? "auditor" : "campaign_admin")
        : pathname.startsWith("/operations") ? "remediation_operator" : "reviewer";
  const campaignEvidenceRead = pathname.startsWith("/reviews/") && roles.includes("campaign_admin");
  const authorized = (requiredRole === "auditor" && roles.includes("campaign_admin")) || roles.includes(requiredRole) || campaignEvidenceRead;
  const name = identity?.display_name || session?.user?.name || session?.user?.email || "Reviewer";
  const initials = name.trim().split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase() || "R";
  return (
    <div className="shell">
      <aside className="sidebar">
        <Link href={defaultWorkspacePath(roles)} className="brand"><span className="brand-mark">IG</span><span>IAM Governance</span></Link>
        <div>
          <div className="nav-label">Workspace</div>
          {visibleNav.map((item) => <Link className={`nav-link ${pathname.startsWith(item.href) ? "active" : ""}`} href={item.href} key={item.href}><span className="nav-icon" aria-hidden="true">{item.icon}</span>{item.label}</Link>)}
        </div>
        <div className="sidebar-footer">
          <div>Evidence-led certification</div>
          <div className="scope-label">{identity?.scope_mode === "claim" ? "Account-scoped access" : "Organization-wide scope"}</div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="crumb">Governance <span aria-hidden="true">/</span> {titleForPath(pathname)}</div>
          <nav className="mobile-nav" aria-label="Workspaces">{visibleNav.map((item) => <Link className={pathname.startsWith(item.href) ? "active" : ""} href={item.href} key={item.href}>{item.label}</Link>)}</nav>
          <div className="user-menu"><span className="avatar" aria-hidden="true">{initials}</span><span className="user-name">{name}</span><button className="button subtle signout" onClick={() => signOut({ callbackUrl: "/login" })}>Sign out</button></div>
        </header>
        <main className="page">
          {identityQuery.isLoading && <div className="loading" role="status">Checking your workspace access…</div>}
          {identityQuery.isError && <div className="error" role="alert">Your workspace permissions could not be verified. <button className="button" onClick={() => void identityQuery.refetch()}>Try again</button></div>}
          {identity && !authorized && <div className="panel"><div className="panel-body"><div className="eyebrow">Workspace unavailable</div><h1>Your role does not include this workspace</h1><p className="subhead">Contact your IAM administrator if you need access to this function.</p></div></div>}
          {identity && authorized && children}
        </main>
      </div>
    </div>
  );
}

function titleForPath(path: string) {
  if (path.startsWith("/campaigns")) return "Campaign administration";
  if (path.startsWith("/remediation")) return "Remediation approval";
  if (path.startsWith("/audit")) return "Audit and exports";
  if (path.startsWith("/operations")) return "Platform operations";
  return "Reviewer";
}
