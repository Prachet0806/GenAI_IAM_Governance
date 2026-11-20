"use client";

import Link from "next/link";
import { signOut } from "next-auth/react";

export default function AccessDeniedPage() {
  return <main className="login-page"><section className="login-card"><div className="brand"><span className="brand-mark">IG</span><span>IAM Governance</span></div><div className="eyebrow">Workspace unavailable</div><h1>No governance role is assigned</h1><p>Your organization account is authenticated, but it does not include a role for these workspaces. Contact your IAM administrator if you need access.</p><button className="button primary" onClick={() => void signOut({ callbackUrl: "/login" })}>Sign out</button><p><Link href="/login" className="row-link">Return to sign in</Link></p></section></main>;
}
