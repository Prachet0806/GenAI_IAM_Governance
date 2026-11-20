"use client";

import { signIn, useSession } from "next-auth/react";
import Link from "next/link";

export function LoginCard({ error }: { error: boolean }) {
  const { status } = useSession();
  return (
    <main className="login-page">
      <section className="login-card">
        <div className="brand"><span className="brand-mark">IG</span><span>IAM Governance</span></div>
        <div className="eyebrow">Access certification</div>
        <h1>Sign in to govern access</h1>
        <p>Use your organization account to open the governance workspace available to your role.</p>
        {error && <div className="notice danger" role="alert">Sign-in could not be completed. Check your organization account or contact your administrator.</div>}
        {status === "authenticated" ? <Link className="button primary" href="/">Continue to workspace</Link> : <button className="button primary" onClick={() => signIn("corporate-oidc", { callbackUrl: "/" })}>Continue with your organization</button>}
        <div className="login-footnote">Your access and available actions are determined by your organization role.</div>
      </section>
    </main>
  );
}
