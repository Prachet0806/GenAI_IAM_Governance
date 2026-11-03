"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useSession } from "next-auth/react";
import { apiFetch, ApiError } from "@/lib/api/client";
import { defaultWorkspacePath } from "@/lib/navigation";
import type { AppIdentity } from "@/lib/api/types";

export default function Home() {
  const router = useRouter();
  const session = useSession();
  const identity = useQuery({
    queryKey: ["me"],
    queryFn: () => apiFetch<AppIdentity>("me"),
    enabled: session.status === "authenticated" && !session.data?.error,
  });

  useEffect(() => {
    if (session.status === "unauthenticated" || session.data?.error) {
      router.replace("/login");
      return;
    }
    if (identity.data) {
      router.replace(defaultWorkspacePath(identity.data.roles));
      return;
    }
    if (identity.error instanceof ApiError && identity.error.status === 401) {
      router.replace("/login");
    }
  }, [identity.data, identity.error, router, session.data?.error, session.status]);

  if (identity.isError && !(identity.error instanceof ApiError && identity.error.status === 401)) {
    return <main className="login-page"><section className="login-card"><div className="eyebrow">Workspace unavailable</div><h1>Could not load your access</h1><p>{identity.error instanceof Error ? identity.error.message : "Try again or contact your administrator."}</p><button className="button primary" onClick={() => void identity.refetch()}>Try again</button></section></main>;
  }
  return <main className="login-page"><div className="loading" role="status">{session.status === "loading" ? "Checking your session…" : "Finding your workspace…"}</div></main>;
}
