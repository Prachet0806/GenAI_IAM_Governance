"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SessionProvider } from "next-auth/react";
import { useState } from "react";

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(() => new QueryClient({
    defaultOptions: {
      queries: { staleTime: 20_000, retry: 1, refetchOnWindowFocus: true },
      mutations: { retry: 0 },
    },
  }));
  return <SessionProvider><QueryClientProvider client={client}>{children}</QueryClientProvider></SessionProvider>;
}
