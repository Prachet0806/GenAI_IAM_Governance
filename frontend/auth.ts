import NextAuth from "next-auth";
import type { JWT } from "next-auth/jwt";

async function refreshAccessToken(token: JWT): Promise<JWT> {
  const issuer = process.env.AUTH_OIDC_ISSUER;
  if (!issuer || !token.backendRefreshToken) {
    return { ...token, authError: "AccessTokenRefreshFailed" };
  }

  try {
    const configurationResponse = await fetch(
      `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
      { cache: "no-store", signal: AbortSignal.timeout(5000) },
    );
    if (!configurationResponse.ok) throw new Error("OIDC configuration unavailable");
    const configuration = (await configurationResponse.json()) as {
      token_endpoint?: string;
    };
    if (!configuration.token_endpoint) throw new Error("OIDC token endpoint unavailable");
    const clientId = process.env.AUTH_CLIENT_ID;
    const clientSecret = process.env.AUTH_CLIENT_SECRET;
    if (!clientId || !clientSecret) throw new Error("OIDC client credentials unavailable");

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: token.backendRefreshToken,
    });
    const response = await fetch(configuration.token_endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
      },
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) throw new Error("OIDC refresh failed");
    const refreshed = (await response.json()) as {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
    };
    if (!refreshed.access_token) throw new Error("OIDC response had no access token");
    return {
      ...token,
      backendAccessToken: refreshed.access_token,
      backendRefreshToken: refreshed.refresh_token ?? token.backendRefreshToken,
      backendAccessTokenExpiresAt: Date.now() + (refreshed.expires_in ?? 3600) * 1000,
      authError: undefined,
    };
  } catch {
    return { ...token, authError: "AccessTokenRefreshFailed" };
  }
}

const issuer = process.env.AUTH_OIDC_ISSUER?.trim();

export const oidcConfigured = Boolean(
  issuer && process.env.AUTH_CLIENT_ID && process.env.AUTH_CLIENT_SECRET && process.env.AUTH_SECRET,
);

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: oidcConfigured
    ? [
        {
          id: "corporate-oidc",
          name: "Your organization",
          type: "oidc",
          issuer,
          clientId: process.env.AUTH_CLIENT_ID,
          clientSecret: process.env.AUTH_CLIENT_SECRET,
          authorization: {
            params: { scope: process.env.AUTH_SCOPE ?? "openid profile email groups" },
          },
          checks: ["pkce", "state"],
        },
      ]
    : [],
  secret: process.env.AUTH_SECRET,
  session: { strategy: "jwt", maxAge: 8 * 60 * 60 },
  pages: { signIn: "/login" },
  callbacks: {
    async jwt({ token, account }) {
      if (account?.access_token) {
        token.backendAccessToken = account.access_token;
        token.backendRefreshToken = account.refresh_token;
        token.backendAccessTokenExpiresAt = account.expires_at
          ? account.expires_at * 1000
          : Date.now() + (account.expires_in ?? 3600) * 1000;
        token.authError = undefined;
      }
      if (!token.backendAccessToken) return token;
      if ((token.backendAccessTokenExpiresAt ?? 0) > Date.now() + 60_000) return token;
      return refreshAccessToken(token);
    },
    async session({ session, token }) {
      if (session.user) session.user.id = token.sub ?? "";
      if (token.authError) session.error = token.authError;
      else delete session.error;
      return session;
    },
  },
});
