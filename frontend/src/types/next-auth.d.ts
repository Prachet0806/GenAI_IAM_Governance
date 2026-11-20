import "next-auth";

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      name?: string | null;
      email?: string | null;
    };
    error?: "AccessTokenRefreshFailed";
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    backendAccessToken?: string;
    backendRefreshToken?: string;
    backendAccessTokenExpiresAt?: number;
    authError?: "AccessTokenRefreshFailed";
  }
}
