import { getToken } from "next-auth/jwt";
import { NextRequest, NextResponse } from "next/server";

type RouteContext = { params: Promise<{ path: string[] }> };

function allowed(path: string[], method: string): boolean {
  const joined = path.join("/");
  if (method === "GET") {
    return [
      "me",
      "reviews/summary",
      "reviews/queue",
      "campaigns",
      "snapshots",
      "approvals",
      "audit/events",
      "exports",
      "operations/health",
      "operations/integrations",
      "operations/jobs",
      "operations/audit",
      /^reviews\/[^/]+$/,
      /^reviews\/[^/]+\/history$/,
      /^campaigns\/[^/]+$/,
      /^campaigns\/[^/]+\/(events|progress|reviews|reviewers)$/,
      /^snapshots\/[^/]+\/readiness$/,
      /^approvals\/[^/]+$/,
      /^exports\/[^/]+(\/verify|\/download)?$/,
      /^ai\/jobs\/[^/]+$/,
    ].some((route) => typeof route === "string" ? joined === route : route.test(joined));
  }
  if (method === "POST") {
    return [
      /^reviews\/[^/]+\/(decision|ai\/explanation|assignment|exception(\/resolve)?|remediation\/reconciliation)$/,
      /^campaigns(\/[^/]+\/(reviewers|state|owner|deadline))?$/,
      /^approvals\/[^/]+\/decision$/,
      /^exports$/,
    ].some((route) => route.test(joined));
  }
  if (method === "DELETE") return /^campaigns\/[^/]+\/reviewers$/.test(joined);
  return false;
}

async function proxy(request: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  if (!path.length || path.some((part) => part === ".." || part.includes("\\"))) {
    return NextResponse.json({ error: { code: "INVALID_ROUTE", message: "Unsupported API route" } }, { status: 404 });
  }
  if (!allowed(path, request.method)) {
    return NextResponse.json({ error: { code: "ROUTE_NOT_ALLOWED", message: "This frontend route is not available" } }, { status: 404 });
  }
  if (request.method !== "GET") {
    const expectedOrigin = new URL(process.env.FRONTEND_ORIGIN ?? request.nextUrl.origin).origin;
    if (request.headers.get("origin") !== expectedOrigin) {
      return NextResponse.json({ error: { code: "CSRF_ORIGIN_REJECTED", message: "Request origin was not accepted" } }, { status: 403 });
    }
  }

  const session = await getToken({
    req: request,
    secret: process.env.AUTH_SECRET,
  });
  const accessToken = session?.backendAccessToken;
  const expiresAt = session?.backendAccessTokenExpiresAt ?? 0;
  if (typeof accessToken !== "string" || expiresAt <= Date.now()) {
    return NextResponse.json({ error: { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue" } }, { status: 401 });
  }

  const base = process.env.IAM_API_BASE_URL;
  if (!base) {
    return NextResponse.json({ error: { code: "API_NOT_CONFIGURED", message: "The governance API is not configured" } }, { status: 503 });
  }
  const upstream = new URL(path.map(encodeURIComponent).join("/"), `${base.replace(/\/$/, "")}/`);
  upstream.search = request.nextUrl.search;
  const headers = new Headers({
    authorization: `Bearer ${accessToken}`,
    accept: "application/json",
    "x-request-id": crypto.randomUUID(),
  });
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);

  try {
    const response = await fetch(upstream, {
      method: request.method,
      headers,
      body: request.method === "GET" ? undefined : await request.arrayBuffer(),
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(15_000),
    });
    const responseHeaders = new Headers({
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    });
    const responseType = response.headers.get("content-type");
    const requestId = response.headers.get("x-request-id");
    if (responseType) responseHeaders.set("content-type", responseType);
    const disposition = response.headers.get("content-disposition");
    if (disposition) responseHeaders.set("content-disposition", disposition);
    if (requestId) responseHeaders.set("x-request-id", requestId);
    return new Response(await response.arrayBuffer(), {
      status: response.status,
      headers: responseHeaders,
    });
  } catch {
    return NextResponse.json({ error: { code: "API_UNAVAILABLE", message: "The review service could not be reached" } }, { status: 502 });
  }
}

export const GET = proxy;
export const POST = proxy;
export const DELETE = proxy;
