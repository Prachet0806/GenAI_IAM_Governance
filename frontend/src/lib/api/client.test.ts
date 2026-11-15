import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiFetch } from "./client";

const { getSession } = vi.hoisted(() => ({ getSession: vi.fn() }));
vi.mock("next-auth/react", () => ({ getSession }));

describe("apiFetch error responses", () => {
  beforeEach(() => {
    getSession.mockReset();
    getSession.mockResolvedValue({ user: { name: "Reviewer" } });
    vi.restoreAllMocks();
  });

  it.each([401, 403, 409, 500])("preserves a %i API error and request ID", async (status) => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      error: { code: `HTTP_${status}`, message: `Request failed (${status})`, request_id: "trace-123" },
    }), { status, headers: { "content-type": "application/json" } }));

    await expect(apiFetch("campaigns")).rejects.toMatchObject({
      name: "ApiError", status, code: `HTTP_${status}`,
      message: `Request failed (${status})`, requestId: "trace-123",
    } satisfies Partial<ApiError>);
    expect(fetch).toHaveBeenCalledWith("/api/backend/campaigns", expect.objectContaining({
      credentials: "same-origin", cache: "no-store",
    }));
  });

  it("rejects an expired session before contacting the API", async () => {
    getSession.mockResolvedValue({ error: "RefreshAccessTokenError" });
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await expect(apiFetch("campaigns")).rejects.toMatchObject({
      status: 401, code: "AUTHENTICATION_REQUIRED",
    });
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
