import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ReviewWorkspace } from "./review-workspace";
import type { ReviewDetail } from "@/lib/api/types";

const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }));
vi.mock("@/lib/api/client", () => ({ apiFetch }));

const review: ReviewDetail = {
  review_id: "review-1", status: "PENDING", user: "Jordan Lee", entitlement: "BillingReadOnly",
  risk_level: "HIGH", policy_document: { Version: "2012-10-17", Statement: [] },
  risk_reason: "Read access includes billing data", risk_evidence: { actions: ["billing:Get*"] },
  risk_rule_version: "rules-v3", snapshot_id: "snapshot-1", grant_id: "grant-1",
  observation_id: "observation-1", risk_assessment_id: "assessment-1", grant_type: "USER_POLICY",
  grant_source: "Inline policy", policy_version: "v4", policy_sha256: "abc123",
  evidence_state: "snapshot_pinned", policy_evidence_status: "COMPLETE", missing_policy_reason: null,
  source_coverage: { complete: true }, source_account_id: "123456789012", source_scope: "IAM_USER_POLICY",
  snapshot_published_at: "2026-01-01T00:00:00Z", snapshot_current_eligible: true,
  review_scope: "GRANT_PATH", principal_access_status: "not_evaluated",
  ai_explanation: { status: "not_available", summary: null }, assigned_reviewer_sub: "oidc|reviewer",
  due_at: null, exception_state: "NONE", campaign_state: "OPEN",
};

function renderReview() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><ReviewWorkspace reviewId="review-1" /></QueryClientProvider>);
}

describe("ReviewWorkspace", () => {
  afterEach(() => { cleanup(); vi.restoreAllMocks(); });
  beforeEach(() => {
    apiFetch.mockReset();
    apiFetch.mockImplementation((path: string) => {
      if (path === "me") return Promise.resolve({ subject: "oidc|reviewer", roles: ["reviewer"] });
      if (path.startsWith("reviews/review-1/history")) return Promise.resolve({ events: [] });
      if (path === "reviews/review-1") return Promise.resolve(review);
      return Promise.resolve({ status: "REVOKED" });
    });
  });

  it("keeps observed grant evidence distinct from effective access and records a commented revocation", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderReview();
    expect(await screen.findByText("BillingReadOnly")).toBeInTheDocument();
    expect(screen.getByText("Not evaluated")).toBeInTheDocument();
    expect(screen.getByText(/one observed grant path/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke grant path" })).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/Reviewer comment/), { target: { value: "No longer required" } });
    fireEvent.click(screen.getByRole("button", { name: "Revoke grant path" }));

    await waitFor(() => expect(apiFetch).toHaveBeenCalledWith("reviews/review-1/decision", expect.objectContaining({
      method: "POST", body: JSON.stringify({ decision: "REVOKED", comment: "No longer required" }),
    })));
    expect(window.confirm).toHaveBeenCalledOnce();
  });

  it("blocks decisions when the bound snapshot is no longer eligible", async () => {
    apiFetch.mockImplementation((path: string) => {
      if (path === "me") return Promise.resolve({ subject: "oidc|reviewer", roles: ["reviewer"] });
      if (path.startsWith("reviews/review-1/history")) return Promise.resolve({ events: [] });
      return Promise.resolve({ ...review, snapshot_current_eligible: false });
    });
    renderReview();
    expect(await screen.findByRole("alert")).toHaveTextContent("Evidence is no longer current");
    expect(screen.getByRole("button", { name: "Approve grant path" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Revoke grant path" })).toBeDisabled();
  });

  it("lets a campaign-pool reviewer act when the review has no individual assignee", async () => {
    apiFetch.mockImplementation((path: string) => {
      if (path === "me") return Promise.resolve({ subject: "oidc|reviewer", roles: ["reviewer"] });
      if (path.startsWith("reviews/review-1/history")) return Promise.resolve({ events: [] });
      if (path === "reviews/review-1") return Promise.resolve({ ...review, assigned_reviewer_sub: null });
      return Promise.resolve({ status: "APPROVED" });
    });
    renderReview();
    expect(await screen.findByRole("button", { name: "Approve grant path" })).toBeEnabled();
  });
});
